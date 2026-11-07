//! Role credentials from `GetRoleCredentials`, cached the way the AWS CLI caches them, so `gac`
//! and `aws` reuse each other's entries and `aws sso logout` (or `gac logout`) sweeps them.
//!
//! botocore's `SSOCredentialFetcher` keys an entry by the SHA-1 of a minified, key-sorted JSON
//! object naming the account and role and the session (or the start URL of a legacy profile),
//! and reuses it until 15 minutes before it expires.

use std::path::PathBuf;

use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

use crate::auth::token::CachedToken;
use crate::auth::{Session, SessionKind};
use crate::domain::{AccountId, RoleName};
use crate::error::Result;
use crate::fsx::{self, ModePolicy};
use crate::portal::Portal;
use crate::secret::{self, SecretString};

/// botocore's `CachedCredentialFetcher` refreshes this long before expiry.
pub const EXPIRY_WINDOW: SignedDuration = SignedDuration::from_mins(15);

/// Short-lived credentials for one account and role.
#[derive(Debug, Clone)]
pub struct RoleCredentials {
    pub access_key_id: String,
    pub secret_access_key: SecretString,
    pub session_token: SecretString,
    pub expiration: Timestamp,
}

/// The AWS CLI's role credential cache, `~/.aws/cli/cache`.
#[derive(Debug, Clone)]
pub struct RoleCache {
    dir: PathBuf,
}

/// An entry as botocore writes it.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Entry {
    provider_type: String,
    credentials: EntryCredentials,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct EntryCredentials {
    access_key_id: String,
    #[serde(with = "secret::serde_required")]
    secret_access_key: SecretString,
    #[serde(with = "secret::serde_required")]
    session_token: SecretString,
    /// `%Y-%m-%dT%H:%M:%SZ`, as botocore formats it.
    expiration: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account_id: Option<String>,
}

impl RoleCache {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The file name botocore uses for these credentials.
    pub fn key(session: &Session, account: &AccountId, role: &RoleName) -> String {
        // serde_json sorts object keys and writes no whitespace: botocore's
        // `json.dumps(args, sort_keys=True, separators=(',', ':'))`.
        let mut args = serde_json::Map::new();
        args.insert("accountId".into(), account.as_str().into());
        args.insert("roleName".into(), role.as_str().into());
        match &session.kind {
            SessionKind::Named(name) => args.insert("sessionName".into(), name.as_str().into()),
            SessionKind::Legacy(_) => {
                args.insert("startUrl".into(), session.start_url.as_str().into())
            }
        };
        let json = serde_json::Value::Object(args).to_string();
        hex::encode(Sha1::digest(json.as_bytes()))
    }

    fn path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.json"))
    }

    /// The cached credentials, unless they expire within the window. An entry that cannot be
    /// read is treated as missing and replaced.
    pub fn load(&self, key: &str, now: Timestamp) -> Option<RoleCredentials> {
        let path = self.path(key);
        let bytes = fsx::read_optional(&path).ok()??;
        let entry: Entry = match serde_json::from_slice(&bytes) {
            Ok(entry) => entry,
            Err(err) => {
                tracing::debug!(path = %path.display(), "ignoring an unreadable role cache entry: {err}");
                return None;
            }
        };
        let expiration: Timestamp = entry.credentials.expiration.parse().ok()?;
        if expiration.duration_since(now) < EXPIRY_WINDOW {
            return None;
        }
        Some(RoleCredentials {
            access_key_id: entry.credentials.access_key_id,
            secret_access_key: entry.credentials.secret_access_key,
            session_token: entry.credentials.session_token,
            expiration,
        })
    }

    /// When the cached credentials expire, even inside the window `load` refuses them in.
    pub fn expiration(&self, key: &str) -> Option<Timestamp> {
        let bytes = fsx::read_optional(&self.path(key)).ok()??;
        let entry: Entry = serde_json::from_slice(&bytes).ok()?;
        entry.credentials.expiration.parse().ok()
    }

    pub fn store(&self, key: &str, account: &AccountId, creds: &RoleCredentials) -> Result<()> {
        fsx::ensure_private_dir(&self.dir)?;
        let entry = Entry {
            provider_type: "sso".into(),
            credentials: EntryCredentials {
                access_key_id: creds.access_key_id.clone(),
                secret_access_key: creds.secret_access_key.clone(),
                session_token: creds.session_token.clone(),
                expiration: creds.expiration.strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
                account_id: Some(account.to_string()),
            },
        };
        let json = serde_json::to_vec(&entry).expect("serializing plain data cannot fail");
        fsx::write_atomic(&self.path(key), &json, ModePolicy::Private)
    }
}

/// Credentials for the account and role: from the cache while they last, otherwise from
/// `GetRoleCredentials` with the SSO token `token` gets, only then.
pub async fn credentials(
    cache: &RoleCache,
    session: &Session,
    account: &AccountId,
    role: &RoleName,
    token: impl AsyncFnOnce() -> Result<CachedToken>,
) -> Result<RoleCredentials> {
    let key = RoleCache::key(session, account, role);
    if let Some(creds) = cache.load(&key, Timestamp::now()) {
        tracing::debug!(%key, expiration = %creds.expiration, "using cached role credentials");
        return Ok(creds);
    }
    let token = token().await?;
    let creds = Portal::new(session)
        .await
        .role_credentials(&token.access_token, account, role)
        .await?;
    cache.store(&key, account, &creds)?;
    tracing::debug!(%key, expiration = %creds.expiration, "cached new role credentials");
    Ok(creds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aws_files::SsoSessionConfig;

    fn session() -> Session {
        SsoSessionConfig {
            name: "corp".parse().unwrap(),
            start_url: "https://corp.awsapps.com/start".parse().unwrap(),
            region: "us-east-1".parse().unwrap(),
            scopes: Vec::new(),
        }
        .into()
    }

    #[test]
    fn keys_entries_as_botocore_does() {
        // sha1('{"accountId":"111122223333","roleName":"ReadOnly","sessionName":"corp"}')
        let key = RoleCache::key(
            &session(),
            &"111122223333".parse().unwrap(),
            &"ReadOnly".parse().unwrap(),
        );
        let expected = hex::encode(Sha1::digest(
            br#"{"accountId":"111122223333","roleName":"ReadOnly","sessionName":"corp"}"#,
        ));
        assert_eq!(key, expected);
    }

    #[test]
    fn reuses_an_entry_until_the_expiry_window() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RoleCache::new(dir.path().join("cache"));
        let now: Timestamp = "2026-11-06T12:00:00Z".parse().unwrap();
        let creds = RoleCredentials {
            access_key_id: "ASIAEXAMPLE".into(),
            secret_access_key: "secret".into(),
            session_token: "token".into(),
            expiration: "2026-11-06T13:00:00Z".parse().unwrap(),
        };
        let account = "111122223333".parse().unwrap();
        cache.store("k", &account, &creds).unwrap();
        let written: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("cache/k.json")).unwrap())
                .unwrap();
        assert_eq!(written["ProviderType"], "sso");
        assert_eq!(written["Credentials"]["Expiration"], "2026-11-06T13:00:00Z");
        assert_eq!(written["Credentials"]["AccountId"], "111122223333");

        assert!(cache.load("k", now).is_some());
        assert_eq!(cache.expiration("k"), Some(creds.expiration));
        let late: Timestamp = "2026-11-06T12:46:00Z".parse().unwrap();
        assert!(
            cache.load("k", late).is_none(),
            "within 15 minutes of expiry"
        );
        assert!(cache.load("missing", now).is_none());
        assert_eq!(cache.expiration("missing"), None);
        std::fs::write(dir.path().join("cache/bad.json"), "{").unwrap();
        assert!(cache.load("bad", now).is_none());
    }
}
