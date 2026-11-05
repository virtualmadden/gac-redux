//! The SSO token cache shared with the AWS CLI and SDKs: `~/.aws/sso/cache/<sha1(key)>.json`,
//! where the key is the `sso-session` name, or the start URL for a legacy profile.
//!
//! Files are written in botocore's key order and format and always carry `startUrl` and `region`,
//! so `aws sso logout` can revoke them server-side. Reads accept anything the CLI or aws-config
//! write. Writers take a sidecar lock, re-read, and replace the file atomically.

use std::path::PathBuf;
use std::time::Duration;

use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use sha2::Sha256;

use crate::auth::botocore_json::{self, timestamp};
use crate::error::{Error, Result};
use crate::fsx::{self, FileLock, ModePolicy};
use crate::secret::{self, ExposeSecret, SecretString};

/// Refresh once less than this remains, matching the AWS CLI (aws-config uses 5 minutes).
pub const REFRESH_WINDOW: SignedDuration = SignedDuration::from_mins(15);

const LOCK_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CachedToken {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(with = "secret::serde_required")]
    pub access_token: SecretString,
    #[serde(with = "timestamp")]
    pub expires_at: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(
        default,
        with = "secret::serde_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub client_secret: Option<SecretString>,
    #[serde(
        default,
        with = "timestamp::optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub registration_expires_at: Option<Timestamp>,
    #[serde(
        default,
        with = "secret::serde_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub refresh_token: Option<SecretString>,
}

/// Where a token stands, for display and for deciding what to do with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenState {
    /// More than the refresh window remains.
    Valid,
    /// Still valid, but inside the refresh window.
    RefreshDue,
    Expired,
}

impl CachedToken {
    pub fn remaining(&self, now: Timestamp) -> SignedDuration {
        self.expires_at.duration_since(now)
    }

    pub fn state(&self, now: Timestamp) -> TokenState {
        let remaining = self.remaining(now);
        if remaining <= SignedDuration::ZERO {
            TokenState::Expired
        } else if remaining < REFRESH_WINDOW {
            TokenState::RefreshDue
        } else {
            TokenState::Valid
        }
    }

    /// A one-way hash that changes whenever another sign-in replaces the token: of the refresh
    /// token, or of the access token when there is none. Safe to store; it reveals no secret.
    pub fn lineage(&self) -> String {
        let secret = self.refresh_token.as_ref().unwrap_or(&self.access_token);
        hex::encode(Sha256::digest(secret.expose_secret().as_bytes()))
    }

    /// Whether a refresh can be attempted: the same test botocore applies.
    pub fn is_refreshable(&self, now: Timestamp) -> bool {
        self.refresh_token.is_some()
            && self.client_id.is_some()
            && self.client_secret.is_some()
            && self.registration_expires_at.is_some_and(|at| at > now)
    }
}

/// Where SSO tokens are kept, keyed by session name or legacy start URL (S2). v1 has one
/// implementation, the AWS-compatible [`SsoCache`].
pub trait TokenStore {
    /// Held across a re-read, refresh and save so concurrent writers do not race.
    type Lock;

    fn load(&self, key: &str) -> Result<Option<CachedToken>>;

    async fn lock(&self, key: &str) -> Result<Self::Lock>;

    /// Stores the token. The caller holds the lock.
    fn save(&self, key: &str, token: &CachedToken) -> Result<()>;

    /// Deletes the token. Returns whether one existed.
    fn delete(&self, key: &str) -> Result<bool>;
}

/// The plaintext token cache directory shared with the AWS CLI and SDKs.
#[derive(Debug, Clone)]
pub struct SsoCache {
    dir: PathBuf,
}

impl SsoCache {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// `sha1(key)` as lowercase hex: the file name the AWS CLI and SDKs look up.
    pub fn file_stem(key: &str) -> String {
        hex::encode(Sha1::digest(key.as_bytes()))
    }

    pub fn path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{}.json", Self::file_stem(key)))
    }

    fn lock_path(&self, key: &str) -> PathBuf {
        // Not `.json`: `aws sso logout` skips files it cannot parse as JSON tokens.
        self.dir.join(format!("{}.lock", Self::file_stem(key)))
    }
}

impl TokenStore for SsoCache {
    type Lock = FileLock;

    fn load(&self, key: &str) -> Result<Option<CachedToken>> {
        let path = self.path(key);
        let Some(bytes) = fsx::read_optional(&path)? else {
            return Ok(None);
        };
        serde_json::from_slice(&bytes).map(Some).map_err(|err| {
            Error::config(format!(
                "the SSO token cache {} is not readable: {err}",
                path.display()
            ))
            .with_hint("log in again to replace it")
        })
    }

    async fn lock(&self, key: &str) -> Result<FileLock> {
        FileLock::acquire(&self.lock_path(key), LOCK_TIMEOUT).await
    }

    /// Writes the token atomically with mode 0600.
    fn save(&self, key: &str, token: &CachedToken) -> Result<()> {
        fsx::ensure_private_dir(&self.dir)?;
        fsx::write_atomic(
            &self.path(key),
            botocore_json::to_string(token).as_bytes(),
            ModePolicy::Private,
        )
    }

    /// Deletes the token. The lock file stays: a process waiting on it would otherwise lock an
    /// unlinked file while a newcomer locks a fresh one, and both would hold "the" lock.
    fn delete(&self, key: &str) -> Result<bool> {
        fsx::remove_if_exists(&self.path(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    fn token(expires_at: &str) -> CachedToken {
        CachedToken {
            start_url: Some("https://corp.awsapps.com/start".into()),
            region: Some("us-west-2".into()),
            access_token: "access".into(),
            expires_at: ts(expires_at),
            client_id: Some("cid".into()),
            client_secret: Some("csecret".into()),
            registration_expires_at: Some(ts("2027-01-22T22:02:06Z")),
            refresh_token: Some("refresh".into()),
        }
    }

    #[test]
    fn cache_file_names_match_the_aws_cli() {
        // Verified against AWS CLI 2.38.2: sha1("corp").
        assert_eq!(
            SsoCache::file_stem("corp"),
            "ee0bfd2552fbd840c02cc48b6e823320543c450f"
        );
    }

    #[test]
    fn writes_botocore_key_order_and_format() {
        insta::assert_snapshot!(
            botocore_json::to_string(&token("2026-10-25T06:01:31Z")),
            @r#"{"startUrl": "https://corp.awsapps.com/start", "region": "us-west-2", "accessToken": "access", "expiresAt": "2026-10-25T06:01:31Z", "clientId": "cid", "clientSecret": "csecret", "registrationExpiresAt": "2027-01-22T22:02:06Z", "refreshToken": "refresh"}"#
        );
    }

    #[test]
    fn reads_what_aws_config_writes() {
        // aws-config writes fractional seconds and may omit the registration fields.
        let parsed: CachedToken = serde_json::from_str(
            r#"{"accessToken":"a","expiresAt":"2026-10-25T06:01:13.210505Z","unknownKey":1}"#,
        )
        .unwrap();
        assert_eq!(parsed.access_token.expose_secret(), "a");
        assert_eq!(parsed.expires_at, ts("2026-10-25T06:01:13.210505Z"));
        assert!(!parsed.is_refreshable(ts("2026-10-25T00:00:00Z")));
    }

    #[test]
    fn lineage_follows_the_refresh_token_and_hides_it() {
        let t = token("2026-10-25T12:00:00Z");
        let mut refreshed = t.clone();
        refreshed.access_token = "access-2".into();
        assert_eq!(t.lineage(), refreshed.lineage(), "a new access token alone");
        refreshed.refresh_token = Some("refresh-2".into());
        assert_ne!(t.lineage(), refreshed.lineage());
        assert!(!t.lineage().contains("refresh"));

        let legacy = CachedToken {
            refresh_token: None,
            ..t.clone()
        };
        let mut relogged = legacy.clone();
        relogged.access_token = "access-2".into();
        assert_ne!(legacy.lineage(), relogged.lineage());
    }

    #[test]
    fn classifies_by_remaining_time() {
        let t = token("2026-10-25T12:00:00Z");
        assert_eq!(t.state(ts("2026-10-25T11:00:00Z")), TokenState::Valid);
        assert_eq!(t.state(ts("2026-10-25T11:50:00Z")), TokenState::RefreshDue);
        assert_eq!(t.state(ts("2026-10-25T12:00:00Z")), TokenState::Expired);
        assert!(t.is_refreshable(ts("2026-10-25T12:00:00Z")));
        assert!(
            !t.is_refreshable(ts("2027-02-01T00:00:00Z")),
            "registration expired"
        );
    }

    #[tokio::test]
    async fn delete_keeps_the_lock_exclusive() {
        let dir = tempfile::tempdir().unwrap();
        let store = SsoCache::new(dir.path().to_path_buf());
        let held = store.lock("corp").await.unwrap();
        store.save("corp", &token("2026-10-25T12:00:00Z")).unwrap();
        assert!(store.delete("corp").unwrap());
        let second = FileLock::acquire(&store.lock_path("corp"), Duration::from_millis(200)).await;
        assert!(second.is_err(), "a second holder got the lock after delete");
        drop(held);
    }

    #[tokio::test]
    async fn saves_privately_and_deletes_the_token() {
        let dir = tempfile::tempdir().unwrap();
        let cache_dir = dir.path().join("sso/cache");
        let store = SsoCache::new(cache_dir.clone());
        let lock = store.lock("corp").await.unwrap();
        store.save("corp", &token("2026-10-25T12:00:00Z")).unwrap();
        drop(lock);
        let loaded = store.load("corp").unwrap().unwrap();
        assert_eq!(loaded.refresh_token.unwrap().expose_secret(), "refresh");
        #[cfg(unix)]
        assert_eq!(fsx::mode(&store.path("corp")), Some(0o600));
        assert!(store.delete("corp").unwrap());
        assert!(store.load("corp").unwrap().is_none());
        assert!(!store.path("corp").exists());
        assert!(store.lock_path("corp").exists(), "the lock file stays");
    }
}
