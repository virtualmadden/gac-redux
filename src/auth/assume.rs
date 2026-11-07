//! Role chaining: STS `AssumeRole` with the credentials of a source profile, for profiles with
//! `role_arn` and `source_profile`. Results are cached the way the AWS CLI caches them, so `gac`
//! and `aws` reuse each other's entries.
//!
//! botocore's `AssumeRoleCredentialFetcher` keys an entry by the SHA-1 of
//! `json.dumps(args, sort_keys=True)`, where `args` holds `RoleArn` and whichever of
//! `RoleSessionName`, `ExternalId` and `DurationSeconds` the profile sets (a generated session
//! name is left out), and stores the `AssumeRole` response, `Expiration` in ISO 8601 with a
//! `+00:00` offset (older botocore wrote a `UTC` suffix).

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, UNIX_EPOCH};

use aws_sdk_sts::error::ProvideErrorMetadata;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

use crate::auth::botocore_json::{self, timestamp};
use crate::auth::role::{EXPIRY_WINDOW, RoleCredentials};
use crate::domain::{AccountId, Region, RoleName};
use crate::error::{self, Error, Result};
use crate::fsx::{self, ModePolicy};
use crate::sdk;
use crate::secret::{self, ExposeSecret, SecretString};

/// An IAM role ARN, `arn:PARTITION:iam::ACCOUNT:role/PATH/NAME`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleArn {
    arn: String,
    account: AccountId,
    role: RoleName,
}

impl RoleArn {
    pub fn as_str(&self) -> &str {
        &self.arn
    }

    pub fn account(&self) -> &AccountId {
        &self.account
    }

    /// The role's name, the last part of its path.
    pub fn role(&self) -> &RoleName {
        &self.role
    }
}

impl fmt::Display for RoleArn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.arn)
    }
}

impl FromStr for RoleArn {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let invalid = || {
            Error::usage(format!("`{s}` is not an IAM role ARN"))
                .with_hint("use arn:aws:iam::ACCOUNT_ID:role/NAME")
        };
        let mut parts = s.splitn(6, ':');
        let (Some("arn"), Some(partition), Some("iam"), Some(""), Some(account), Some(resource)) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return Err(invalid());
        };
        let name = resource.strip_prefix("role/").ok_or_else(invalid)?;
        let name = name.rsplit('/').next().unwrap_or_default();
        if partition.is_empty() {
            return Err(invalid());
        }
        Ok(Self {
            arn: s.to_owned(),
            account: account.parse().map_err(|_| invalid())?,
            role: name.parse().map_err(|_| invalid())?,
        })
    }
}

/// One `AssumeRole` step of a chain, from a profile's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssumeRole {
    pub role_arn: RoleArn,
    /// `role_session_name`; gac names the session when it is unset.
    pub session_name: Option<String>,
    pub external_id: Option<String>,
    pub duration_seconds: Option<u32>,
}

impl AssumeRole {
    /// The file name the AWS CLI uses for this role's credentials.
    pub fn cache_key(&self) -> String {
        let mut args: BTreeMap<&str, serde_json::Value> = BTreeMap::new();
        args.insert("RoleArn", self.role_arn.as_str().into());
        if let Some(name) = &self.session_name {
            args.insert("RoleSessionName", name.as_str().into());
        }
        if let Some(id) = &self.external_id {
            args.insert("ExternalId", id.as_str().into());
        }
        if let Some(seconds) = self.duration_seconds {
            args.insert("DurationSeconds", seconds.into());
        }
        // A `BTreeMap` serializes its keys sorted, as `sort_keys=True` does.
        hex::encode(Sha1::digest(botocore_json::to_string(&args).as_bytes()))
    }
}

/// An entry as botocore writes it: the `AssumeRole` response.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Entry {
    credentials: EntryCredentials,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    assumed_role_user: Option<AssumedRoleUser>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct EntryCredentials {
    access_key_id: String,
    #[serde(with = "secret::serde_required")]
    secret_access_key: SecretString,
    #[serde(with = "secret::serde_required")]
    session_token: SecretString,
    /// `2026-11-06T13:00:00+00:00`, as the AWS CLI writes it; `Z` and `UTC` are read too.
    expiration: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AssumedRoleUser {
    assumed_role_id: String,
    arn: String,
}

/// The AWS CLI's credential cache, `~/.aws/cli/cache`, for assumed roles.
#[derive(Debug, Clone)]
pub struct AssumeCache {
    dir: PathBuf,
}

impl AssumeCache {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn path(&self, step: &AssumeRole) -> PathBuf {
        self.dir.join(format!("{}.json", step.cache_key()))
    }

    /// When the cached credentials expire, even inside the reuse window.
    pub fn expiration(&self, step: &AssumeRole) -> Option<Timestamp> {
        let bytes = fsx::read_optional(&self.path(step)).ok()??;
        let entry: Entry = serde_json::from_slice(&bytes).ok()?;
        timestamp::parse(&entry.credentials.expiration)
    }

    /// The cached credentials, unless they expire within the window.
    fn load(&self, step: &AssumeRole, now: Timestamp) -> Option<RoleCredentials> {
        let bytes = fsx::read_optional(&self.path(step)).ok()??;
        let entry: Entry = match serde_json::from_slice(&bytes) {
            Ok(entry) => entry,
            Err(err) => {
                tracing::debug!(role = %step.role_arn, "ignoring an unreadable cache entry: {err}");
                return None;
            }
        };
        let expiration = timestamp::parse(&entry.credentials.expiration)?;
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

    fn store(&self, step: &AssumeRole, entry: &Entry) -> Result<()> {
        fsx::ensure_private_dir(&self.dir)?;
        fsx::write_atomic(
            &self.path(step),
            botocore_json::to_string(entry).as_bytes(),
            ModePolicy::Private,
        )
    }

    /// Forgets the cached credentials, so the next use assumes the role again.
    pub fn remove(&self, step: &AssumeRole) -> Result<()> {
        fsx::remove_if_exists(&self.path(step)).map(drop)
    }
}

/// Credentials for `step`: from the cache while they last, otherwise from STS `AssumeRole`
/// signed with `source`, asked in `region`.
pub async fn credentials(
    cache: &AssumeCache,
    step: &AssumeRole,
    source: &RoleCredentials,
    region: &Region,
) -> Result<RoleCredentials> {
    if let Some(creds) = cache.load(step, Timestamp::now()) {
        tracing::debug!(role = %step.role_arn, expiration = %creds.expiration, "using cached assumed-role credentials");
        return Ok(creds);
    }
    let entry = assume(step, source, region).await?;
    cache.store(step, &entry)?;
    let creds = entry.credentials;
    let expiration = timestamp::parse(&creds.expiration).expect("formatted above");
    tracing::debug!(role = %step.role_arn, %expiration, "assumed the role");
    Ok(RoleCredentials {
        access_key_id: creds.access_key_id,
        secret_access_key: creds.secret_access_key,
        session_token: creds.session_token,
        expiration,
    })
}

async fn assume(step: &AssumeRole, source: &RoleCredentials, region: &Region) -> Result<Entry> {
    let expiry = UNIX_EPOCH
        + Duration::from_secs(u64::try_from(source.expiration.as_second()).unwrap_or_default());
    let source = aws_credential_types::Credentials::new(
        &source.access_key_id,
        source.secret_access_key.expose_secret(),
        Some(source.session_token.expose_secret().to_owned()),
        Some(expiry),
        "gac-redux",
    );
    let config = aws_sdk_sts::config::Builder::from(&sdk::load(region).await)
        .credentials_provider(source)
        .build();
    let session_name = step
        .session_name
        .clone()
        .unwrap_or_else(|| format!("gac-redux-{}", Timestamp::now().as_second()));
    let output = aws_sdk_sts::Client::from_conf(config)
        .assume_role()
        .role_arn(step.role_arn.as_str())
        .role_session_name(session_name)
        .set_external_id(step.external_id.clone())
        .set_duration_seconds(
            step.duration_seconds
                .map(|s| i32::try_from(s).unwrap_or(i32::MAX)),
        )
        .send()
        .await
        .map_err(|err| {
            if err.code() == Some("AccessDenied") {
                Error::config(format!(
                    "STS refused to let the source profile assume {}: {}",
                    step.role_arn,
                    err.message().unwrap_or("access denied")
                ))
                .with_hint("check that the role's trust policy allows the source profile's role")
            } else {
                error::service("AssumeRole", &err)
            }
        })?;
    let creds = output
        .credentials
        .ok_or_else(|| Error::config("STS AssumeRole answered without credentials"))?;
    let expiration = Timestamp::from_second(creds.expiration.secs())
        .map_err(|_| Error::config("STS AssumeRole answered with an unreadable expiration"))?;
    Ok(Entry {
        credentials: EntryCredentials {
            access_key_id: creds.access_key_id,
            secret_access_key: creds.secret_access_key.into(),
            session_token: creds.session_token.into(),
            expiration: expiration.strftime("%Y-%m-%dT%H:%M:%S+00:00").to_string(),
            account_id: Some(step.role_arn.account().to_string()),
        },
        assumed_role_user: output.assumed_role_user.map(|user| AssumedRoleUser {
            assumed_role_id: user.assumed_role_id,
            arn: user.arn,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(arn: &str) -> AssumeRole {
        AssumeRole {
            role_arn: arn.parse().unwrap(),
            session_name: None,
            external_id: None,
            duration_seconds: None,
        }
    }

    #[test]
    fn parses_role_arns() {
        let arn: RoleArn = "arn:aws:iam::111122223333:role/teams/Deploy"
            .parse()
            .unwrap();
        assert_eq!(arn.account().as_str(), "111122223333");
        assert_eq!(arn.role().as_str(), "Deploy");
        for bad in [
            "arn:aws:iam::111122223333:user/Deploy",
            "arn:aws:sts::111122223333:role/Deploy",
            "arn:aws:iam::12:role/Deploy",
            "arn::iam::111122223333:role/Deploy",
            "Deploy",
        ] {
            assert!(bad.parse::<RoleArn>().is_err(), "{bad}");
        }
    }

    #[test]
    fn keys_entries_as_botocore_does() {
        // sha1(json.dumps({"RoleArn": ...}, sort_keys=True)), with Python's separators.
        let digest = |json: &str| hex::encode(Sha1::digest(json.as_bytes()));
        let plain = step("arn:aws:iam::111122223333:role/Deploy");
        assert_eq!(
            plain.cache_key(),
            digest(r#"{"RoleArn": "arn:aws:iam::111122223333:role/Deploy"}"#)
        );
        let full = AssumeRole {
            session_name: Some("ci".into()),
            external_id: Some("ext".into()),
            duration_seconds: Some(3600),
            ..plain
        };
        assert_eq!(
            full.cache_key(),
            digest(
                r#"{"DurationSeconds": 3600, "ExternalId": "ext", "RoleArn": "arn:aws:iam::111122223333:role/Deploy", "RoleSessionName": "ci"}"#
            )
        );
    }

    #[test]
    fn reads_entries_the_aws_cli_wrote() {
        let dir = tempfile::tempdir().unwrap();
        let cache = AssumeCache::new(dir.path());
        let step = step("arn:aws:iam::111122223333:role/Deploy");
        let now: Timestamp = "2026-11-06T12:00:00Z".parse().unwrap();
        for expiration in [
            "2026-11-06T13:00:00UTC",
            "2026-11-06T13:00:00Z",
            "2026-11-06T13:00:00+00:00",
        ] {
            std::fs::write(
                dir.path().join(format!("{}.json", step.cache_key())),
                format!(
                    r#"{{"Credentials": {{"AccessKeyId": "ASIA", "SecretAccessKey": "s", "SessionToken": "t", "Expiration": "{expiration}"}}, "AssumedRoleUser": {{"AssumedRoleId": "AROA:x", "Arn": "arn:aws:sts::111122223333:assumed-role/Deploy/x"}}, "ResponseMetadata": {{"RequestId": "r"}}}}"#
                ),
            )
            .unwrap();
            let creds = cache.load(&step, now).expect(expiration);
            assert_eq!(
                creds.expiration,
                "2026-11-06T13:00:00Z".parse::<Timestamp>().unwrap()
            );
        }
        let late: Timestamp = "2026-11-06T12:50:00Z".parse().unwrap();
        assert!(
            cache.load(&step, late).is_none(),
            "within 15 minutes of expiry"
        );
    }
}
