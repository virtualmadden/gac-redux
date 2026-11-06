//! Reads `~/.aws/config` and `~/.aws/credentials` with the SDK's own parser, so profile and
//! section semantics match the SDKs exactly. The two files are parsed separately: the SDK merges
//! same-named profiles across them, and the mixed-credentials guard needs to know which file a
//! key came from.

use aws_config::profile::{Profile, ProfileSet};
use aws_runtime::env_config::file::{EnvConfigFileKind, EnvConfigFiles};
use aws_types::os_shim_internal::{Env, Fs};

use crate::aws_files::managed_block;
use crate::aws_files::paths::AwsPaths;
use crate::domain::{Region, SessionName, StartUrl, parse_scopes};
use crate::error::{Error, Result};
use crate::fsx;

/// A snapshot of the two AWS files, read once per command.
#[derive(Debug)]
pub struct AwsFiles {
    config_text: String,
    config: ProfileSet,
    credentials: ProfileSet,
}

/// A resolved `[sso-session NAME]` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsoSessionConfig {
    pub name: SessionName,
    pub start_url: StartUrl,
    pub region: Region,
    pub scopes: Vec<String>,
}

/// A profile with inline `sso_start_url` and no `sso_session`: the legacy, non-refreshable form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacySsoProfile {
    pub profile: String,
    pub start_url: StartUrl,
    pub region: Region,
}

impl AwsFiles {
    pub async fn load(paths: &AwsPaths) -> Result<Self> {
        let config = fsx::read_text_optional(paths.config_file())?.unwrap_or_default();
        let credentials = fsx::read_text_optional(paths.credentials_file())?.unwrap_or_default();
        Self::parse(config, &credentials).await
    }

    pub async fn parse(config_text: String, credentials_text: &str) -> Result<Self> {
        let config = parse_one(EnvConfigFileKind::Config, &config_text)
            .await
            .map_err(|err| Error::config(format!("cannot parse the AWS config file: {err}")))?;
        let credentials = parse_one(EnvConfigFileKind::Credentials, credentials_text)
            .await
            .map_err(|err| {
                Error::config(format!("cannot parse the AWS credentials file: {err}"))
            })?;
        Ok(Self {
            config_text,
            config,
            credentials,
        })
    }

    /// The config file's text, exactly as read.
    pub fn config_text(&self) -> &str {
        &self.config_text
    }

    pub fn session_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.config.sso_sessions().collect();
        names.sort_unstable();
        names
    }

    pub fn has_session(&self, name: &str) -> bool {
        self.config.sso_session(name).is_some()
    }

    pub fn sso_session(&self, name: &SessionName) -> Result<SsoSessionConfig> {
        let section = self.config.sso_session(name.as_str()).ok_or_else(|| {
            Error::config(format!("no [sso-session {name}] in the AWS config file"))
                .with_hint(missing_session_hint(&self.config_text, name.as_str()))
        })?;
        let required = |key: &str| {
            section.get(key).filter(|v| !v.is_empty()).ok_or_else(|| {
                Error::config(format!("[sso-session {name}] has no {key}")).with_hint(format!(
                    "add {key} to [sso-session {name}] in the AWS config file"
                ))
            })
        };
        Ok(SsoSessionConfig {
            name: name.clone(),
            start_url: required("sso_start_url")?.parse()?,
            region: required("sso_region")?.parse()?,
            scopes: section
                .get("sso_registration_scopes")
                .map(parse_scopes)
                .unwrap_or_default(),
        })
    }

    pub fn config_profile_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.config.profiles().collect();
        names.sort_unstable();
        names
    }

    pub fn config_profile(&self, name: &str) -> Option<&Profile> {
        self.config.get_profile(name)
    }

    pub fn credentials_profile_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.credentials.profiles().collect();
        names.sort_unstable();
        names
    }

    pub fn credentials_profile(&self, name: &str) -> Option<&Profile> {
        self.credentials.get_profile(name)
    }

    /// Profiles that log in with an inline start URL. They are read for interop, never written.
    pub fn legacy_sso_profiles(&self) -> Vec<LegacySsoProfile> {
        self.config_profile_names()
            .into_iter()
            .filter_map(|name| self.legacy_sso_profile(name).ok().flatten())
            .collect()
    }

    pub fn legacy_sso_profile(&self, name: &str) -> Result<Option<LegacySsoProfile>> {
        let Some(profile) = self.config.get_profile(name) else {
            return Ok(None);
        };
        if profile.get("sso_session").is_some() {
            return Ok(None);
        }
        let Some(start_url) = profile.get("sso_start_url") else {
            return Ok(None);
        };
        let region = profile.get("sso_region").ok_or_else(|| {
            Error::config(format!(
                "profile `{name}` has sso_start_url but no sso_region"
            ))
        })?;
        Ok(Some(LegacySsoProfile {
            profile: name.to_owned(),
            start_url: start_url.parse()?,
            region: region.parse()?,
        }))
    }
}

async fn parse_one(
    kind: EnvConfigFileKind,
    contents: &str,
) -> std::result::Result<ProfileSet, aws_config::profile::ProfileFileLoadError> {
    let files = EnvConfigFiles::builder()
        .include_default_config_file(false)
        .include_default_credentials_file(false)
        .with_contents(kind, contents)
        .build();
    // The contents are supplied directly, so the empty Fs and Env are never consulted.
    aws_config::profile::load(&Fs::from_slice(&[]), &Env::from_slice(&[]), &files, None).await
}

/// How to recover from a missing `[sso-session NAME]`. `gac setup` refuses to recreate a session
/// whose gac block survived, so the block has to go first.
pub fn missing_session_hint(config_text: &str, session: &str) -> String {
    let orphaned = managed_block::scan(config_text)
        .is_ok_and(|blocks| blocks.iter().any(|b| b.header.session == session));
    if orphaned {
        format!(
            "run `gac doctor --fix` to delete the gac block for session `{session}`, then `gac setup --session {session}`"
        )
    } else {
        format!("run `gac setup --session {session}`")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = "\
[default]
region = us-west-2

[sso-session corp]
sso_start_url = https://corp.awsapps.com/start
sso_region = us-east-1
sso_registration_scopes = sso:account:access

[profile dev]
sso_session = corp
sso_account_id = 111122223333
sso_role_name = ReadOnly

[profile legacy]
sso_start_url = https://old.awsapps.com/start
sso_region = eu-west-1
sso_account_id = 111122223333
sso_role_name = ReadOnly

[sso-session broken]
sso_region = us-east-1
";

    #[tokio::test]
    async fn reads_sessions_and_profiles() {
        let files = AwsFiles::parse(CONFIG.to_owned(), "[dev]\naws_access_key_id = AKIA\n")
            .await
            .unwrap();
        assert_eq!(files.session_names(), ["broken", "corp"]);
        let corp = files.sso_session(&"corp".parse().unwrap()).unwrap();
        assert_eq!(corp.start_url.as_str(), "https://corp.awsapps.com/start");
        assert_eq!(corp.region.as_str(), "us-east-1");
        assert_eq!(corp.scopes, ["sso:account:access"]);
        assert_eq!(files.config_profile_names(), ["default", "dev", "legacy"]);
        assert_eq!(files.credentials_profile_names(), ["dev"]);
        assert!(
            files
                .config_profile("dev")
                .unwrap()
                .get("aws_access_key_id")
                .is_none(),
            "the files are parsed separately"
        );
    }

    #[tokio::test]
    async fn reports_incomplete_sessions() {
        let files = AwsFiles::parse(CONFIG.to_owned(), "").await.unwrap();
        let err = files.sso_session(&"broken".parse().unwrap()).unwrap_err();
        assert!(err.to_string().contains("no sso_start_url"), "{err}");
        let err = files.sso_session(&"missing".parse().unwrap()).unwrap_err();
        assert_eq!(err.hint().unwrap(), "run `gac setup --session missing`");
        let orphaned = format!(
            "{CONFIG}\n# BEGIN gac-redux sync session=missing\n# END gac-redux sync session=missing\n"
        );
        let files = AwsFiles::parse(orphaned, "").await.unwrap();
        let err = files.sso_session(&"missing".parse().unwrap()).unwrap_err();
        assert_eq!(
            err.hint().unwrap(),
            "run `gac doctor --fix` to delete the gac block for session `missing`, then `gac setup --session missing`"
        );
    }

    #[tokio::test]
    async fn finds_legacy_profiles() {
        let files = AwsFiles::parse(CONFIG.to_owned(), "").await.unwrap();
        let legacy = files.legacy_sso_profiles();
        assert_eq!(legacy.len(), 1);
        assert_eq!(legacy[0].profile, "legacy");
        assert_eq!(legacy[0].region.as_str(), "eu-west-1");
    }
}
