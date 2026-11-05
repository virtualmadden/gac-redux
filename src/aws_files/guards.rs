//! The T5 rule. botocore and the Rust SDK resolve SSO, process and role settings before static
//! keys in the same profile: with a token the keys are silently ignored, and without one the
//! lookup fails hard even though valid keys are in the file. So static keys and resolving
//! settings must never share a profile name, and gac must never create that layout.

use aws_config::profile::Profile;

use crate::aws_files::read::AwsFiles;

/// Config keys that make a profile resolve through SSO, a process or a role.
pub const RESOLVING_KEYS: &[&str] = &[
    "sso_session",
    "sso_start_url",
    "credential_process",
    "role_arn",
    "web_identity_token_file",
    "login_session",
];

const STATIC_KEYS: &[&str] = &["aws_access_key_id", "aws_secret_access_key"];

/// The first resolving key a profile sets, if any.
pub fn resolving_key(profile: &Profile) -> Option<&'static str> {
    RESOLVING_KEYS
        .iter()
        .copied()
        .find(|key| profile.get(key).is_some())
}

pub fn has_static_keys(profile: &Profile) -> bool {
    STATIC_KEYS.iter().any(|key| profile.get(key).is_some())
}

/// A profile that has the T5 layout today: static keys in the credentials file under a name
/// whose config section resolves through something else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collision {
    pub profile: String,
    pub resolving_key: &'static str,
}

pub fn collisions(files: &AwsFiles) -> Vec<Collision> {
    files
        .credentials_profile_names()
        .into_iter()
        .filter(|name| files.credentials_profile(name).is_some_and(has_static_keys))
        .filter_map(|name| {
            let key = files.config_profile(name).and_then(resolving_key)?;
            Some(Collision {
                profile: name.to_owned(),
                resolving_key: key,
            })
        })
        .collect()
}

/// Why a profile name cannot be written into a sync block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameConflict {
    /// The credentials file has a section with this name. Writing an SSO profile would create
    /// the T5 layout when it holds keys, and a confusing merge when it does not.
    CredentialsSection,
    /// The config file already defines this profile outside the block being written.
    ConfigProfile,
}

impl NameConflict {
    pub fn describe(self) -> &'static str {
        match self {
            Self::CredentialsSection => {
                "the credentials file has a section with this name; an SSO profile there would hide its keys (T5)"
            }
            Self::ConfigProfile => {
                "the config file already defines this profile outside this block"
            }
        }
    }
}

/// Checks a name for a sync block. `outside_block` is the config parsed without the block
/// being replaced.
pub fn sync_conflict(
    name: &str,
    outside_block: &AwsFiles,
    files: &AwsFiles,
) -> Option<NameConflict> {
    if files.credentials_profile(name).is_some() {
        Some(NameConflict::CredentialsSection)
    } else if outside_block.config_profile(name).is_some() {
        Some(NameConflict::ConfigProfile)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn finds_the_t5_layout() {
        let config = "\
[profile dev]
sso_session = corp
[profile proc]
credential_process = /bin/true
[profile plain]
region = us-east-1
";
        let credentials = "\
[dev]
aws_access_key_id = AKIAEXAMPLE
aws_secret_access_key = x
[proc]
aws_access_key_id = AKIAEXAMPLE
[plain]
aws_access_key_id = AKIAEXAMPLE
";
        let files = AwsFiles::parse(config.to_owned(), credentials)
            .await
            .unwrap();
        assert_eq!(
            collisions(&files),
            [
                Collision {
                    profile: "dev".into(),
                    resolving_key: "sso_session"
                },
                Collision {
                    profile: "proc".into(),
                    resolving_key: "credential_process"
                },
            ]
        );
    }

    #[tokio::test]
    async fn refuses_names_that_exist_elsewhere() {
        let files = AwsFiles::parse(
            "[profile mine]\nregion = x\n".into(),
            "[keys]\nregion = x\n",
        )
        .await
        .unwrap();
        assert_eq!(
            sync_conflict("keys", &files, &files),
            Some(NameConflict::CredentialsSection)
        );
        assert_eq!(
            sync_conflict("mine", &files, &files),
            Some(NameConflict::ConfigProfile)
        );
        assert_eq!(sync_conflict("fresh", &files, &files), None);
    }
}
