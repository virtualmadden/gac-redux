//! The fixes behind `gac doctor --fix`. Each is mechanical and can be undone by hand, and those
//! that edit lines the user wrote say so, so the caller can ask first. Everything else doctor
//! finds stays report-only.

use std::path::PathBuf;

use crate::auth::registration::DEFAULT_SCOPE;
use crate::aws_files::section::{self, Owner, Target};
use crate::aws_files::{AwsFiles, SsoSessionConfig, managed_block};
use crate::domain::SessionName;
use crate::fsx;
use crate::profiles;

/// What a check found that a fix can repair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// A file or directory others can read.
    Chmod { path: PathBuf, mode: u32 },
    /// The gac block of a session whose `[sso-session]` is gone.
    RemoveBlock { session: String },
    /// A gac block with the markers from before the rename.
    RenameMarkers { session: String },
    /// The state directory from before the rename, `~/.aws/gac`.
    RemoveDir { path: PathBuf },
    /// An `[sso-session]` without `sso_registration_scopes`.
    AddScopes { session: String },
    /// A profile with an inline `sso_start_url`.
    MoveLegacy { profile: String },
}

/// A fix ready to apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fix {
    /// What it does, e.g. "chmod 600 ~/.aws/credentials".
    pub summary: String,
    /// It edits lines the user wrote.
    pub needs_consent: bool,
    /// What to run once it is applied.
    pub next: Option<String>,
    edit: Edit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Edit {
    Chmod {
        path: PathBuf,
        mode: u32,
    },
    RemoveBlock {
        session: String,
    },
    RenameMarkers {
        session: String,
    },
    RemoveDir {
        path: PathBuf,
    },
    AddScopes {
        session: String,
    },
    MoveLegacy {
        session: SsoSessionConfig,
        create: bool,
        profiles: Vec<String>,
    },
}

impl Fix {
    /// Whether it edits the config file, rather than a file's mode.
    pub fn edits_config(&self) -> bool {
        !matches!(self.edit, Edit::Chmod { .. } | Edit::RemoveDir { .. })
    }

    /// Changes a file's mode. A fix that edits the config file does nothing here.
    pub fn apply_to_disk(&self) -> crate::error::Result<()> {
        match &self.edit {
            Edit::Chmod { path, mode } => fsx::set_mode(path, *mode),
            Edit::RemoveDir { path } => std::fs::remove_dir_all(path)
                .map_err(|err| crate::error::Error::io_at("delete", path, err)),
            _ => Ok(()),
        }
    }

    /// The config file's `text` with the fix applied, or why it cannot be.
    pub fn apply_to_config(&self, text: &str) -> Result<String, String> {
        match &self.edit {
            Edit::Chmod { .. } | Edit::RemoveDir { .. } => Ok(text.to_owned()),
            Edit::RemoveBlock { session } => {
                let blocks = managed_block::scan(text).map_err(|err| err.to_string())?;
                let block = blocks
                    .iter()
                    .find(|b| b.header.session == *session)
                    .ok_or_else(|| format!("the gac block for session `{session}` is gone"))?;
                Ok(managed_block::without(text, block))
            }
            Edit::RenameMarkers { session } => {
                let blocks = managed_block::scan(text).map_err(|err| err.to_string())?;
                let block = blocks
                    .iter()
                    .find(|b| b.header.session == *session)
                    .ok_or_else(|| format!("the gac block for session `{session}` is gone"))?;
                Ok(managed_block::with_current_markers(text, block))
            }
            Edit::AddScopes { session } => {
                let (mut section, _) =
                    section::find(text, Target::SsoSession(session)).map_err(|e| e.to_string())?;
                section.edit(|section| {
                    section.set(
                        "sso_registration_scopes",
                        DEFAULT_SCOPE,
                        &["sso_start_url", "sso_region"],
                    );
                });
                Ok(section.splice_into(text))
            }
            Edit::MoveLegacy {
                session,
                create,
                profiles,
            } => {
                let mut text = text.to_owned();
                for profile in profiles {
                    let (mut section, owner) = section::find(&text, Target::Profile(profile))
                        .map_err(|e| e.to_string())?;
                    if owner == Owner::Gac {
                        return Err(format!("[profile {profile}] is inside a gac block"));
                    }
                    section.edit(|section| {
                        section.set("sso_session", session.name.as_str(), &["sso_start_url"]);
                        section.remove("sso_start_url");
                        section.remove("sso_region");
                    });
                    text = section.splice_into(&text);
                }
                if *create {
                    text = profiles::append_session_block(&text, session);
                }
                Ok(text)
            }
        }
    }
}

/// The fixes for `actions`, in the order to apply them: modes, then gac's own blocks, then the
/// edits to the user's lines. Legacy profiles with the same start URL and region share one new
/// `[sso-session]`, or an existing one that matches.
pub fn plan(actions: &[Action], files: &AwsFiles) -> Vec<Fix> {
    let mut planned = Vec::new();
    for action in actions {
        match action {
            Action::Chmod { path, mode } => planned.push(Fix {
                summary: format!("chmod {mode:o} {}", path.display()),
                needs_consent: false,
                next: None,
                edit: Edit::Chmod {
                    path: path.clone(),
                    mode: *mode,
                },
            }),
            Action::RemoveBlock { session } => planned.push(Fix {
                summary: format!(
                    "remove the gac block of session `{session}`, whose [sso-session] is gone"
                ),
                needs_consent: false,
                next: Some(format!(
                    "run `gac setup --session {session}` if you still use that session"
                )),
                edit: Edit::RemoveBlock {
                    session: session.clone(),
                },
            }),
            Action::RenameMarkers { session } => planned.push(Fix {
                summary: format!(
                    "give the gac block of session `{session}` the `# BEGIN gac-redux sync` markers"
                ),
                needs_consent: false,
                next: None,
                edit: Edit::RenameMarkers {
                    session: session.clone(),
                },
            }),
            Action::RemoveDir { path } => planned.push(Fix {
                summary: format!("delete {}, left from before the rename", path.display()),
                needs_consent: false,
                next: None,
                edit: Edit::RemoveDir { path: path.clone() },
            }),
            Action::AddScopes { .. } | Action::MoveLegacy { .. } => {}
        }
    }
    for action in actions {
        if let Action::AddScopes { session } = action {
            let owner = section::find(files.config_text(), Target::SsoSession(session))
                .map_or(Owner::User, |(_, owner)| owner);
            planned.push(Fix {
                summary: format!(
                    "add `sso_registration_scopes = {DEFAULT_SCOPE}` to [sso-session {session}]"
                ),
                needs_consent: owner == Owner::User,
                next: Some(format!(
                    "run `gac login --session {session}` to get a refreshable token"
                )),
                edit: Edit::AddScopes {
                    session: session.clone(),
                },
            });
        }
    }
    planned.extend(legacy_fixes(actions, files));
    planned
}

fn legacy_fixes(actions: &[Action], files: &AwsFiles) -> Vec<Fix> {
    let mut taken: Vec<String> = files
        .session_names()
        .into_iter()
        .map(str::to_owned)
        .collect();
    if let Ok(blocks) = managed_block::scan(files.config_text()) {
        taken.extend(blocks.into_iter().map(|b| b.header.session));
    }
    let existing: Vec<SsoSessionConfig> = files
        .session_names()
        .into_iter()
        .filter_map(|name| files.sso_session(&name.parse().ok()?).ok())
        .collect();

    let mut groups: Vec<(SsoSessionConfig, bool, Vec<String>)> = Vec::new();
    for action in actions {
        let Action::MoveLegacy { profile } = action else {
            continue;
        };
        let Ok(Some(legacy)) = files.legacy_sso_profile(profile) else {
            continue;
        };
        let same =
            |s: &SsoSessionConfig| s.start_url == legacy.start_url && s.region == legacy.region;
        if let Some((_, _, profiles)) = groups.iter_mut().find(|(s, _, _)| same(s)) {
            profiles.push(profile.clone());
            continue;
        }
        let (session, create) = if let Some(session) = existing.iter().find(|s| same(s)) {
            (session.clone(), false)
        } else {
            {
                let name = unused_name(&profiles::suggest_session_name(&legacy.start_url), &taken);
                taken.push(name.to_string());
                let session = SsoSessionConfig {
                    name,
                    start_url: legacy.start_url.clone(),
                    region: legacy.region.clone(),
                    scopes: vec![DEFAULT_SCOPE.to_owned()],
                };
                (session, true)
            }
        };
        groups.push((session, create, vec![profile.clone()]));
    }

    groups
        .into_iter()
        .map(|(session, create, profiles)| {
            let names = profiles
                .iter()
                .map(|p| format!("`{p}`"))
                .collect::<Vec<_>>()
                .join(", ");
            let noun = if profiles.len() == 1 {
                "profile"
            } else {
                "profiles"
            };
            let summary = if create {
                format!(
                    "move the start URL of {noun} {names} into a new [sso-session {}]",
                    session.name
                )
            } else {
                format!(
                    "point {noun} {names} at the existing [sso-session {}]",
                    session.name
                )
            };
            Fix {
                summary,
                needs_consent: true,
                next: Some(format!("run `gac login --session {}`", session.name)),
                edit: Edit::MoveLegacy {
                    session,
                    create,
                    profiles,
                },
            }
        })
        .collect()
}

/// `name`, or `name-2`, `name-3`, ... if it is taken.
fn unused_name(name: &SessionName, taken: &[String]) -> SessionName {
    // One of the first `taken.len() + 1` candidates is free.
    (1..=taken.len() + 1)
        .map(|n| match n {
            1 => name.to_string(),
            n => format!("{name}-{n}"),
        })
        .find(|candidate| !taken.contains(candidate))
        .and_then(|candidate| candidate.parse().ok())
        .expect("a suffixed session name is valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn files(config: &str) -> AwsFiles {
        AwsFiles::parse(config.to_owned(), "").await.unwrap()
    }

    fn apply(planned: &[Fix], text: &str) -> String {
        planned.iter().fold(text.to_owned(), |text, fix| {
            fix.apply_to_config(&text).unwrap()
        })
    }

    #[tokio::test]
    async fn legacy_profiles_with_one_portal_share_a_new_session() {
        let config = "\
[sso-session corp]
sso_start_url = https://corp.awsapps.com/start
sso_region = us-east-1
sso_registration_scopes = sso:account:access

[profile a]
sso_start_url = https://old.awsapps.com/start
sso_region    = eu-west-1
sso_account_id = 111122223333
sso_role_name = ReadOnly
region = eu-west-1

[profile b]
sso_start_url = https://old.awsapps.com/start
sso_region = eu-west-1
sso_account_id = 444455556666
sso_role_name = Admin

[profile c]
sso_region = us-east-1
sso_start_url = https://corp.awsapps.com/start
sso_account_id = 777788889999
sso_role_name = Dev
";
        let files = files(config).await;
        let actions = ["a", "b", "c"].map(|p| Action::MoveLegacy {
            profile: p.to_owned(),
        });
        let planned = plan(&actions, &files);
        assert_eq!(
            planned
                .iter()
                .map(|f| f.summary.as_str())
                .collect::<Vec<_>>(),
            [
                "move the start URL of profiles `a`, `b` into a new [sso-session old]",
                "point profile `c` at the existing [sso-session corp]"
            ]
        );
        assert!(planned.iter().all(|f| f.needs_consent));
        let updated = apply(&planned, config);
        insta::assert_snapshot!(updated, @r"
        [sso-session corp]
        sso_start_url = https://corp.awsapps.com/start
        sso_region = us-east-1
        sso_registration_scopes = sso:account:access

        [profile a]
        sso_session    = old
        sso_account_id = 111122223333
        sso_role_name  = ReadOnly
        region         = eu-west-1

        [profile b]
        sso_session = old
        sso_account_id = 444455556666
        sso_role_name = Admin

        [profile c]
        sso_session = corp
        sso_account_id = 777788889999
        sso_role_name = Dev

        # BEGIN gac-redux sync session=old
        # Managed by gac-redux: edits inside this block are replaced on the next sync.
        [sso-session old]
        sso_start_url = https://old.awsapps.com/start
        sso_region = eu-west-1
        sso_registration_scopes = sso:account:access
        # END gac-redux sync session=old
        ");

        let after = AwsFiles::parse(updated, "").await.unwrap();
        assert_eq!(after.legacy_sso_profiles(), []);
        assert_eq!(
            after.config_profile("a").unwrap().get("sso_session"),
            Some("old")
        );
    }

    #[tokio::test]
    async fn a_new_session_name_never_collides() {
        let config = "\
[sso-session old]
sso_start_url = https://elsewhere.awsapps.com/start
sso_region = us-east-1

[profile a]
sso_start_url = https://old.awsapps.com/start
sso_region = eu-west-1

# BEGIN gac-redux sync session=old-2
# END gac-redux sync session=old-2
";
        let planned = plan(
            &[Action::MoveLegacy {
                profile: "a".into(),
            }],
            &files(config).await,
        );
        assert!(
            planned[0].summary.ends_with("[sso-session old-3]"),
            "{}",
            planned[0].summary
        );
    }

    #[tokio::test]
    async fn scopes_need_consent_only_outside_gac_blocks() {
        let config = "\
[sso-session mine]
sso_start_url = https://mine.awsapps.com/start
sso_region = us-east-1

# BEGIN gac-redux sync session=gacs
[sso-session gacs]
sso_start_url = https://gacs.awsapps.com/start
sso_region = us-east-1
# END gac-redux sync session=gacs

# BEGIN gac-redux sync session=gone mode=sso
[profile x]
sso_session = gone
# END gac-redux sync session=gone
";
        let actions = [
            Action::AddScopes {
                session: "mine".into(),
            },
            Action::AddScopes {
                session: "gacs".into(),
            },
            Action::RemoveBlock {
                session: "gone".into(),
            },
        ];
        let planned = plan(&actions, &files(config).await);
        assert_eq!(
            planned
                .iter()
                .map(|f| (f.summary.as_str(), f.needs_consent))
                .collect::<Vec<_>>(),
            [
                (
                    "remove the gac block of session `gone`, whose [sso-session] is gone",
                    false
                ),
                (
                    "add `sso_registration_scopes = sso:account:access` to [sso-session mine]",
                    true
                ),
                (
                    "add `sso_registration_scopes = sso:account:access` to [sso-session gacs]",
                    false
                ),
            ]
        );
        let updated = apply(&planned, config);
        assert!(!updated.contains("session=gone"));
        let after = AwsFiles::parse(updated, "").await.unwrap();
        for name in ["mine", "gacs"] {
            let session = after.sso_session(&name.parse().unwrap()).unwrap();
            assert_eq!(session.scopes, [DEFAULT_SCOPE], "{name}");
        }
    }
}
