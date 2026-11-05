//! The AWS checks behind `gac doctor`. They only read.

use std::ffi::OsString;
use std::path::Path;

use jiff::Timestamp;

use crate::auth::token::{SsoCache, TokenState, TokenStore};
use crate::aws_files::read::missing_session_hint;
use crate::aws_files::{AwsFiles, AwsPaths, guards, managed_block};
use crate::doctor::Report;
use crate::fsx;

/// Everything the checks look at, gathered up front so they stay pure.
#[derive(Debug)]
pub struct Inputs<'a> {
    pub paths: &'a AwsPaths,
    pub files: Result<&'a AwsFiles, String>,
    pub home_var: Option<OsString>,
    pub userprofile_var: Option<OsString>,
    pub now: Timestamp,
}

pub fn run(inputs: &Inputs<'_>) -> Report {
    let mut report = Report::default();
    check_home(&mut report, inputs);
    check_modes(&mut report, inputs.paths);
    match &inputs.files {
        Ok(files) => {
            let files = *files;
            let config = inputs.paths.config_file();
            if config.exists() {
                report.ok("config", format!("{} parses", config.display()));
            } else {
                report.ok("config", format!("{} does not exist yet", config.display()));
            }
            check_t5(&mut report, inputs.paths, files);
            check_sessions(&mut report, inputs, files);
            check_legacy(&mut report, files);
            check_blocks(&mut report, files);
        }
        Err(err) => report.fail(
            "config",
            err.clone(),
            "correct the file; gac and the AWS SDKs read it with the same parser",
        ),
    }
    report
}

fn check_home(report: &mut Report, inputs: &Inputs<'_>) {
    match (&inputs.home_var, &inputs.userprofile_var) {
        (Some(home), Some(profile))
            if !home.is_empty() && !profile.is_empty() && home != profile =>
        {
            report.warn(
                "home",
                format!(
                    "HOME ({}) and USERPROFILE ({}) differ: the AWS CLI on Windows uses USERPROFILE and the Rust SDK uses HOME, so they can read different ~/.aws directories",
                    home.to_string_lossy(),
                    profile.to_string_lossy()
                ),
                "point HOME and USERPROFILE at the same directory",
            );
        }
        _ => report.ok(
            "home",
            format!("AWS files are under {}", inputs.paths.home().display()),
        ),
    }
}

/// `true` when group or others can read or write.
fn too_open(mode: u32) -> bool {
    mode & 0o077 != 0
}

fn check_modes(report: &mut Report, paths: &AwsPaths) {
    let credentials = paths.credentials_file();
    if let Some(mode) = fsx::mode(credentials).filter(|m| too_open(*m)) {
        report.warn(
            "file-modes",
            format!(
                "{} is {mode:o}: other users can read it",
                credentials.display()
            ),
            format!("chmod 600 {}", credentials.display()),
        );
    }
    for dir in [paths.sso_cache_dir(), paths.state_dir()] {
        if let Some(mode) = fsx::mode(&dir).filter(|m| too_open(*m)) {
            report.warn(
                "file-modes",
                format!("{} is {mode:o}: other users can list it", dir.display()),
                format!("chmod 700 {}", dir.display()),
            );
        }
    }
    for file in json_files(&paths.sso_cache_dir()) {
        if let Some(mode) = fsx::mode(&file).filter(|m| too_open(*m)) {
            report.warn(
                "file-modes",
                format!(
                    "{} is {mode:o}: it holds a portal session other users can read",
                    file.display()
                ),
                format!("chmod 600 {}", file.display()),
            );
        }
    }
    if !report.findings.iter().any(|f| f.check == "file-modes") {
        report.ok("file-modes", "credentials and caches are private");
    }
}

fn json_files(dir: &Path) -> Vec<std::path::PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<_> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();
    files
}

fn check_t5(report: &mut Report, paths: &AwsPaths, files: &AwsFiles) {
    let collisions = guards::collisions(files);
    if collisions.is_empty() {
        report.ok(
            "t5",
            "no profile mixes static keys with SSO, process or role settings",
        );
    }
    for collision in collisions {
        report.fail(
            "t5",
            format!(
                "profile `{name}` has static keys in {creds}, but its config section sets {key}; the SDKs ignore the keys, and with no SSO token every lookup fails",
                name = collision.profile,
                creds = paths.credentials_file().display(),
                key = collision.resolving_key
            ),
            format!(
                "delete the [{name}] section from {creds}, or move the keys to a profile name without SSO, process or role settings",
                name = collision.profile,
                creds = paths.credentials_file().display()
            ),
        );
    }
}

fn check_sessions(report: &mut Report, inputs: &Inputs<'_>, files: &AwsFiles) {
    let store = SsoCache::new(inputs.paths.sso_cache_dir());
    let legacy_urls: Vec<String> = files
        .legacy_sso_profiles()
        .into_iter()
        .map(|p| p.start_url.to_string())
        .collect();
    let names = files.session_names();
    if names.is_empty() {
        report.warn(
            "sessions",
            "no [sso-session] is configured",
            "run `gac setup`",
        );
    }
    for name in names {
        let session = match name.parse().and_then(|n| files.sso_session(&n)) {
            Ok(session) => session,
            Err(err) => {
                report.fail(
                    "sessions",
                    format!("[sso-session {name}]: {err}"),
                    err.hint().unwrap_or_default(),
                );
                continue;
            }
        };
        if session.scopes.is_empty() {
            report.warn(
                "sessions",
                format!("[sso-session {name}] has no sso_registration_scopes, so logins get no refresh token"),
                format!("add `sso_registration_scopes = sso:account:access` to [sso-session {name}]"),
            );
        }
        let login = format!("run `gac login --session {name}`");
        match store.load(name) {
            Ok(None) => report.warn(
                "sessions",
                format!("session `{name}` is not logged in"),
                login,
            ),
            Err(err) => report.warn("sessions", format!("session `{name}`: {err}"), login),
            Ok(Some(token)) => match token.state(inputs.now) {
                TokenState::Expired if !token.is_refreshable(inputs.now) => report.warn(
                    "sessions",
                    format!(
                        "session `{name}`: the token expired at {} and cannot be refreshed",
                        token.expires_at
                    ),
                    login,
                ),
                TokenState::Expired | TokenState::RefreshDue => report.ok(
                    "sessions",
                    format!("session `{name}`: the token refreshes on next use"),
                ),
                TokenState::Valid => report.ok(
                    "sessions",
                    format!("session `{name}`: logged in until {}", token.expires_at),
                ),
            },
        }

        let url_keyed = store.path(session.start_url.as_str());
        if url_keyed.exists() && !legacy_urls.contains(&session.start_url.to_string()) {
            report.warn(
                "sessions",
                format!(
                    "{} is a token keyed by the start URL of session `{name}`; sso-session profiles never read it (another tool wrote it)",
                    url_keyed.display()
                ),
                format!("delete {}", url_keyed.display()),
            );
        }
    }
}

fn check_legacy(report: &mut Report, files: &AwsFiles) {
    for profile in files.legacy_sso_profiles() {
        report.warn(
            "legacy-profiles",
            format!(
                "profile `{}` sets sso_start_url inline: a legacy profile with a fixed session and no token refresh",
                profile.profile
            ),
            format!(
                "move sso_start_url and sso_region into an [sso-session NAME] section, then set `sso_session = NAME` in [profile {}]",
                profile.profile
            ),
        );
    }
}

fn check_blocks(report: &mut Report, files: &AwsFiles) {
    match managed_block::scan(files.config_text()) {
        Err(err) => report.fail(
            "managed-blocks",
            format!("the gac markers in the config file are broken: {err}"),
            "repair or delete the `# BEGIN gac` / `# END gac` lines by hand; gac will not write until they are fixed",
        ),
        Ok(blocks) => {
            let mut orphaned = false;
            for block in &blocks {
                if !files.has_session(&block.header.session) {
                    orphaned = true;
                    report.warn(
                        "managed-blocks",
                        format!("the gac block for session `{}` has no [sso-session] section, so its profiles cannot resolve", block.header.session),
                        missing_session_hint(files.config_text(), &block.header.session),
                    );
                }
            }
            if !orphaned {
                let summary = match blocks.len() {
                    0 => "no gac blocks yet".to_owned(),
                    1 => "1 gac block, well formed".to_owned(),
                    n => format!("{n} gac blocks, all well formed"),
                };
                report.ok("managed-blocks", summary);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::Level;

    #[tokio::test]
    async fn flags_t5_legacy_and_orphaned_blocks() {
        let home = tempfile::tempdir().unwrap();
        let paths = AwsPaths::from_vars(|name| {
            (name == "HOME" || name == "USERPROFILE").then(|| home.path().into())
        })
        .unwrap();
        let config = "\
[sso-session corp]
sso_start_url = https://corp.awsapps.com/start
sso_region = us-east-1

[profile dev]
sso_session = corp

[profile old]
sso_start_url = https://old.awsapps.com/start
sso_region = us-east-1

# BEGIN gac sync session=gone mode=sso
# END gac sync session=gone
";
        let files = AwsFiles::parse(config.into(), "[dev]\naws_access_key_id = AKIA\n")
            .await
            .unwrap();
        let report = run(&Inputs {
            paths: &paths,
            files: Ok(&files),
            home_var: None,
            userprofile_var: None,
            now: Timestamp::now(),
        });
        let level_of = |check: &str, needle: &str| {
            report
                .findings
                .iter()
                .find(|f| f.check == check && f.message.contains(needle))
                .map(|f| f.level)
        };
        assert_eq!(level_of("t5", "profile `dev`"), Some(Level::Fail));
        assert_eq!(
            level_of("sessions", "no sso_registration_scopes"),
            Some(Level::Warn)
        );
        assert_eq!(level_of("sessions", "not logged in"), Some(Level::Warn));
        assert_eq!(
            level_of("legacy-profiles", "profile `old`"),
            Some(Level::Warn)
        );
        assert_eq!(
            level_of("managed-blocks", "session `gone`"),
            Some(Level::Warn)
        );
        assert!(report.has_failures());
    }

    #[test]
    fn reports_a_home_mismatch() {
        let home = tempfile::tempdir().unwrap();
        let paths = AwsPaths::from_vars(|name| {
            (name == "HOME" || name == "USERPROFILE").then(|| home.path().into())
        })
        .unwrap();
        let report = run(&Inputs {
            paths: &paths,
            files: Err("cannot parse".into()),
            home_var: Some("/a".into()),
            userprofile_var: Some("/b".into()),
            now: Timestamp::now(),
        });
        assert_eq!(report.findings[0].check, "home");
        assert_eq!(report.findings[0].level, Level::Warn);
        assert!(report.has_failures(), "an unparsable config fails");
    }
}
