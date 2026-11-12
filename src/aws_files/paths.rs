//! Where the AWS files live, using the same rules as the AWS CLI.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// The name of gac's own state directory under `~/.aws`.
pub const STATE_DIR_NAME: &str = "gac-redux";

/// The state directory's name before the project was renamed.
const LEGACY_STATE_DIR_NAME: &str = "gac";

#[derive(Debug, Clone)]
pub struct AwsPaths {
    home: PathBuf,
    config: PathBuf,
    credentials: PathBuf,
}

impl AwsPaths {
    pub fn from_env() -> Result<Self> {
        Self::from_vars(|name| std::env::var_os(name))
    }

    /// Resolves the paths from environment variables supplied by `var`.
    pub fn from_vars(var: impl Fn(&str) -> Option<OsString>) -> Result<Self> {
        let home = home_dir(&var).ok_or_else(|| {
            Error::config("cannot find the home directory").with_hint(if cfg!(windows) {
                "set USERPROFILE"
            } else {
                "set HOME"
            })
        })?;
        let config = file_override(&var, "AWS_CONFIG_FILE", &home)
            .unwrap_or_else(|| home.join(".aws").join("config"));
        let credentials = file_override(&var, "AWS_SHARED_CREDENTIALS_FILE", &home)
            .unwrap_or_else(|| home.join(".aws").join("credentials"));
        Ok(Self {
            home,
            config,
            credentials,
        })
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn config_file(&self) -> &Path {
        &self.config
    }

    pub fn credentials_file(&self) -> &Path {
        &self.credentials
    }

    /// `~/.aws/sso/cache`, shared with the AWS CLI and SDKs.
    pub fn sso_cache_dir(&self) -> PathBuf {
        self.home.join(".aws").join("sso").join("cache")
    }

    /// `~/.aws/cli/cache`, where the AWS CLI caches the role credentials it fetches.
    pub fn cli_cache_dir(&self) -> PathBuf {
        self.home.join(".aws").join("cli").join("cache")
    }

    /// `~/.aws/gac-redux`, gac's own state (0700).
    pub fn state_dir(&self) -> PathBuf {
        self.home.join(".aws").join(STATE_DIR_NAME)
    }

    /// `~/.aws/gac`, the state directory's name before the rename.
    pub fn legacy_state_dir(&self) -> PathBuf {
        self.home.join(".aws").join(LEGACY_STATE_DIR_NAME)
    }

    /// Moves the state directory from its name before the rename, `~/.aws/gac`, unless the
    /// current one already exists. Its contents are caches and a lock, so a failure only costs a
    /// refetch and is not an error.
    pub fn migrate_legacy_state_dir(&self) {
        let legacy = self.legacy_state_dir();
        let current = self.state_dir();
        if !legacy.is_dir() || current.exists() {
            return;
        }
        match std::fs::rename(&legacy, &current) {
            Ok(()) => {
                tracing::debug!(from = %legacy.display(), to = %current.display(), "moved the state directory");
            }
            Err(err) => {
                tracing::debug!(from = %legacy.display(), %err, "could not move the old state directory");
            }
        }
    }
}

/// The AWS CLI uses Python's `expanduser`: `USERPROFILE` on Windows, `HOME` elsewhere.
fn home_dir(var: &impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    let non_empty = |name: &str| var(name).filter(|v| !v.is_empty()).map(PathBuf::from);
    if cfg!(windows) {
        non_empty("USERPROFILE").or_else(|| {
            let drive = var("HOMEDRIVE")?;
            let path = var("HOMEPATH")?;
            let mut joined = drive;
            joined.push(path);
            Some(PathBuf::from(joined))
        })
    } else {
        non_empty("HOME")
    }
}

fn file_override(
    var: &impl Fn(&str) -> Option<OsString>,
    name: &str,
    home: &Path,
) -> Option<PathBuf> {
    let value = var(name).filter(|v| !v.is_empty())?;
    let text = value.to_string_lossy();
    // Both the AWS CLI and the SDKs expand a leading `~`.
    if text == "~" {
        return Some(home.to_path_buf());
    }
    if let Some(rest) = text.strip_prefix("~/").or_else(|| text.strip_prefix("~\\")) {
        return Some(home.join(rest));
    }
    Some(PathBuf::from(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn paths(vars: &[(&str, &str)]) -> Result<AwsPaths> {
        let map: HashMap<String, OsString> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), OsString::from(v)))
            .collect();
        AwsPaths::from_vars(|name| map.get(name).cloned())
    }

    #[cfg(not(windows))]
    #[test]
    fn defaults_live_under_home() {
        let p = paths(&[("HOME", "/h")]).unwrap();
        assert_eq!(p.config_file(), Path::new("/h/.aws/config"));
        assert_eq!(p.credentials_file(), Path::new("/h/.aws/credentials"));
        assert_eq!(p.sso_cache_dir(), Path::new("/h/.aws/sso/cache"));
        assert_eq!(p.state_dir(), Path::new("/h/.aws/gac-redux"));
    }

    #[cfg(not(windows))]
    #[test]
    fn honors_file_overrides_with_tilde() {
        let p = paths(&[
            ("HOME", "/h"),
            ("AWS_CONFIG_FILE", "~/alt/config"),
            ("AWS_SHARED_CREDENTIALS_FILE", "/abs/creds"),
        ])
        .unwrap();
        assert_eq!(p.config_file(), Path::new("/h/alt/config"));
        assert_eq!(p.credentials_file(), Path::new("/abs/creds"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_prefers_userprofile_like_the_aws_cli() {
        let p = paths(&[("HOME", r"C:\msys\home"), ("USERPROFILE", r"C:\Users\me")]).unwrap();
        assert_eq!(p.home(), Path::new(r"C:\Users\me"));
    }

    #[test]
    fn moves_the_legacy_state_dir_once() {
        let home = tempfile::tempdir().unwrap();
        let home_str = home.path().to_str().unwrap();
        let p = paths(&[("HOME", home_str), ("USERPROFILE", home_str)]).unwrap();
        let legacy = home.path().join(".aws/gac");
        std::fs::create_dir_all(legacy.join("inventory")).unwrap();
        p.migrate_legacy_state_dir();
        assert!(!legacy.exists());
        assert!(p.state_dir().join("inventory").is_dir());

        // A legacy directory that reappears beside the current one is left alone.
        std::fs::create_dir_all(&legacy).unwrap();
        p.migrate_legacy_state_dir();
        assert!(legacy.is_dir());
        assert!(p.state_dir().join("inventory").is_dir());
    }

    #[test]
    fn missing_home_is_an_error() {
        assert!(paths(&[]).is_err());
    }
}
