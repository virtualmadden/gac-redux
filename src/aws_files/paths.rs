//! Where the AWS files live, using the same rules as the AWS CLI.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// The name of gac's own state directory under `~/.aws`. It follows the project's final name.
pub const STATE_DIR_NAME: &str = "gac";

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

    /// `~/.aws/gac`, gac's own state (0700).
    pub fn state_dir(&self) -> PathBuf {
        self.home.join(".aws").join(STATE_DIR_NAME)
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
        assert_eq!(p.state_dir(), Path::new("/h/.aws/gac"));
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
    fn missing_home_is_an_error() {
        assert!(paths(&[]).is_err());
    }
}
