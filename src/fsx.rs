//! File discipline: atomic writes, private modes and advisory locks. Nothing here knows about AWS.
//!
//! Every write goes to a temp file in the destination directory, is fsynced, renamed over the
//! target and followed by an fsync of the directory. Symlinked targets are resolved first so a
//! dotfile manager's link survives. Modes are kept, and secret files are never looser than 0600.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{Error, Result};

/// How the mode of a written file is chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModePolicy {
    /// A secret: 0600 when new; an existing mode is kept but never looser than 0600.
    Private,
    /// A user-owned file such as `~/.aws/config`: an existing mode is kept as it is; 0600 when new.
    Keep,
}

/// Reads a file, or returns `None` when it does not exist.
pub fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(Error::io_at("read", path, err)),
    }
}

/// Reads a UTF-8 text file, or returns `None` when it does not exist.
pub fn read_text_optional(path: &Path) -> Result<Option<String>> {
    read_optional(path)?
        .map(|bytes| {
            String::from_utf8(bytes).map_err(|err| {
                Error::io_at(
                    "read",
                    path,
                    io::Error::new(io::ErrorKind::InvalidData, err),
                )
            })
        })
        .transpose()
}

/// Deletes a file. Returns whether it existed.
pub fn remove_if_exists(path: &Path) -> Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(Error::io_at("delete", path, err)),
    }
}

/// Creates a directory and its missing parents with mode 0700. An existing directory is left as
/// it is.
pub fn ensure_private_dir(path: &Path) -> Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .map_err(|err| Error::io_at("create directory", path, err))
}

/// The permission bits of a file, where the platform has them.
#[cfg(unix)]
pub fn mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path)
        .ok()
        .map(|m| m.permissions().mode() & 0o7777)
}

/// The permission bits of a file, where the platform has them.
#[cfg(not(unix))]
pub fn mode(_path: &Path) -> Option<u32> {
    None
}

/// The file a write to `path` should land in: the target of a symlink, otherwise `path` itself.
fn resolve_target(path: &Path) -> Result<PathBuf> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            fs::canonicalize(path).map_err(|err| Error::io_at("resolve symlink", path, err))
        }
        _ => Ok(path.to_path_buf()),
    }
}

/// Atomically replaces `path` with `contents`.
pub fn write_atomic(path: &Path, contents: &[u8], policy: ModePolicy) -> Result<()> {
    let target = resolve_target(path)?;
    let dir = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure_private_dir(dir)?;

    let existing_mode = mode(&target);
    let mut tmp = tempfile::Builder::new()
        .prefix(".gac-")
        .suffix(".tmp")
        .tempfile_in(dir)
        .map_err(|err| Error::io_at("create a temp file in", dir, err))?;
    tmp.write_all(contents)
        .map_err(|err| Error::io_at("write", tmp.path(), err))?;
    apply_mode(tmp.as_file(), existing_mode, policy)
        .map_err(|err| Error::io_at("set permissions on", tmp.path(), err))?;
    tmp.as_file()
        .sync_all()
        .map_err(|err| Error::io_at("sync", tmp.path(), err))?;
    persist(tmp, &target)?;
    sync_dir(dir);
    Ok(())
}

#[cfg(unix)]
fn apply_mode(file: &File, existing: Option<u32>, policy: ModePolicy) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = match (policy, existing) {
        (ModePolicy::Private, Some(existing)) => existing & 0o600,
        (ModePolicy::Keep, Some(existing)) => existing,
        (_, None) => 0o600,
    };
    file.set_permissions(fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)] // mirrors the fallible unix signature the caller uses
fn apply_mode(_file: &File, _existing: Option<u32>, _policy: ModePolicy) -> io::Result<()> {
    // Windows has no POSIX modes; files inherit the user profile's ACLs, as with the AWS CLI.
    Ok(())
}

fn persist(tmp: tempfile::NamedTempFile, target: &Path) -> Result<()> {
    // Windows refuses to replace a file another process holds open; retry briefly.
    let attempts = if cfg!(windows) { 10 } else { 1 };
    let mut tmp = tmp;
    for attempt in 1..=attempts {
        match tmp.persist(target) {
            Ok(_) => return Ok(()),
            Err(err)
                if attempt < attempts && err.error.kind() == io::ErrorKind::PermissionDenied =>
            {
                tmp = err.file;
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(err) => return Err(Error::io_at("replace", target, err.error)),
        }
    }
    unreachable!("the final attempt always returns")
}

#[cfg(unix)]
fn sync_dir(dir: &Path) {
    // Durability of the rename. A failure here cannot undo the write, so it is not an error.
    if let Ok(handle) = File::open(dir) {
        let _ = handle.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) {}

/// An exclusive advisory lock on a sidecar file, released on drop.
#[derive(Debug)]
pub struct FileLock {
    file: File,
}

impl FileLock {
    /// Waits for the lock, polling so a stuck holder surfaces as an error instead of a hang.
    pub async fn acquire(path: &Path, timeout: Duration) -> Result<Self> {
        if let Some(dir) = path.parent() {
            ensure_private_dir(dir)?;
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(path)
            .map_err(|err| Error::io_at("open lock file", path, err))?;

        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Self { file }),
                Err(TryLockError::WouldBlock) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(TryLockError::WouldBlock) => {
                    return Err(Error::io_at(
                        "acquire lock",
                        path,
                        io::Error::new(io::ErrorKind::TimedOut, "another gac process holds it"),
                    ));
                }
                Err(TryLockError::Error(err)) => return Err(Error::io_at("lock", path, err)),
            }
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_new_files_privately_and_replaces_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/dir/file.json");
        write_atomic(&path, b"one", ModePolicy::Private).unwrap();
        write_atomic(&path, b"two", ModePolicy::Private).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        let leftovers: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(leftovers, ["file.json"]);
        #[cfg(unix)]
        {
            assert_eq!(mode(&path), Some(0o600));
            assert_eq!(mode(path.parent().unwrap()), Some(0o700));
        }
    }

    #[cfg(unix)]
    #[test]
    fn keeps_modes_but_never_loosens_secrets() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        fs::write(&config, "x").unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o644)).unwrap();
        write_atomic(&config, b"y", ModePolicy::Keep).unwrap();
        assert_eq!(mode(&config), Some(0o644));

        let secret = dir.path().join("secret");
        fs::write(&secret, "x").unwrap();
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o644)).unwrap();
        write_atomic(&secret, b"y", ModePolicy::Private).unwrap();
        assert_eq!(mode(&secret), Some(0o600));
    }

    #[cfg(unix)]
    #[test]
    fn writes_through_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real-config");
        fs::write(&real, "old").unwrap();
        let link = dir.path().join("config");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        write_atomic(&link, b"new", ModePolicy::Keep).unwrap();
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(&real).unwrap(), b"new");
    }

    #[tokio::test]
    async fn locks_are_exclusive_until_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.lock");
        let held = FileLock::acquire(&path, Duration::from_secs(1))
            .await
            .unwrap();
        let err = FileLock::acquire(&path, Duration::from_millis(120))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("acquire lock"), "{err}");
        drop(held);
        FileLock::acquire(&path, Duration::from_secs(1))
            .await
            .unwrap();
    }
}
