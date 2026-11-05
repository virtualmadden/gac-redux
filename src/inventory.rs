//! An on-disk cache of a listing with a time-to-live. Generic over the item; nothing here knows
//! about AWS.

use std::path::{Path, PathBuf};

use jiff::{SignedDuration, Timestamp};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

use crate::error::Result;
use crate::fsx::{self, ModePolicy};

const FORMAT_VERSION: u32 = 1;

/// A stored listing. `scope` identifies what was listed; a snapshot for another scope (say, a
/// session whose start URL changed) is ignored.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot<T> {
    version: u32,
    pub scope: String,
    pub fetched_at: Timestamp,
    pub items: Vec<T>,
}

impl<T> Snapshot<T> {
    pub fn age(&self, now: Timestamp) -> SignedDuration {
        now.duration_since(self.fetched_at)
    }
}

#[derive(Debug, Clone)]
pub struct Inventory {
    path: PathBuf,
    ttl: SignedDuration,
}

impl Inventory {
    /// The cache for `key` in `dir`. The key is hashed into the file name, so any string works.
    pub fn new(dir: &Path, key: &str, ttl: SignedDuration) -> Self {
        Self {
            path: dir.join(format!(
                "{}.json",
                hex::encode(Sha1::digest(key.as_bytes()))
            )),
            ttl,
        }
    }

    /// The stored snapshot for `scope`, fresh or not. An unreadable file counts as absent.
    pub fn load<T: DeserializeOwned>(&self, scope: &str) -> Option<Snapshot<T>> {
        let bytes = fsx::read_optional(&self.path).ok().flatten()?;
        match serde_json::from_slice::<Snapshot<T>>(&bytes) {
            Ok(snapshot) if snapshot.version == FORMAT_VERSION && snapshot.scope == scope => {
                Some(snapshot)
            }
            Ok(_) => None,
            Err(err) => {
                tracing::debug!(path = %self.path.display(), %err, "ignoring an unreadable inventory cache");
                None
            }
        }
    }

    pub fn is_fresh<T>(&self, snapshot: &Snapshot<T>, now: Timestamp) -> bool {
        let age = snapshot.age(now);
        age >= SignedDuration::ZERO && age < self.ttl
    }

    pub fn store<T: Serialize>(
        &self,
        scope: &str,
        items: Vec<T>,
        now: Timestamp,
    ) -> Result<Snapshot<T>> {
        let snapshot = Snapshot {
            version: FORMAT_VERSION,
            scope: scope.to_owned(),
            fetched_at: now,
            items,
        };
        let json =
            serde_json::to_vec_pretty(&snapshot).expect("serializing plain data cannot fail");
        fsx::write_atomic(&self.path, &json, ModePolicy::Private)?;
        Ok(snapshot)
    }

    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_loads_and_expires() {
        let dir = tempfile::tempdir().unwrap();
        let inventory = Inventory::new(
            &dir.path().join("inv"),
            "corp",
            SignedDuration::from_hours(1),
        );
        let t0: Timestamp = "2026-10-25T10:00:00Z".parse().unwrap();
        assert!(inventory.load::<String>("scope-a").is_none());
        inventory
            .store("scope-a", vec!["x".to_owned()], t0)
            .unwrap();

        let snapshot = inventory.load::<String>("scope-a").unwrap();
        assert_eq!(snapshot.items, ["x"]);
        assert!(inventory.is_fresh(&snapshot, t0 + SignedDuration::from_mins(59)));
        assert!(!inventory.is_fresh(&snapshot, t0 + SignedDuration::from_mins(61)));
        assert!(
            !inventory.is_fresh(&snapshot, t0 - SignedDuration::from_mins(1)),
            "clock skew"
        );
        assert!(
            inventory.load::<String>("scope-b").is_none(),
            "another scope"
        );

        std::fs::write(inventory.path(), "not json").unwrap();
        assert!(inventory.load::<String>("scope-a").is_none());
    }
}
