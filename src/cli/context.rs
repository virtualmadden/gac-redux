//! What every command shares: the AWS paths, prompting rules, and session resolution.

use std::time::Duration;

use jiff::{SignedDuration, Timestamp};

use crate::auth::token::SsoCache;
use crate::auth::{self, Session};
use crate::aws_files::managed_block::{self, Block};
use crate::aws_files::{AwsFiles, AwsPaths};
use crate::domain::SessionName;
use crate::error::{Error, Result};
use crate::fsx::{self, FileLock, ModePolicy};
use crate::inventory::{Inventory, Snapshot};
use crate::portal::{Account, Portal};
use crate::profiles;
use crate::ui;

/// How long a listing of accounts and roles is reused before asking the portal again.
const INVENTORY_TTL: SignedDuration = SignedDuration::from_hours(1);

#[derive(Debug)]
pub struct Context {
    pub paths: AwsPaths,
    /// `--session`, from the command line.
    session: Option<SessionName>,
    /// `GAC_REDUX_SESSION`: like `--session`, except that `--profile` wins over it.
    env_session: Option<SessionName>,
    no_input: bool,
}

impl Context {
    pub fn new(session: Option<&str>, no_input: bool) -> Result<Self> {
        let paths = AwsPaths::from_env()?;
        paths.migrate_legacy_state_dir();
        Ok(Self {
            paths,
            session: session.map(str::parse).transpose()?,
            env_session: std::env::var("GAC_REDUX_SESSION")
                .ok()
                .filter(|v| !v.is_empty())
                .map(|v| v.parse())
                .transpose()?,
            no_input,
        })
    }

    /// `--session` as typed on the command line; `GAC_REDUX_SESSION` does not count.
    pub fn typed_session(&self) -> Option<&SessionName> {
        self.session.as_ref()
    }

    /// `GAC_REDUX_SESSION`.
    pub fn env_session(&self) -> Option<&SessionName> {
        self.env_session.as_ref()
    }

    /// `--session`, else `GAC_REDUX_SESSION`.
    pub fn session_flag(&self) -> Option<&SessionName> {
        self.session.as_ref().or(self.env_session.as_ref())
    }

    pub fn can_prompt(&self) -> bool {
        ui::can_prompt(self.no_input)
    }

    pub fn token_store(&self) -> SsoCache {
        SsoCache::new(self.paths.sso_cache_dir())
    }

    pub async fn files(&self) -> Result<AwsFiles> {
        AwsFiles::load(&self.paths).await
    }

    /// The managed blocks in the config file. Broken markers are an error: gac does not write
    /// around them.
    pub fn blocks(&self, files: &AwsFiles) -> Result<Vec<Block>> {
        managed_block::scan(files.config_text()).map_err(|err| {
            Error::config(format!(
                "the gac markers in {} are broken: {err}",
                self.paths.config_file().display()
            ))
            .with_hint("repair or delete the `# BEGIN gac-redux` / `# END gac-redux` lines by hand")
        })
    }

    /// Replaces the config file's text, under gac's config lock, only if it still reads as
    /// `original`: a concurrent edit is never overwritten.
    pub async fn write_config(&self, original: &str, updated: &str) -> Result<()> {
        let path = self.paths.config_file();
        let lock_path = self.paths.state_dir().join("config.lock");
        let _lock = FileLock::acquire(&lock_path, Duration::from_secs(30)).await?;
        let current = fsx::read_text_optional(path)?.unwrap_or_default();
        if current != original {
            return Err(
                Error::config(format!("{} changed while gac was working", path.display()))
                    .with_hint("run the command again"),
            );
        }
        fsx::write_atomic(path, updated.as_bytes(), ModePolicy::Keep)
    }

    /// The session's accounts and roles: from the inventory cache while it is fresh and was made
    /// with the current token's lineage, otherwise (or with `refresh`) from the portal. Either way
    /// a usable SSO token is required, which may be refreshed first.
    pub async fn accounts(&self, session: &Session, refresh: bool) -> Result<Snapshot<Account>> {
        let token = auth::usable_token(&self.token_store(), session).await?;
        let inventory = Inventory::new(
            &self.paths.state_dir().join("inventory"),
            session.cache_key(),
            INVENTORY_TTL,
        );
        let scope = format!(
            "{} {} {}",
            session.start_url,
            session.region,
            token.lineage()
        );
        let now = Timestamp::now();
        if !refresh
            && let Some(snapshot) = inventory
                .load(&scope)
                .filter(|s| inventory.is_fresh(s, now))
        {
            tracing::debug!(fetched_at = %snapshot.fetched_at, "using the inventory cache");
            return Ok(snapshot);
        }
        let accounts = Portal::new(session)
            .await
            .accounts_with_roles(&token.access_token)
            .await?;
        inventory.store(&scope, accounts, Timestamp::now())
    }

    /// The session a command acts on: `--session`, else the session of `--profile`, else
    /// `GAC_REDUX_SESSION`, else the session of the `[default]` profile, else the only configured
    /// session.
    pub fn resolve_session(&self, files: &AwsFiles, profile: Option<&str>) -> Result<Session> {
        if let Some(name) = &self.session {
            return Ok(files.sso_session(name)?.into());
        }
        if let Some(profile) = profile {
            return session_of_profile(files, profile);
        }
        if let Some(name) = &self.env_session {
            return Ok(files.sso_session(name)?.into());
        }
        if let Some(name) = default_session(files) {
            if files.has_session(name) {
                return Ok(files.sso_session(&name.parse()?)?.into());
            }
            ui::warn(format!(
                "ignoring the [default] profile's session `{name}`: there is no [sso-session {name}]"
            ));
        }
        match files.session_names().as_slice() {
            [] => Err(no_sessions()),
            [only] => Ok(files.sso_session(&only.parse()?)?.into()),
            many => Err(Error::usage(format!(
                "more than one session is configured: {}",
                many.join(", ")
            ))
            .with_hint("run `gac select` to pick a default profile, or pass --session NAME")),
        }
    }
}

/// The error for a config file with no `[sso-session]` to act on.
pub fn no_sessions() -> Error {
    Error::config("no [sso-session] is configured in the AWS config file")
        .with_hint("run `gac setup`")
}

/// The `sso_session` of the `[default]` profile: the session tools use without --profile.
pub fn default_session(files: &AwsFiles) -> Option<&str> {
    files.config_profile("default")?.get("sso_session")
}

pub fn session_of_profile(files: &AwsFiles, name: &str) -> Result<Session> {
    let profile = files
        .config_profile(name)
        .ok_or_else(|| Error::config(format!("no profile `{name}` in the AWS config file")))?;
    if let Some(session) = profile.get("sso_session") {
        return Ok(files.sso_session(&session.parse()?)?.into());
    }
    if let Some((session, _, _)) = profile
        .get("credential_process")
        .and_then(profiles::parse_process_command)
    {
        return Ok(files.sso_session(&session)?.into());
    }
    if let Some(legacy) = files.legacy_sso_profile(name)? {
        return Ok(legacy.into());
    }
    Err(
        Error::config(format!("profile `{name}` does not use IAM Identity Center"))
            .with_hint("pick a profile with sso_session, or pass --session NAME"),
    )
}
