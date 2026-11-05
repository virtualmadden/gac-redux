//! Identity Center authentication: logging in, keeping the shared token cache fresh, and
//! logging out.

pub mod botocore_json;
mod device;
pub mod oidc;
mod pkce;
pub mod registration;
pub mod token;

use std::io;
use std::path::Path;
use std::time::Duration;

use jiff::Timestamp;

use crate::aws_files::{LegacySsoProfile, SsoSessionConfig};
use crate::domain::{Region, SessionName, StartUrl};
use crate::error::{Error, Result};
use crate::fsx;
use crate::portal::Portal;
use crate::secret;
use oidc::{ClientCredentials, Oidc, TokenGrant};
use registration::Grant;
use token::{CachedToken, TokenState, TokenStore};

/// What a login is for: an `sso-session`, or a legacy profile with an inline start URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub kind: SessionKind,
    pub start_url: StartUrl,
    pub region: Region,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionKind {
    Named(SessionName),
    /// Read and logged in for interop, never written (S3).
    Legacy(String),
}

impl From<SsoSessionConfig> for Session {
    fn from(config: SsoSessionConfig) -> Self {
        Self {
            kind: SessionKind::Named(config.name),
            start_url: config.start_url,
            region: config.region,
            scopes: config.scopes,
        }
    }
}

impl From<LegacySsoProfile> for Session {
    fn from(profile: LegacySsoProfile) -> Self {
        Self {
            kind: SessionKind::Legacy(profile.profile),
            start_url: profile.start_url,
            region: profile.region,
            scopes: Vec::new(),
        }
    }
}

impl Session {
    pub fn name(&self) -> Option<&SessionName> {
        match &self.kind {
            SessionKind::Named(name) => Some(name),
            SessionKind::Legacy(_) => None,
        }
    }

    pub fn is_legacy(&self) -> bool {
        matches!(self.kind, SessionKind::Legacy(_))
    }

    /// The token cache key: the session name, or the start URL for a legacy profile.
    pub fn cache_key(&self) -> &str {
        match &self.kind {
            SessionKind::Named(name) => name.as_str(),
            SessionKind::Legacy(_) => self.start_url.as_str(),
        }
    }

    pub fn label(&self) -> String {
        match &self.kind {
            SessionKind::Named(name) => format!("session `{name}`"),
            SessionKind::Legacy(profile) => format!("profile `{profile}`"),
        }
    }

    pub fn login_args(&self) -> String {
        match &self.kind {
            SessionKind::Named(name) => format!("--session {name}"),
            SessionKind::Legacy(profile) => format!("--profile {profile}"),
        }
    }

    pub fn login_required(&self, reason: impl Into<String>) -> Error {
        Error::LoginRequired {
            target: self.label(),
            login_args: self.login_args(),
            reason: reason.into(),
        }
    }
}

/// How the user signs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// Authorization code with PKCE through a loopback redirect: the default.
    Pkce,
    /// RFC 8628 device authorization: for SSH sessions and headless machines.
    DeviceCode,
}

#[derive(Debug, Clone)]
pub struct LoginOptions {
    pub flow: Flow,
    pub open_browser: bool,
    pub port: Option<u16>,
    pub timeout: Duration,
}

/// Runs a login and saves the token. Client registrations are cached in `registrations`.
pub async fn login(
    store: &impl TokenStore,
    registrations: &Path,
    session: &Session,
    options: &LoginOptions,
) -> Result<CachedToken> {
    if session.is_legacy() && options.flow == Flow::Pkce {
        // botocore registers legacy clients without scopes, and an /authorize request has to
        // name some, so the AWS CLI signs legacy profiles in with the device code flow only.
        return Err(Error::usage(format!(
            "{} has an inline start URL, so it signs in with the device code flow only",
            session.label()
        ))
        .with_hint("drop --pkce, or move the profile to an [sso-session] with `gac setup`"));
    }
    let oidc = Oidc::new(&session.region).await;
    let grant_kind = match options.flow {
        Flow::Pkce => Grant::AuthorizationCode,
        Flow::DeviceCode => Grant::DeviceCode,
    };
    let client =
        registration::obtain(&oidc, registrations, session, grant_kind, Timestamp::now()).await?;
    let grant = match options.flow {
        Flow::Pkce => pkce::login(&oidc, &client, session, options).await?,
        Flow::DeviceCode => device::login(&oidc, &client, session, options).await?,
    };
    let token = new_token(session, &client, grant, Timestamp::now())?;
    let _lock = store.lock(session.cache_key()).await?;
    store.save(session.cache_key(), &token)?;
    tracing::debug!(
        key = session.cache_key(),
        expires_at = %token.expires_at,
        refreshable = token.refresh_token.is_some(),
        "saved the SSO token"
    );
    Ok(token)
}

/// The token as botocore would cache it after a login.
fn new_token(
    session: &Session,
    client: &ClientCredentials,
    grant: TokenGrant,
    now: Timestamp,
) -> Result<CachedToken> {
    Ok(CachedToken {
        start_url: Some(session.start_url.to_string()),
        region: Some(session.region.to_string()),
        access_token: grant.access_token,
        expires_at: expiry(now, grant.expires_in)?,
        client_id: Some(client.client_id.clone()),
        client_secret: Some(client.client_secret.clone()),
        registration_expires_at: Some(client.expires_at),
        refresh_token: grant.refresh_token,
    })
}

fn expiry(now: Timestamp, expires_in: jiff::SignedDuration) -> Result<Timestamp> {
    now.checked_add(expires_in).map_err(|_| Error::Service {
        operation: "CreateToken",
        message: "the response has an out-of-range expiresIn".into(),
    })
}

/// A usable token, refreshed first when less than 15 minutes remain.
///
/// The refresh takes the sidecar lock and re-reads the cache, so parallel gac processes refresh
/// once, and a token another process (or the AWS CLI) already rotated is used as it is.
pub async fn usable_token(store: &impl TokenStore, session: &Session) -> Result<CachedToken> {
    let key = session.cache_key();
    let token = load_token(store, session)?;
    let now = Timestamp::now();
    if token.state(now) == TokenState::Valid || !token.is_refreshable(now) {
        return usable(token, session, now);
    }

    let _lock = store.lock(key).await?;
    let token = load_token(store, session)?;
    let now = Timestamp::now();
    if token.state(now) == TokenState::Valid || !token.is_refreshable(now) {
        return usable(token, session, now);
    }
    match refresh(session, &token, now).await {
        Ok(refreshed) => {
            store.save(key, &refreshed)?;
            tracing::debug!(expires_at = %refreshed.expires_at, "refreshed the SSO token");
            Ok(refreshed)
        }
        Err(err) if token.state(now) == TokenState::Expired => {
            Err(session.login_required(format!(
                "the SSO token expired at {} and could not be refreshed: {err}",
                token.expires_at
            )))
        }
        Err(err) => {
            tracing::warn!("could not refresh the SSO token: {err}");
            usable(token, session, now)
        }
    }
}

fn load_token(store: &impl TokenStore, session: &Session) -> Result<CachedToken> {
    store
        .load(session.cache_key())?
        .ok_or_else(|| session.login_required("no cached SSO token"))
}

fn usable(token: CachedToken, session: &Session, now: Timestamp) -> Result<CachedToken> {
    if token.state(now) == TokenState::Expired {
        Err(session.login_required(format!("the SSO token expired at {}", token.expires_at)))
    } else {
        tracing::debug!(token = %secret::shape(&token.access_token), expires_at = %token.expires_at, "using the cached SSO token");
        Ok(token)
    }
}

async fn refresh(session: &Session, token: &CachedToken, now: Timestamp) -> Result<CachedToken> {
    let (Some(client_id), Some(client_secret), Some(refresh_token)) =
        (&token.client_id, &token.client_secret, &token.refresh_token)
    else {
        unreachable!("is_refreshable checked these fields");
    };
    let oidc = Oidc::new(&session.region).await;
    let grant = oidc
        .refresh(client_id, client_secret, refresh_token)
        .await?;
    Ok(CachedToken {
        start_url: Some(session.start_url.to_string()),
        region: Some(session.region.to_string()),
        access_token: grant.access_token,
        expires_at: expiry(now, grant.expires_in)?,
        client_id: token.client_id.clone(),
        client_secret: token.client_secret.clone(),
        registration_expires_at: token.registration_expires_at,
        // Keep the old refresh token if the service did not rotate it.
        refresh_token: grant.refresh_token.or_else(|| token.refresh_token.clone()),
    })
}

/// What `logout` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogoutOutcome {
    /// `sso:Logout` revoked the token, and the file was deleted.
    Revoked,
    /// The token had expired, so there was nothing to revoke; the file was deleted.
    Expired,
    /// `sso:Logout` failed; the file was deleted anyway.
    RevokeFailed,
    /// The token file could not be parsed, so nothing was revoked; the file was deleted.
    Unreadable,
    /// There was no token.
    NotLoggedIn,
}

/// Revokes the session server-side when there is a live token, then deletes the token file.
pub async fn logout(store: &impl TokenStore, session: &Session) -> Result<LogoutOutcome> {
    let key = session.cache_key();
    let _lock = store.lock(key).await?;
    let outcome = match store.load(key) {
        Err(err) => {
            tracing::warn!("{err}");
            LogoutOutcome::Unreadable
        }
        Ok(None) => LogoutOutcome::NotLoggedIn,
        Ok(Some(token)) if token.state(Timestamp::now()) == TokenState::Expired => {
            LogoutOutcome::Expired
        }
        Ok(Some(token)) => match Portal::new(session).await.logout(&token.access_token).await {
            Ok(()) => LogoutOutcome::Revoked,
            Err(err) => {
                tracing::warn!("sso:Logout failed; deleting the local token anyway: {err}");
                LogoutOutcome::RevokeFailed
            }
        },
    };
    store.delete(key)?;
    Ok(outcome)
}

/// Deletes the role credentials the AWS CLI cached from SSO tokens, as `aws sso logout` does:
/// every file in `dir` whose JSON has `"ProviderType": "sso"`, whichever session fetched it.
/// Deleting the entry of a session that is still logged in only costs it one
/// `GetRoleCredentials` call. Anything else (assume-role entries, the CLI's `session.db`) is left
/// alone. Returns how many files were deleted.
pub fn sweep_role_credentials(dir: &Path) -> Result<usize> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(err) => return Err(Error::io_at("read", dir, err)),
    };
    let mut deleted = 0;
    for entry in entries {
        let path = entry.map_err(|err| Error::io_at("read", dir, err))?.path();
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(contents) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        if contents.get("ProviderType").and_then(|v| v.as_str()) == Some("sso")
            && fsx::remove_if_exists(&path)?
        {
            deleted += 1;
        }
    }
    Ok(deleted)
}
