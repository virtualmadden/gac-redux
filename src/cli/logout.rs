//! `gac logout`: `sso:Logout`, delete the cached token, then sweep the AWS CLI's cached SSO role
//! credentials.

use crate::auth::{self, LogoutOutcome, Session};
use crate::cli::LogoutArgs;
use crate::cli::context::Context;
use crate::error::{Error, Result};
use crate::ui;

pub async fn run(ctx: &Context, args: LogoutArgs) -> Result<()> {
    let files = ctx.files().await?;
    let mut unusable = Vec::new();
    let sessions: Vec<Session> = if args.all {
        let mut all = Vec::new();
        for name in files.session_names() {
            match name.parse().and_then(|name| files.sso_session(&name)) {
                Ok(config) => all.push(Session::from(config)),
                Err(err) => unusable.push(err),
            }
        }
        for name in files.config_profile_names() {
            match files.legacy_sso_profile(name) {
                Ok(Some(legacy)) => {
                    let session = Session::from(legacy);
                    if !all.iter().any(|s| s.cache_key() == session.cache_key()) {
                        all.push(session);
                    }
                }
                Ok(None) => {}
                Err(err) => unusable.push(err),
            }
        }
        all
    } else {
        vec![ctx.resolve_session(&files, args.profile.as_deref())?]
    };

    let store = ctx.token_store();
    for session in &sessions {
        let outcome = auth::logout(&store, session).await?;
        let label = session.label();
        let message = match outcome {
            LogoutOutcome::Revoked => format!("Logged out of {label}."),
            LogoutOutcome::Expired => {
                format!("Logged out of {label}; its token had already expired.")
            }
            LogoutOutcome::RevokeFailed => {
                format!("Logged out of {label} locally; revoking the token server-side failed.")
            }
            LogoutOutcome::Unreadable => format!(
                "Deleted the unreadable token of {label}; it could not be revoked server-side, so its portal session lasts until it expires."
            ),
            LogoutOutcome::NotLoggedIn => format!("{label} was not logged in."),
        };
        ui::notice(capitalize(&message));
    }
    let swept = auth::sweep_role_credentials(&ctx.paths.cli_cache_dir())?;
    if swept > 0 {
        let noun = if swept == 1 {
            "credential"
        } else {
            "credentials"
        };
        ui::notice(format!(
            "Deleted {swept} role {noun} the AWS CLI had cached from SSO tokens, for every session, as `aws sso logout` does."
        ));
    }
    if unusable.is_empty() {
        return Ok(());
    }
    for err in &unusable {
        ui::warn(format!("not logged out: {err}"));
    }
    Err(Error::config(format!(
        "{} of the configured sessions and profiles could not be read, so they were not logged out",
        unusable.len()
    ))
    .with_hint("fix them in the AWS config file, then run `gac logout --all` again"))
}

fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}
