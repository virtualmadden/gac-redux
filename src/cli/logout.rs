//! `gac logout`: `sso:Logout`, then delete the cached token.

use crate::auth::{self, LogoutOutcome, Session};
use crate::cli::LogoutArgs;
use crate::cli::context::Context;
use crate::error::Result;
use crate::ui;

pub async fn run(ctx: &Context, args: LogoutArgs) -> Result<()> {
    let files = ctx.files().await?;
    let sessions: Vec<Session> = if args.all {
        let mut all: Vec<Session> = files
            .session_names()
            .into_iter()
            .filter_map(|name| files.sso_session(&name.parse().ok()?).ok())
            .map(Session::from)
            .collect();
        for legacy in files.legacy_sso_profiles() {
            let session = Session::from(legacy);
            if !all.iter().any(|s| s.cache_key() == session.cache_key()) {
                all.push(session);
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
    Ok(())
}

fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}
