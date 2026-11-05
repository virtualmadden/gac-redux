//! `gac login`: PKCE in the browser by default, the device code flow over SSH (D6).

use std::time::Duration;

use jiff::Timestamp;

use crate::auth::{self, Flow, LoginOptions};
use crate::cli::LoginArgs;
use crate::cli::context::Context;
use crate::error::{Error, Result};
use crate::ui;

/// How long to wait for the browser sign-in, as the AWS CLI does.
const PKCE_TIMEOUT: Duration = Duration::from_secs(600);

pub async fn run(ctx: &Context, args: LoginArgs) -> Result<()> {
    let files = ctx.files().await?;
    let session = ctx.resolve_session(&files, args.profile.as_deref())?;
    let over_ssh = ["SSH_CONNECTION", "SSH_TTY"]
        .iter()
        .any(|var| std::env::var_os(var).is_some_and(|v| !v.is_empty()));

    let flow = if args.device_code {
        Flow::DeviceCode
    } else if session.is_legacy() && !args.pkce {
        ui::notice(format!(
            "Using the device code flow: {} has an inline start URL, which the AWS CLI also signs in this way. Move it to an [sso-session] to sign in with a browser.",
            session.label()
        ));
        Flow::DeviceCode
    } else if args.pkce {
        Flow::Pkce
    } else if over_ssh {
        ui::notice(
            "SSH session detected: using the device code flow. Pass --pkce to sign in with a browser on this machine.",
        );
        Flow::DeviceCode
    } else {
        Flow::Pkce
    };
    if flow == Flow::DeviceCode && args.port.is_some() {
        return Err(Error::usage(
            "--port sets the PKCE redirect port, but this login uses the device code flow",
        )
        .with_hint(if session.is_legacy() {
            "drop --port"
        } else {
            "add --pkce to sign in with a browser on this machine, or drop --port"
        }));
    }
    let options = LoginOptions {
        flow,
        open_browser: !args.no_browser && (!over_ssh || flow != Flow::DeviceCode),
        port: args.port,
        timeout: PKCE_TIMEOUT,
    };

    let token = auth::login(
        &ctx.token_store(),
        &ctx.paths.sso_cache_dir(),
        &session,
        &options,
    )
    .await?;
    let refresh = if token.is_refreshable(Timestamp::now()) {
        "; it refreshes automatically"
    } else {
        ""
    };
    ui::notice(format!(
        "Logged in to {}. The token is valid until {}{refresh}.",
        session.label(),
        token.expires_at
    ));
    Ok(())
}
