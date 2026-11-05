//! The device authorization login (RFC 8628). It can be phished: anyone holding the link can
//! approve it from any device. So it runs only on request or over SSH, with a notice.

use crate::auth::oidc::{ClientCredentials, Oidc, TokenGrant};
use crate::auth::{LoginOptions, Session};
use crate::error::{Error, Result};
use crate::oauth::device_poll::{self, PollError};
use crate::ui;

pub async fn login(
    oidc: &Oidc,
    client: &ClientCredentials,
    session: &Session,
    options: &LoginOptions,
) -> Result<TokenGrant> {
    let authorization = oidc
        .start_device_authorization(client, session.start_url.as_str())
        .await?;
    let url = authorization
        .verification_uri_complete
        .as_deref()
        .unwrap_or(&authorization.verification_uri);

    ui::notice(format!("Sign in to {} by opening:", session.start_url));
    ui::notice(format!("  {url}"));
    ui::notice(format!(
        "and confirm that the page shows the code {}",
        authorization.user_code
    ));
    ui::notice("Only approve a code you requested yourself.");
    if options.open_browser {
        ui::browser::open(url);
    }
    ui::notice("Waiting for approval...");

    let interval = authorization.interval.unsigned_abs();
    let expires_in = authorization.expires_in.unsigned_abs();
    device_poll::poll(interval, expires_in, || {
        oidc.poll_device_token(client, &authorization.device_code)
    })
    .await
    .map_err(|err| match err {
        PollError::Expired => Error::login("the device code expired before it was approved")
            .with_hint("run the login again"),
        PollError::Failed(err) => err,
    })
}
