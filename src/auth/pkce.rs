//! The authorization-code login with PKCE, as the AWS CLI runs it (its default since 2.22.0).

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

use crate::auth::oidc::{ClientCredentials, Oidc, TokenGrant};
use crate::auth::registration;
use crate::auth::{LoginOptions, Session};
use crate::error::Result;
use crate::oauth::loopback::Loopback;
use crate::oauth::pkce::{Pkce, random_state};
use crate::ui;

const CALLBACK_PATH: &str = "/oauth/callback";

/// RFC 3986 unreserved characters stay; everything else is percent-encoded, as botocore does.
const QUERY_ESCAPES: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

pub async fn login(
    oidc: &Oidc,
    client: &ClientCredentials,
    session: &Session,
    options: &LoginOptions,
) -> Result<TokenGrant> {
    let loopback = Loopback::bind(options.port).await?;
    let redirect_uri = loopback.redirect_uri(CALLBACK_PATH);
    let pkce = Pkce::generate();
    let state = random_state();
    let scopes = registration::scopes_for(session);
    let url = authorize_url(
        &oidc.authorize_base_url().await?,
        &client.client_id,
        &redirect_uri,
        &state,
        &pkce.challenge,
        &scopes,
    );

    ui::notice(format!("Sign in to {} in your browser:", session.start_url));
    ui::notice(format!("  {url}"));
    if options.open_browser && !ui::browser::open(&url) {
        ui::notice("Could not open a browser; open the link above yourself.");
    }
    ui::notice("Waiting for the sign-in to finish...");

    let code = loopback
        .wait_for_code(CALLBACK_PATH, &state, options.timeout)
        .await?;
    oidc.exchange_code(client, &code, &redirect_uri, &pkce.verifier)
        .await
}

/// The `/authorize` URL, with parameters in botocore's order.
fn authorize_url(
    base: &str,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    challenge: &str,
    scopes: &[String],
) -> String {
    let scopes = scopes.join(" ");
    let query = [
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("state", state),
        ("code_challenge_method", "S256"),
        ("scopes", &scopes),
        ("code_challenge", challenge),
    ]
    .iter()
    .map(|(key, value)| format!("{key}={}", utf8_percent_encode(value, QUERY_ESCAPES)))
    .collect::<Vec<_>>()
    .join("&");
    format!("{base}/authorize?{query}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_the_authorize_url_like_botocore() {
        let url = authorize_url(
            "https://oidc.us-east-1.amazonaws.com",
            "cid",
            "http://127.0.0.1:4321/oauth/callback",
            "st",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            &["sso:account:access".into(), "other:scope".into()],
        );
        assert_eq!(
            url,
            "https://oidc.us-east-1.amazonaws.com/authorize?response_type=code&client_id=cid\
             &redirect_uri=http%3A%2F%2F127.0.0.1%3A4321%2Foauth%2Fcallback&state=st\
             &code_challenge_method=S256&scopes=sso%3Aaccount%3Aaccess%20other%3Ascope\
             &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }
}
