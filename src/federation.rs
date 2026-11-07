//! The AWS federation endpoint: role credentials in exchange for a console sign-in link.
//! <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html>

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use url::Url;

use crate::auth::role::RoleCredentials;
use crate::error::Error;
use crate::partition::Partition;
use crate::secret::{ExposeSecret, SecretString};

/// Points the sign-in token request somewhere else; the tests' mock uses it.
const ENDPOINT_VAR: &str = "GAC_REDUX_FEDERATION_ENDPOINT";

#[derive(Debug, Deserialize)]
struct SigninTokenResponse {
    #[serde(rename = "SigninToken")]
    signin_token: String,
}

/// Why there is no sign-in link.
#[derive(Debug)]
pub enum SigninError {
    /// The endpoint answered, and refused the credentials.
    Refused(ureq::http::StatusCode),
    /// It could not be asked, or its answer could not be read.
    Failed(Error),
}

impl SigninError {
    pub fn into_error(self) -> Error {
        match self {
            Self::Refused(status) => Error::config(format!(
                "the AWS federation endpoint refused the role's credentials: HTTP {status}"
            ))
            .with_hint("check that the role may use the AWS console, or try `gac exec` instead"),
            Self::Failed(err) => err,
        }
    }
}

/// The sign-in link for `creds`, landing on `destination`. `issuer` is where the console sends
/// the user when the session ends. The link holds a sign-in token: treat it as a secret.
pub fn signin_url(
    partition: &Partition,
    creds: &RoleCredentials,
    issuer: &str,
    destination: &Url,
) -> std::result::Result<SecretString, SigninError> {
    let endpoint = std::env::var(ENDPOINT_VAR)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| partition.signin.to_owned());
    let session = serde_json::json!({
        "sessionId": creds.access_key_id,
        "sessionKey": creds.secret_access_key.expose_secret(),
        "sessionToken": creds.session_token.expose_secret(),
    })
    .to_string();
    let failed = |reason: String| {
        SigninError::Failed(
            Error::config(format!(
                "could not get a console sign-in token from {endpoint}: {reason}"
            ))
            .with_hint("check the network and HTTPS_PROXY, then run the command again"),
        )
    };
    let mut response = agent()
        .get(&endpoint)
        .query("Action", "getSigninToken")
        .query("Session", &session)
        .call()
        .map_err(|err| failed(err.to_string()))?;
    let status = response.status();
    let body = response
        .body_mut()
        .read_to_string()
        .map_err(|err| failed(err.to_string()))?;
    if status.is_client_error() {
        return Err(SigninError::Refused(status));
    }
    if !status.is_success() {
        return Err(failed(format!("HTTP {status}")));
    }
    let token: SigninTokenResponse =
        serde_json::from_str(&body).map_err(|err| failed(format!("unreadable response: {err}")))?;

    let mut url = Url::parse(&endpoint).map_err(|err| failed(err.to_string()))?;
    url.query_pairs_mut()
        .append_pair("Action", "login")
        .append_pair("Issuer", issuer)
        .append_pair("Destination", destination.as_str())
        .append_pair("SigninToken", &token.signin_token);
    Ok(SecretString::from(String::from(url)))
}

/// An HTTPS client that trusts the system's certificates and honors `HTTPS_PROXY` and
/// `NO_PROXY`, as the AWS SDK does.
fn agent() -> ureq::Agent {
    use ureq::tls::{Certificate, RootCerts, TlsConfig, TlsProvider};
    let roots: Vec<Certificate<'static>> = rustls_native_certs::load_native_certs()
        .certs
        .iter()
        .map(|cert| Certificate::from_der(cert.as_ref()).to_owned())
        .collect();
    let tls = TlsConfig::builder()
        .provider(TlsProvider::Rustls)
        .root_certs(RootCerts::new_with_certs(&roots))
        .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .build();
    ureq::Agent::config_builder()
        .tls_config(tls)
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(30)))
        .user_agent(concat!("gac-redux/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}
