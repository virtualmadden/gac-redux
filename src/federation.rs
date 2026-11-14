//! The AWS federation endpoint: role credentials in exchange for a console sign-in link.
//! <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html>

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use url::{Host, Url};

use crate::auth::role::RoleCredentials;
use crate::error::{Error, Result};
use crate::partition::Partition;
use crate::secret::{ExposeSecret, SecretString};

/// Points the sign-in token request somewhere else, for the tests' mock. It is not part of the
/// compatibility promise.
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

/// The federation endpoint for `partition`, or its override. Check it before fetching the
/// credentials it will be sent.
pub fn endpoint(partition: &Partition) -> Result<Url> {
    match std::env::var(ENDPOINT_VAR).ok().filter(|v| !v.is_empty()) {
        Some(value) => override_endpoint(&value),
        None => Ok(Url::parse(partition.signin).expect("a valid federation endpoint")),
    }
}

/// The endpoint is sent live role credentials, so an override has to be HTTPS. Plain HTTP is
/// allowed only to this computer, where the tests' mock listens.
fn override_endpoint(value: &str) -> Result<Url> {
    let url = Url::parse(value)
        .ok()
        .filter(|url| match (url.scheme(), url.host()) {
            ("https", Some(_)) => true,
            ("http", Some(Host::Domain(host))) => host.eq_ignore_ascii_case("localhost"),
            ("http", Some(Host::Ipv4(ip))) => ip.is_loopback(),
            ("http", Some(Host::Ipv6(ip))) => ip.is_loopback(),
            _ => false,
        });
    url.ok_or_else(|| {
        Error::config(format!(
            "{ENDPOINT_VAR} must be an https:// URL, or http:// to localhost, not `{value}`"
        ))
        .with_hint(format!(
            "unset {ENDPOINT_VAR} to use the AWS federation endpoint"
        ))
    })
}

/// The sign-in link for `creds` from `endpoint`, landing on `destination`. `issuer` is where
/// the console sends the user when the session ends. The link holds a sign-in token: treat it
/// as a secret.
pub fn signin_url(
    endpoint: &Url,
    creds: &RoleCredentials,
    issuer: &str,
    destination: &Url,
) -> std::result::Result<SecretString, SigninError> {
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
        .get(endpoint.as_str())
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

    let mut url = endpoint.clone();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_override_must_be_https_or_reach_only_this_computer() {
        for allowed in [
            "https://signin.example.com/federation",
            "http://127.0.0.1:8080/federation",
            "http://127.0.0.2/federation",
            "http://[::1]:8080/federation",
            "http://localhost:8080/federation",
            "http://LOCALHOST/federation",
        ] {
            assert_eq!(
                override_endpoint(allowed).unwrap().as_str(),
                allowed.to_lowercase()
            );
        }
        for refused in [
            "http://signin.example.com/federation",
            "http://10.0.0.1/federation",
            "http://localhost.example.com/federation",
            "http://127.0.0.1.example.com/federation",
            "ftp://signin.example.com/federation",
            "file:///etc/passwd",
            "signin.example.com/federation",
            "not a url",
        ] {
            let err = override_endpoint(refused).unwrap_err();
            assert!(err.to_string().contains(ENDPOINT_VAR), "{err}");
            assert_eq!(err.exit_code(), crate::error::exit::ERROR);
        }
    }
}
