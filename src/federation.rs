//! The AWS federation endpoint: role credentials in exchange for a console sign-in link.
//! <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html>

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use url::Url;

use crate::auth::role::RoleCredentials;
use crate::domain::Region;
use crate::error::{Error, Result};
use crate::secret::{ExposeSecret, SecretString};

/// Points the sign-in token request somewhere else; the tests' mock uses it.
const ENDPOINT_VAR: &str = "GAC_REDUX_FEDERATION_ENDPOINT";

/// The sign-in and console hosts of a partition, known from any of its regions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    pub signin: &'static str,
    pub console: &'static str,
}

impl Partition {
    pub fn of(region: &Region) -> Self {
        let region = region.as_str();
        if region.starts_with("cn-") {
            Self {
                signin: "https://signin.amazonaws.cn/federation",
                console: "https://console.amazonaws.cn",
            }
        } else if region.starts_with("us-gov-") {
            Self {
                signin: "https://signin.amazonaws-us-gov.com/federation",
                console: "https://console.amazonaws-us-gov.com",
            }
        } else {
            Self {
                signin: "https://signin.aws.amazon.com/federation",
                console: "https://console.aws.amazon.com",
            }
        }
    }

    /// The console page to land on: `destination` as a full URL, or as a path under the console
    /// (`s3/home`), else the console home. A region is added unless the page names one.
    pub fn destination(&self, destination: Option<&str>, region: Option<&Region>) -> Result<Url> {
        let mut url = match destination {
            Some(full) if full.starts_with("https://") => Url::parse(full).map_err(|err| {
                Error::usage(format!("--destination `{full}` is not a URL: {err}"))
            })?,
            Some(path) => Url::parse(&format!(
                "{}/{}",
                self.console,
                path.trim_start_matches('/')
            ))
            .map_err(|err| {
                Error::usage(format!(
                    "--destination `{path}` is not a console path: {err}"
                ))
            })?,
            None => Url::parse(&format!("{}/console/home", self.console)).expect("a valid URL"),
        };
        if let Some(region) = region
            && !url.query_pairs().any(|(key, _)| key == "region")
        {
            url.query_pairs_mut().append_pair("region", region.as_str());
        }
        Ok(url)
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn region(name: &str) -> Region {
        name.parse().unwrap()
    }

    #[test]
    fn picks_the_partition_from_a_region() {
        assert_eq!(
            Partition::of(&region("eu-west-1")).signin,
            "https://signin.aws.amazon.com/federation"
        );
        assert_eq!(
            Partition::of(&region("cn-north-1")).console,
            "https://console.amazonaws.cn"
        );
        assert_eq!(
            Partition::of(&region("us-gov-west-1")).signin,
            "https://signin.amazonaws-us-gov.com/federation"
        );
    }

    #[test]
    fn builds_the_destination() {
        let aws = Partition::of(&region("us-east-1"));
        let eu = region("eu-west-1");
        let page = |destination, region| aws.destination(destination, region).unwrap().to_string();
        assert_eq!(
            page(None, None),
            "https://console.aws.amazon.com/console/home"
        );
        assert_eq!(
            page(None, Some(&eu)),
            "https://console.aws.amazon.com/console/home?region=eu-west-1"
        );
        assert_eq!(
            page(Some("/s3/home"), Some(&eu)),
            "https://console.aws.amazon.com/s3/home?region=eu-west-1"
        );
        assert_eq!(
            page(
                Some("https://console.aws.amazon.com/ec2/home?region=us-east-2#Instances:"),
                Some(&eu)
            ),
            "https://console.aws.amazon.com/ec2/home?region=us-east-2#Instances:",
            "a page that names its region keeps it"
        );
        assert!(aws.destination(Some("https://"), None).is_err());
    }
}
