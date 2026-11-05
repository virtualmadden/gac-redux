//! The IAM Identity Center OIDC API (`sso-oidc`), wrapped in the few calls gac makes.

use std::sync::{Arc, Mutex};

use aws_sdk_ssooidc::Client;
use aws_sdk_ssooidc::config::interceptors::BeforeTransmitInterceptorContextRef;
use aws_sdk_ssooidc::config::{ConfigBag, Intercept, RuntimeComponents};
use aws_sdk_ssooidc::error::BoxError;
use jiff::{SignedDuration, Timestamp};

use crate::domain::Region;
use crate::error::{self, Error, Result};
use crate::oauth::device_poll::Poll;
use crate::secret::{ExposeSecret, SecretString};

/// What a successful `CreateToken` returns.
#[derive(Debug)]
pub struct TokenGrant {
    pub access_token: SecretString,
    pub expires_in: SignedDuration,
    pub refresh_token: Option<SecretString>,
}

/// A `RegisterClient` result.
#[derive(Debug)]
pub struct ClientCredentials {
    pub client_id: String,
    pub client_secret: SecretString,
    pub expires_at: Timestamp,
}

/// Optional `RegisterClient` parameters for the authorization-code grant.
#[derive(Debug, Default)]
pub struct RegisterRequest<'a> {
    pub client_name: &'a str,
    pub scopes: &'a [String],
    pub grant_types: &'a [&'a str],
    pub redirect_uri: Option<&'a str>,
    pub issuer_url: Option<&'a str>,
}

/// A `StartDeviceAuthorization` result.
#[derive(Debug)]
pub struct DeviceAuthorization {
    pub device_code: SecretString,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: SignedDuration,
    pub interval: SignedDuration,
}

#[derive(Debug, Clone)]
pub struct Oidc {
    client: Client,
}

impl Oidc {
    pub async fn new(region: &Region) -> Self {
        Self {
            client: Client::new(&crate::sdk::load(region).await),
        }
    }

    pub async fn register(&self, request: &RegisterRequest<'_>) -> Result<ClientCredentials> {
        let mut call = self
            .client
            .register_client()
            .client_name(request.client_name)
            .client_type("public");
        for scope in request.scopes {
            call = call.scopes(scope);
        }
        for grant in request.grant_types {
            call = call.grant_types(*grant);
        }
        if let Some(uri) = request.redirect_uri {
            call = call.redirect_uris(uri);
        }
        if let Some(issuer) = request.issuer_url {
            call = call.issuer_url(issuer);
        }
        let out = call
            .send()
            .await
            .map_err(|err| error::service("RegisterClient", &err))?;
        let missing = || Error::Service {
            operation: "RegisterClient",
            message: "the response has no client credentials".into(),
        };
        Ok(ClientCredentials {
            client_id: out.client_id().ok_or_else(missing)?.to_owned(),
            client_secret: out.client_secret().ok_or_else(missing)?.into(),
            expires_at: Timestamp::from_second(out.client_secret_expires_at()).map_err(|_| {
                Error::Service {
                    operation: "RegisterClient",
                    message: "the response has an invalid clientSecretExpiresAt".into(),
                }
            })?,
        })
    }

    pub async fn start_device_authorization(
        &self,
        client: &ClientCredentials,
        start_url: &str,
    ) -> Result<DeviceAuthorization> {
        let out = self
            .client
            .start_device_authorization()
            .client_id(&client.client_id)
            .client_secret(client.client_secret.expose_secret())
            .start_url(start_url)
            .send()
            .await
            .map_err(|err| error::service("StartDeviceAuthorization", &err))?;
        let missing = |field: &str| Error::Service {
            operation: "StartDeviceAuthorization",
            message: format!("the response has no {field}"),
        };
        Ok(DeviceAuthorization {
            device_code: out
                .device_code()
                .ok_or_else(|| missing("deviceCode"))?
                .into(),
            user_code: out
                .user_code()
                .ok_or_else(|| missing("userCode"))?
                .to_owned(),
            verification_uri: out
                .verification_uri()
                .ok_or_else(|| missing("verificationUri"))?
                .to_owned(),
            verification_uri_complete: out.verification_uri_complete().map(str::to_owned),
            expires_in: SignedDuration::from_secs(i64::from(out.expires_in())),
            interval: SignedDuration::from_secs(i64::from(out.interval())),
        })
    }

    /// One device-code `CreateToken` attempt, classified for RFC 8628 polling.
    pub async fn poll_device_token(
        &self,
        client: &ClientCredentials,
        device_code: &SecretString,
    ) -> Result<Poll<TokenGrant>> {
        let result = self
            .client
            .create_token()
            .grant_type("urn:ietf:params:oauth:grant-type:device_code")
            .client_id(&client.client_id)
            .client_secret(client.client_secret.expose_secret())
            .device_code(device_code.expose_secret())
            .send()
            .await;
        match result {
            Ok(out) => grant(&out).map(Poll::Ready),
            Err(err) => match err.as_service_error() {
                Some(e) if e.is_authorization_pending_exception() => Ok(Poll::Pending),
                Some(e) if e.is_slow_down_exception() => Ok(Poll::SlowDown),
                Some(e) if e.is_expired_token_exception() => Ok(Poll::Expired),
                Some(e) if e.is_access_denied_exception() => {
                    Err(Error::login("the sign-in request was denied"))
                }
                _ => Err(error::service("CreateToken", &err)),
            },
        }
    }

    pub async fn exchange_code(
        &self,
        client: &ClientCredentials,
        code: &SecretString,
        redirect_uri: &str,
        verifier: &SecretString,
    ) -> Result<TokenGrant> {
        let out = self
            .client
            .create_token()
            .grant_type("authorization_code")
            .client_id(&client.client_id)
            .client_secret(client.client_secret.expose_secret())
            .code(code.expose_secret())
            .redirect_uri(redirect_uri)
            .code_verifier(verifier.expose_secret())
            .send()
            .await
            .map_err(|err| error::service("CreateToken", &err))?;
        grant(&out)
    }

    pub async fn refresh(
        &self,
        client_id: &str,
        client_secret: &SecretString,
        refresh_token: &SecretString,
    ) -> Result<TokenGrant> {
        let out = self
            .client
            .create_token()
            .grant_type("refresh_token")
            .client_id(client_id)
            .client_secret(client_secret.expose_secret())
            .refresh_token(refresh_token.expose_secret())
            .send()
            .await
            .map_err(|err| error::service("CreateToken", &err))?;
        grant(&out)
    }

    /// The scheme and authority the SDK resolves for this client, for the un-modeled
    /// `/authorize` endpoint. Like botocore, it runs a request through the SDK's own endpoint
    /// resolution and stops it before anything is sent, so FIPS, dual-stack and
    /// `AWS_ENDPOINT_URL_SSO_OIDC` apply exactly as they do to the modeled calls.
    pub async fn authorize_base_url(&self) -> Result<String> {
        let capture = CaptureEndpoint::default();
        let _ = self
            .client
            .register_client()
            .client_name("endpoint-probe")
            .client_type("public")
            .customize()
            .interceptor(capture.clone())
            .send()
            .await;
        let uri = capture
            .0
            .lock()
            .expect("the capture lock is never poisoned")
            .take()
            .ok_or_else(|| Error::Service {
                operation: "endpoint resolution",
                message: "could not resolve the sso-oidc endpoint".into(),
            })?;
        let url = url::Url::parse(&uri).map_err(|err| Error::Service {
            operation: "endpoint resolution",
            message: format!("the sso-oidc endpoint `{uri}` is not a URL: {err}"),
        })?;
        Ok(url.origin().ascii_serialization())
    }
}

fn grant(out: &aws_sdk_ssooidc::operation::create_token::CreateTokenOutput) -> Result<TokenGrant> {
    let access_token = out.access_token().ok_or_else(|| Error::Service {
        operation: "CreateToken",
        message: "the response has no accessToken".into(),
    })?;
    Ok(TokenGrant {
        access_token: access_token.into(),
        expires_in: SignedDuration::from_secs(i64::from(out.expires_in())),
        refresh_token: out.refresh_token().map(SecretString::from),
    })
}

/// Records the request URI after endpoint resolution, then aborts the request.
#[derive(Debug, Clone, Default)]
struct CaptureEndpoint(Arc<Mutex<Option<String>>>);

impl Intercept for CaptureEndpoint {
    fn name(&self) -> &'static str {
        "CaptureEndpoint"
    }

    fn read_before_transmit(
        &self,
        context: &BeforeTransmitInterceptorContextRef<'_>,
        _components: &RuntimeComponents,
        _cfg: &mut ConfigBag,
    ) -> std::result::Result<(), BoxError> {
        *self.0.lock().expect("the capture lock is never poisoned") =
            Some(context.request().uri().to_owned());
        Err("endpoint captured; the request is intentionally not sent".into())
    }
}
