//! OIDC client registration, cached for its 90-day lifetime.
//!
//! The cache file sits beside the tokens, keyed the way botocore keys its own registrations but
//! with `"tool": "gac-redux"`, so gac never reads or clobbers the AWS CLI's entry. It holds no
//! `accessToken`, so `aws sso logout` leaves it alone, as it does botocore's.

use std::path::Path;

use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

use crate::auth::Session;
use crate::auth::botocore_json::{self, timestamp};
use crate::auth::oidc::{ClientCredentials, Oidc, RegisterRequest};
use crate::domain::SessionName;
use crate::error::Result;
use crate::fsx::{self, ModePolicy};
use crate::secret::{self, SecretString};

/// Reuse a registration until this long before it expires, as botocore does.
const EXPIRY_WINDOW: SignedDuration = SignedDuration::from_mins(15);

/// The scope that makes Identity Center issue a refresh token.
pub const DEFAULT_SCOPE: &str = "sso:account:access";

/// The redirect URI registered for PKCE. It has no port: the authorize and token calls add the
/// ephemeral loopback port, as RFC 8252 section 7.3 allows.
pub const REDIRECT_URI: &str = "http://127.0.0.1/oauth/callback";

/// Which OAuth grant a registration is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grant {
    AuthorizationCode,
    DeviceCode,
}

impl Grant {
    fn grant_types(self) -> &'static [&'static str] {
        match self {
            Self::AuthorizationCode => &["authorization_code", "refresh_token"],
            Self::DeviceCode => &[
                "urn:ietf:params:oauth:grant-type:device_code",
                "refresh_token",
            ],
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CachedRegistration {
    client_id: String,
    #[serde(with = "secret::serde_required")]
    client_secret: SecretString,
    #[serde(with = "timestamp")]
    expires_at: Timestamp,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    grant_types: Vec<String>,
}

/// The arguments hashed into the cache key, serialized like Python's
/// `json.dumps(args, sort_keys=True)`: fields are declared in sorted order.
#[derive(Serialize)]
struct KeyArgs<'a> {
    #[serde(rename = "grantTypes")]
    grant_types: &'a [&'a str],
    region: &'a str,
    scopes: &'a [String],
    session_name: Option<&'a str>,
    #[serde(rename = "startUrl")]
    start_url: &'a str,
    tool: &'a str,
}

/// The scopes to register for a session.
pub fn scopes_for(session: &Session) -> Vec<String> {
    if !session.scopes.is_empty() {
        session.scopes.clone()
    } else if session.is_legacy() {
        // Legacy profiles cannot refresh; botocore registers them without scopes.
        Vec::new()
    } else {
        vec![DEFAULT_SCOPE.to_owned()]
    }
}

pub fn cache_key(session: &Session, grant: Grant) -> String {
    let scopes = scopes_for(session);
    let args = KeyArgs {
        grant_types: grant.grant_types(),
        region: session.region.as_str(),
        scopes: &scopes,
        session_name: session.name().map(SessionName::as_str),
        start_url: session.start_url.as_str(),
        tool: "gac-redux",
    };
    hex::encode(Sha1::digest(botocore_json::to_string(&args).as_bytes()))
}

/// Returns a cached registration that fits, or registers a new client and caches it.
pub async fn obtain(
    oidc: &Oidc,
    dir: &Path,
    session: &Session,
    grant: Grant,
    now: Timestamp,
) -> Result<ClientCredentials> {
    let path = dir.join(format!("{}.json", cache_key(session, grant)));
    let cached = fsx::read_optional(&path)?
        .and_then(|bytes| serde_json::from_slice::<CachedRegistration>(&bytes).ok())
        .filter(|r| r.expires_at.duration_since(now) > EXPIRY_WINDOW);
    if let Some(cached) = cached {
        tracing::debug!(client_id = %cached.client_id, expires_at = %cached.expires_at, "reusing cached client registration");
        return Ok(ClientCredentials {
            client_id: cached.client_id,
            client_secret: cached.client_secret,
            expires_at: cached.expires_at,
        });
    }

    let scopes = scopes_for(session);
    let client_name = format!(
        "gac-redux-{}",
        session.name().map_or("legacy", |n| n.as_str())
    );
    let request = match grant {
        Grant::AuthorizationCode => RegisterRequest {
            client_name: &client_name,
            scopes: &scopes,
            grant_types: grant.grant_types(),
            redirect_uri: Some(REDIRECT_URI),
            issuer_url: Some(session.start_url.as_str()),
        },
        // Like botocore, the device registration leaves the grant types to the service default.
        Grant::DeviceCode => RegisterRequest {
            client_name: &client_name,
            scopes: &scopes,
            ..RegisterRequest::default()
        },
    };
    let registered = oidc.register(&request).await?;
    tracing::debug!(client_id = %registered.client_id, expires_at = %registered.expires_at, "registered a new OIDC client");

    let entry = CachedRegistration {
        client_id: registered.client_id.clone(),
        client_secret: registered.client_secret.clone(),
        expires_at: registered.expires_at,
        scopes,
        grant_types: grant
            .grant_types()
            .iter()
            .map(|g| (*g).to_owned())
            .collect(),
    };
    fsx::write_atomic(
        &path,
        botocore_json::to_string(&entry).as_bytes(),
        ModePolicy::Private,
    )?;
    Ok(registered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::SessionKind;

    fn session(kind: SessionKind) -> Session {
        Session {
            kind,
            start_url: "https://corp.awsapps.com/start".parse().unwrap(),
            region: "us-east-1".parse().unwrap(),
            scopes: Vec::new(),
        }
    }

    #[test]
    fn key_matches_python_sorted_json() {
        let named = session(SessionKind::Named("corp".parse().unwrap()));
        // python3 -c 'import json,hashlib; print(hashlib.sha1(json.dumps({"tool": "gac-redux",
        //   "startUrl": "https://corp.awsapps.com/start", "region": "us-east-1",
        //   "scopes": ["sso:account:access"], "session_name": "corp",
        //   "grantTypes": ["authorization_code", "refresh_token"]}, sort_keys=True).encode()).hexdigest())'
        let args = KeyArgs {
            grant_types: Grant::AuthorizationCode.grant_types(),
            region: "us-east-1",
            scopes: &["sso:account:access".to_owned()],
            session_name: Some("corp"),
            start_url: "https://corp.awsapps.com/start",
            tool: "gac-redux",
        };
        assert_eq!(
            botocore_json::to_string(&args),
            r#"{"grantTypes": ["authorization_code", "refresh_token"], "region": "us-east-1", "scopes": ["sso:account:access"], "session_name": "corp", "startUrl": "https://corp.awsapps.com/start", "tool": "gac-redux"}"#
        );
        assert_ne!(
            cache_key(&named, Grant::AuthorizationCode),
            cache_key(&named, Grant::DeviceCode),
            "each grant has its own registration"
        );
    }

    #[test]
    fn legacy_profiles_register_without_scopes() {
        let legacy = session(SessionKind::Legacy("old".into()));
        assert_eq!(scopes_for(&legacy), Vec::<String>::new());
        let named = session(SessionKind::Named("corp".parse().unwrap()));
        assert_eq!(scopes_for(&named), [DEFAULT_SCOPE]);
    }
}
