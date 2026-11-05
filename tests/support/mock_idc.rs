//! A mock IAM Identity Center: the OIDC API (`sso-oidc`), the portal API (`sso`) and an
//! auto-approving `/authorize` page. gac, the AWS CLI and aws-config are pointed at it with
//! `AWS_ENDPOINT_URL_SSO` and `AWS_ENDPOINT_URL_SSO_OIDC`.
//!
//! It behaves like the real service where interop depends on it: PKCE verification, port-less
//! redirect registration, refresh tokens only for the `sso:account:access` scope, refresh-token
//! rotation, server-side logout, pagination, throttling, and AWS-style error responses. Every
//! secret it issues starts with `FAKE-` and is recorded, so tests can prove none leaks.

#![allow(dead_code)] // each test binary uses a different part of the mock

use std::collections::{BTreeMap, HashMap, HashSet};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use sha2::Digest;

/// One account the mock serves: id, name and role names.
#[derive(Debug, Clone)]
pub struct MockAccount {
    pub id: String,
    pub name: String,
    pub roles: Vec<String>,
}

pub fn account(id: &str, name: &str, roles: &[&str]) -> MockAccount {
    MockAccount {
        id: id.into(),
        name: name.into(),
        roles: roles.iter().map(|r| (*r).to_owned()).collect(),
    }
}

/// The accounts used unless a test supplies its own.
pub fn default_accounts() -> Vec<MockAccount> {
    vec![
        account(
            "111122223333",
            "payments-prod",
            &["AdministratorAccess", "ReadOnly"],
        ),
        account("444455556666", "Shared Services", &["ReadOnly"]),
        account("777788889999", "sandbox", &["PowerUser", "ReadOnly"]),
    ]
}

#[derive(Debug)]
struct Client {
    secret: String,
    scopes: Vec<String>,
    grant_types: Vec<String>,
    redirect_uris: Vec<String>,
}

#[derive(Debug)]
struct State {
    accounts: Vec<MockAccount>,
    access_ttl: i64,
    pending_polls: u32,
    deny_authorize: bool,
    rate_limit: Option<u32>,
    window: (Instant, u32),
    clients: HashMap<String, Client>,
    device_codes: HashMap<String, (String, u32)>,
    auth_codes: HashMap<String, (String, String, String)>,
    access_tokens: HashSet<String>,
    refresh_tokens: HashMap<String, String>,
    counters: BTreeMap<String, u64>,
    secrets: Vec<String>,
    serial: u64,
}

impl State {
    fn count(&mut self, name: &str) {
        *self.counters.entry(name.to_owned()).or_default() += 1;
    }

    fn secret(&mut self, kind: &str) -> String {
        self.serial += 1;
        let value = format!("FAKE-{kind}-{:016x}{}", rand_u64(), self.serial);
        self.secrets.push(value.clone());
        value
    }
}

fn rand_u64() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    // Distinct per call; the tests need uniqueness, not unpredictability.
    let mut hasher = sha2::Sha256::new();
    hasher.update(nanos.to_le_bytes());
    hasher.update(std::process::id().to_le_bytes());
    u64::from_le_bytes(hasher.finalize()[..8].try_into().unwrap())
}

/// A running mock. It stops with the test process.
#[derive(Debug, Clone)]
pub struct MockIdc {
    pub url: String,
    state: Arc<Mutex<State>>,
}

impl MockIdc {
    pub fn start(accounts: Vec<MockAccount>) -> Self {
        let state = Arc::new(Mutex::new(State {
            accounts,
            access_ttl: 8 * 3600,
            pending_polls: 1,
            deny_authorize: false,
            rate_limit: None,
            window: (Instant::now(), 0),
            clients: HashMap::new(),
            device_codes: HashMap::new(),
            auth_codes: HashMap::new(),
            access_tokens: HashSet::new(),
            refresh_tokens: HashMap::new(),
            counters: BTreeMap::new(),
            secrets: Vec::new(),
            serial: 0,
        }));
        let (tx, rx) = std::sync::mpsc::channel();
        let shared = Arc::clone(&state);
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                    .await
                    .unwrap();
                tx.send(listener.local_addr().unwrap()).unwrap();
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        continue;
                    };
                    let state = Arc::clone(&shared);
                    tokio::spawn(async move {
                        let service = service_fn(move |req| {
                            let state = Arc::clone(&state);
                            async move { Ok::<_, Infallible>(handle(&state, req).await) }
                        });
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    });
                }
            });
        });
        let addr = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        Self {
            url: format!("http://{addr}"),
            state,
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        f(&mut self.state.lock().unwrap())
    }

    /// Seconds an issued access token lives.
    pub fn set_access_ttl(&self, seconds: i64) {
        self.with(|s| s.access_ttl = seconds);
    }

    /// How many device-code polls answer "pending" before approval.
    pub fn set_pending_polls(&self, polls: u32) {
        self.with(|s| s.pending_polls = polls);
    }

    /// Makes `/authorize` redirect with `error=access_denied`.
    pub fn deny_authorize(&self) {
        self.with(|s| s.deny_authorize = true);
    }

    /// Answers `TooManyRequestsException` beyond this many portal requests per second.
    pub fn set_rate_limit(&self, per_second: u32) {
        self.with(|s| s.rate_limit = Some(per_second));
    }

    pub fn set_accounts(&self, accounts: Vec<MockAccount>) {
        self.with(|s| s.accounts = accounts);
    }

    /// How often an event happened, e.g. `register`, `refresh`, `logout`, `accounts`.
    pub fn counter(&self, name: &str) -> u64 {
        self.with(|s| s.counters.get(name).copied().unwrap_or_default())
    }

    /// Every secret value the mock has issued.
    pub fn secrets(&self) -> Vec<String> {
        self.with(|s| s.secrets.clone())
    }

    /// Whether an access token is still accepted (not expired by logout).
    pub fn is_live(&self, access_token: &str) -> bool {
        self.with(|s| s.access_tokens.contains(access_token))
    }
}

type Reply = Response<Full<Bytes>>;

fn reply(status: StatusCode, body: &Value) -> Reply {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

fn error(status: StatusCode, code: &str, oauth_error: &str) -> Reply {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("x-amzn-errortype", code)
        .body(Full::new(Bytes::from(
            json!({"error": oauth_error, "error_description": code, "message": code}).to_string(),
        )))
        .unwrap()
}

fn now_secs() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

async fn handle(state: &Arc<Mutex<State>>, req: Request<Incoming>) -> Reply {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let query: HashMap<String, String> =
        url::form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes())
            .into_owned()
            .collect();
    let bearer = req
        .headers()
        .get("x-amz-sso_bearer_token")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = req
        .into_body()
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .unwrap_or_default();
    let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let mut s = state.lock().unwrap();

    match (method, path.as_str()) {
        (Method::POST, "/client/register") => register(&mut s, &body),
        (Method::POST, "/device_authorization") => device_authorization(&mut s, &body),
        (Method::POST, "/token") => token(&mut s, &body),
        (Method::GET, "/authorize") => authorize(&mut s, &query),
        (method, portal_path) => {
            if let Some(limit) = s.rate_limit {
                let (start, count) = s.window;
                if start.elapsed() >= Duration::from_secs(1) {
                    s.window = (Instant::now(), 1);
                } else if count >= limit {
                    s.count("throttled");
                    return error(
                        StatusCode::TOO_MANY_REQUESTS,
                        "TooManyRequestsException",
                        "throttled",
                    );
                } else {
                    s.window.1 += 1;
                }
            }
            if !bearer.as_ref().is_some_and(|t| s.access_tokens.contains(t)) {
                s.count("unauthorized");
                return error(
                    StatusCode::UNAUTHORIZED,
                    "UnauthorizedException",
                    "unauthorized",
                );
            }
            match (method, portal_path) {
                (Method::GET, "/assignment/accounts") => list_accounts(&mut s, &query),
                (Method::GET, "/assignment/roles") => list_roles(&mut s, &query),
                (Method::GET, "/federation/credentials") => role_credentials(&mut s, &query),
                (Method::POST, "/logout") => {
                    s.count("logout");
                    s.access_tokens
                        .remove(bearer.as_deref().unwrap_or_default());
                    Response::new(Full::new(Bytes::new()))
                }
                _ => error(
                    StatusCode::NOT_FOUND,
                    "ResourceNotFoundException",
                    "not_found",
                ),
            }
        }
    }
}

fn str_field<'a>(body: &'a Value, name: &str) -> &'a str {
    body.get(name).and_then(Value::as_str).unwrap_or_default()
}

fn str_list(body: &Value, name: &str) -> Vec<String> {
    body.get(name)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn register(s: &mut State, body: &Value) -> Reply {
    s.count("register");
    if str_field(body, "clientType") != "public" || str_field(body, "clientName").is_empty() {
        return error(
            StatusCode::BAD_REQUEST,
            "InvalidClientMetadataException",
            "invalid_client_metadata",
        );
    }
    let client_id = format!("mock-client-{}", s.clients.len() + 1);
    let secret = s.secret("CLIENT-SECRET");
    s.clients.insert(
        client_id.clone(),
        Client {
            secret: secret.clone(),
            scopes: str_list(body, "scopes"),
            grant_types: str_list(body, "grantTypes"),
            redirect_uris: str_list(body, "redirectUris"),
        },
    );
    reply(
        StatusCode::OK,
        &json!({
            "clientId": client_id,
            "clientSecret": secret,
            "clientIdIssuedAt": now_secs(),
            "clientSecretExpiresAt": now_secs() + 90 * 24 * 3600,
        }),
    )
}

fn authenticate<'a>(s: &'a State, body: &Value) -> Option<&'a Client> {
    s.clients
        .get(str_field(body, "clientId"))
        .filter(|c| c.secret == str_field(body, "clientSecret"))
}

fn device_authorization(s: &mut State, body: &Value) -> Reply {
    s.count("device_authorization");
    if authenticate(s, body).is_none() {
        return error(
            StatusCode::BAD_REQUEST,
            "InvalidClientException",
            "invalid_client",
        );
    }
    let device_code = s.secret("DEVICE-CODE");
    let polls = s.pending_polls;
    s.device_codes.insert(
        device_code.clone(),
        (str_field(body, "clientId").to_owned(), polls),
    );
    reply(
        StatusCode::OK,
        &json!({
            "deviceCode": device_code,
            "userCode": "MOCK-CODE",
            "verificationUri": "https://device.sso.mock.invalid/",
            "verificationUriComplete": "https://device.sso.mock.invalid/?user_code=MOCK-CODE",
            "expiresIn": 600,
            "interval": 1,
        }),
    )
}

fn authorize(s: &mut State, query: &HashMap<String, String>) -> Reply {
    s.count("authorize");
    let get = |k: &str| query.get(k).map(String::as_str).unwrap_or_default();
    let Some(client) = s.clients.get(get("client_id")) else {
        return error(
            StatusCode::BAD_REQUEST,
            "InvalidClientException",
            "invalid_client",
        );
    };
    if get("response_type") != "code"
        || get("code_challenge_method") != "S256"
        || get("code_challenge").is_empty()
    {
        return error(
            StatusCode::BAD_REQUEST,
            "InvalidRequestException",
            "invalid_request",
        );
    }
    if !client.grant_types.iter().any(|g| g == "authorization_code") {
        return error(
            StatusCode::BAD_REQUEST,
            "UnauthorizedClientException",
            "unauthorized_client",
        );
    }
    // RFC 8252 section 7.3: a loopback redirect matches its registration regardless of port.
    let redirect = get("redirect_uri");
    let Ok(mut portless) = url::Url::parse(redirect) else {
        return error(
            StatusCode::BAD_REQUEST,
            "InvalidRequestException",
            "invalid_redirect_uri",
        );
    };
    let _ = portless.set_port(None);
    if !client.redirect_uris.iter().any(|r| r == portless.as_str()) {
        return error(
            StatusCode::BAD_REQUEST,
            "InvalidRequestException",
            "invalid_redirect_uri",
        );
    }
    let mut location = url::Url::parse(redirect).unwrap();
    if s.deny_authorize {
        location
            .query_pairs_mut()
            .append_pair("error", "access_denied")
            .append_pair("error_description", "the user denied the request")
            .append_pair("state", get("state"));
    } else {
        let code = s.secret("AUTH-CODE");
        s.auth_codes.insert(
            code.clone(),
            (
                get("client_id").to_owned(),
                redirect.to_owned(),
                get("code_challenge").to_owned(),
            ),
        );
        location
            .query_pairs_mut()
            .append_pair("code", &code)
            .append_pair("state", get("state"));
    }
    Response::builder()
        .status(StatusCode::FOUND)
        .header("location", location.as_str())
        .body(Full::new(Bytes::new()))
        .unwrap()
}

fn token(s: &mut State, body: &Value) -> Reply {
    let Some(client) = authenticate(s, body) else {
        return error(
            StatusCode::BAD_REQUEST,
            "InvalidClientException",
            "invalid_client",
        );
    };
    let client_id = str_field(body, "clientId").to_owned();
    let refreshable = client
        .scopes
        .iter()
        .any(|scope| scope == "sso:account:access");
    match str_field(body, "grantType") {
        "urn:ietf:params:oauth:grant-type:device_code" => {
            let code = str_field(body, "deviceCode");
            match s.device_codes.get_mut(code) {
                Some((owner, _)) if *owner != client_id => error(
                    StatusCode::BAD_REQUEST,
                    "InvalidGrantException",
                    "invalid_grant",
                ),
                Some((_, pending)) if *pending > 0 => {
                    *pending -= 1;
                    error(
                        StatusCode::BAD_REQUEST,
                        "AuthorizationPendingException",
                        "authorization_pending",
                    )
                }
                Some(_) => {
                    s.device_codes.remove(code);
                    s.count("token_device");
                    issue(s, &client_id, refreshable)
                }
                None => error(
                    StatusCode::BAD_REQUEST,
                    "ExpiredTokenException",
                    "expired_token",
                ),
            }
        }
        "authorization_code" => {
            let Some((owner, redirect, challenge)) = s.auth_codes.remove(str_field(body, "code"))
            else {
                return error(
                    StatusCode::BAD_REQUEST,
                    "InvalidGrantException",
                    "invalid_grant",
                );
            };
            let verifier = str_field(body, "codeVerifier");
            let computed = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(sha2::Sha256::digest(verifier.as_bytes()));
            if owner != client_id
                || redirect != str_field(body, "redirectUri")
                || computed != challenge
            {
                return error(
                    StatusCode::BAD_REQUEST,
                    "InvalidGrantException",
                    "invalid_grant",
                );
            }
            s.count("token_code");
            issue(s, &client_id, refreshable)
        }
        "refresh_token" => {
            let presented = str_field(body, "refreshToken");
            match s.refresh_tokens.remove(presented) {
                Some(owner) if owner == client_id => {
                    s.count("refresh");
                    issue(s, &client_id, true)
                }
                _ => {
                    s.count("refresh_rejected");
                    error(
                        StatusCode::BAD_REQUEST,
                        "InvalidGrantException",
                        "invalid_grant",
                    )
                }
            }
        }
        _ => error(
            StatusCode::BAD_REQUEST,
            "UnsupportedGrantTypeException",
            "unsupported_grant_type",
        ),
    }
}

fn issue(s: &mut State, client_id: &str, refreshable: bool) -> Reply {
    let access = s.secret("ACCESS-TOKEN");
    s.access_tokens.insert(access.clone());
    let mut out = json!({
        "accessToken": access,
        "tokenType": "Bearer",
        "expiresIn": s.access_ttl,
    });
    if refreshable {
        let refresh = s.secret("REFRESH-TOKEN");
        s.refresh_tokens
            .insert(refresh.clone(), client_id.to_owned());
        out["refreshToken"] = json!(refresh);
    }
    reply(StatusCode::OK, &out)
}

fn page<T: Clone>(items: &[T], query: &HashMap<String, String>) -> (Vec<T>, Option<String>) {
    let size = query
        .get("max_result")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(100)
        .clamp(1, 100);
    let start = query
        .get("next_token")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let end = (start + size).min(items.len());
    let next = (end < items.len()).then(|| end.to_string());
    (items.get(start..end).unwrap_or_default().to_vec(), next)
}

fn list_accounts(s: &mut State, query: &HashMap<String, String>) -> Reply {
    s.count("accounts");
    let listed: Vec<Value> = s
        .accounts
        .iter()
        .map(|a| json!({"accountId": a.id, "accountName": a.name, "emailAddress": format!("{}@example.invalid", a.id)}))
        .collect();
    let (items, next) = page(&listed, query);
    reply(
        StatusCode::OK,
        &json!({"accountList": items, "nextToken": next}),
    )
}

fn list_roles(s: &mut State, query: &HashMap<String, String>) -> Reply {
    s.count("roles");
    let id = query.get("account_id").cloned().unwrap_or_default();
    let Some(account) = s.accounts.iter().find(|a| a.id == id) else {
        return error(
            StatusCode::NOT_FOUND,
            "ResourceNotFoundException",
            "not_found",
        );
    };
    let listed: Vec<Value> = account
        .roles
        .iter()
        .map(|r| json!({"roleName": r, "accountId": id}))
        .collect();
    let (items, next) = page(&listed, query);
    reply(
        StatusCode::OK,
        &json!({"roleList": items, "nextToken": next}),
    )
}

fn role_credentials(s: &mut State, query: &HashMap<String, String>) -> Reply {
    s.count("credentials");
    let id = query.get("account_id").cloned().unwrap_or_default();
    let role = query.get("role_name").cloned().unwrap_or_default();
    if !s
        .accounts
        .iter()
        .any(|a| a.id == id && a.roles.contains(&role))
    {
        return error(StatusCode::FORBIDDEN, "ForbiddenException", "forbidden");
    }
    let secret_key = s.secret("SECRET-ACCESS-KEY");
    let session_token = s.secret("SESSION-TOKEN");
    let expiration = (now_secs() + 3600) * 1000;
    reply(
        StatusCode::OK,
        &json!({"roleCredentials": {
            "accessKeyId": format!("ASIAMOCK{}", &id[..8]),
            "secretAccessKey": secret_key,
            "sessionToken": session_token,
            "expiration": expiration,
        }}),
    )
}
