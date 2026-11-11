//! The IAM Identity Center portal API (`sso`): accounts, roles, role credentials and logout.

use std::sync::Arc;
use std::time::Duration;

use aws_sdk_sso::Client;
use aws_sdk_sso::config::retry::{RetryConfig, RetryPartition, TokenBucket};
use aws_sdk_sso::error::{ProvideErrorMetadata, SdkError};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::auth::Session;
use crate::auth::role::RoleCredentials;
use crate::domain::{AccountId, RoleName};
use crate::error::{self, Error, Result};
use crate::secret::{ExposeSecret, SecretString};

/// Concurrent `ListAccountRoles` calls during a full listing. With adaptive retry, 4-8 stayed
/// robust under throttling; more only queues behind the client-side rate limiter.
const FAN_OUT: usize = 8;

/// Attempts per portal call. At one request a second against the fan-out, 10 attempts left some
/// `ListAccountRoles` calls out of retries, which failed the whole listing; 20 finished it.
const MAX_ATTEMPTS: u32 = 20;

/// The longest wait before a retry. Adaptive retry's client-side rate limiter can ask for many
/// seconds after a throttle, and the SDK's 20 s cap stalled every throttled listing by about 20 s.
/// 1 s keeps a listing close to the rate the portal allows; 2 s was as fast under moderate
/// throttling and slower, with several times the throttled requests, under heavy throttling.
const MAX_BACKOFF: Duration = Duration::from_secs(1);

/// One account and the roles the user has in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    #[serde(rename = "accountId")]
    pub id: AccountId,
    #[serde(rename = "accountName")]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub roles: Vec<RoleName>,
}

#[derive(Debug, Clone)]
pub struct Portal {
    client: Client,
    session: Session,
}

impl Portal {
    pub async fn new(session: &Session) -> Self {
        let sdk = crate::sdk::load(&session.region).await;
        Self {
            client: Client::from_conf(client_config(&sdk).build()),
            session: session.clone(),
        }
    }

    /// Every account with its roles, sorted by account name and then id.
    pub async fn accounts_with_roles(&self, token: &SecretString) -> Result<Vec<Account>> {
        let mut accounts = self.accounts(token).await?;
        let token = Arc::new(token.clone());
        let permits = Arc::new(Semaphore::new(FAN_OUT));
        let mut tasks = JoinSet::new();
        for (index, account) in accounts.iter().enumerate() {
            let client = self.client.clone();
            let token = Arc::clone(&token);
            let permits = Arc::clone(&permits);
            let account_id = account.id.clone();
            tasks.spawn(async move {
                let _permit = permits
                    .acquire_owned()
                    .await
                    .expect("the semaphore is never closed");
                (index, list_roles(&client, &token, &account_id).await)
            });
        }
        while let Some(joined) = tasks.join_next().await {
            let (index, roles) = joined.expect("listing tasks do not panic");
            accounts[index].roles = roles.map_err(|err| self.convert("ListAccountRoles", &err))?;
        }
        tracing::debug!(accounts = accounts.len(), "listed accounts and roles");
        Ok(accounts)
    }

    async fn accounts(&self, token: &SecretString) -> Result<Vec<Account>> {
        let listed: Vec<_> = self
            .client
            .list_accounts()
            .access_token(token.expose_secret())
            .max_results(100)
            .into_paginator()
            .items()
            .send()
            .collect::<std::result::Result<_, _>>()
            .await
            .map_err(|err| self.convert("ListAccounts", &err))?;
        let mut accounts = listed
            .into_iter()
            .filter_map(|info| {
                let id = info.account_id()?;
                let Ok(account_id) = id.parse::<AccountId>() else {
                    tracing::warn!("skipping account with an unexpected id `{id}`");
                    return None;
                };
                Some(Account {
                    name: info.account_name().unwrap_or(id).to_owned(),
                    id: account_id,
                    email: info.email_address().map(str::to_owned),
                    roles: Vec::new(),
                })
            })
            .collect::<Vec<_>>();
        accounts.sort_by(|a, b| {
            a.name
                .to_lowercase()
                .cmp(&b.name.to_lowercase())
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(accounts)
    }

    /// `GetRoleCredentials`: short-lived credentials for one account and role.
    pub async fn role_credentials(
        &self,
        token: &SecretString,
        account: &AccountId,
        role: &RoleName,
    ) -> Result<RoleCredentials> {
        let output = self
            .client
            .get_role_credentials()
            .access_token(token.expose_secret())
            .account_id(account.as_str())
            .role_name(role.as_str())
            .send()
            .await
            .map_err(|err| match err.code() {
                Some("ForbiddenException" | "ResourceNotFoundException") => {
                    Error::config(format!("you have no role {role} in account {account}"))
                        .with_hint("run `gac list` to see the accounts and roles you can use")
                }
                _ => self.convert("GetRoleCredentials", &err),
            })?;
        let missing = || Error::Service {
            operation: "GetRoleCredentials",
            message: "the response has no complete credentials".into(),
        };
        let creds = output.role_credentials().ok_or_else(missing)?;
        let (Some(access_key_id), Some(secret_access_key), Some(session_token)) = (
            creds.access_key_id(),
            creds.secret_access_key(),
            creds.session_token(),
        ) else {
            return Err(missing());
        };
        let expiration = Timestamp::from_millisecond(creds.expiration()).map_err(|_| missing())?;
        Ok(RoleCredentials {
            access_key_id: access_key_id.to_owned(),
            secret_access_key: SecretString::from(secret_access_key.to_owned()),
            session_token: SecretString::from(session_token.to_owned()),
            expiration,
        })
    }

    /// `sso:Logout`: revokes the token server-side.
    pub async fn logout(&self, token: &SecretString) -> Result<()> {
        self.client
            .logout()
            .access_token(token.expose_secret())
            .send()
            .await
            .map_err(|err| self.convert("Logout", &err))?;
        Ok(())
    }

    /// A rejected token means the session needs a login; anything else is a service error.
    fn convert<E, R>(&self, operation: &'static str, err: &SdkError<E, R>) -> Error
    where
        E: ProvideErrorMetadata + std::error::Error + 'static,
        R: std::fmt::Debug,
    {
        if err.code() == Some("UnauthorizedException") {
            self.session
                .login_required("the portal rejected the SSO token (expired or revoked)")
        } else {
            error::service(operation, err)
        }
    }
}

type RolesError = SdkError<
    aws_sdk_sso::operation::list_account_roles::ListAccountRolesError,
    aws_sdk_sso::config::http::HttpResponse,
>;

/// Portal client settings: adaptive retry tuned for a throttled fan-out, in its own retry
/// partition where a throttled retry costs nothing. The SDK's shared retry budget (500 tokens, 5
/// per retry) otherwise stops all retries after about 100 throttles in one process, so a large
/// listing under sustained throttling failed however many attempts each call had. Adaptive retry
/// already paces throttled calls, and other errors still draw on the budget, so an outage does not
/// turn into a retry storm.
fn client_config(sdk: &aws_config::SdkConfig) -> aws_sdk_sso::config::Builder {
    let partition = RetryPartition::custom("gac-portal")
        .token_bucket(TokenBucket::builder().throttling_retry_cost(0).build())
        .build();
    aws_sdk_sso::config::Builder::from(sdk)
        .retry_config(
            RetryConfig::adaptive()
                .with_max_attempts(MAX_ATTEMPTS)
                .with_max_backoff(MAX_BACKOFF),
        )
        .retry_partition(partition)
}

async fn list_roles(
    client: &Client,
    token: &SecretString,
    account_id: &AccountId,
) -> std::result::Result<Vec<RoleName>, Box<RolesError>> {
    let listed: Vec<_> = client
        .list_account_roles()
        .access_token(token.expose_secret())
        .account_id(account_id.as_str())
        .max_results(100)
        .into_paginator()
        .items()
        .send()
        .collect::<std::result::Result<_, _>>()
        .await
        .map_err(Box::new)?;
    let mut roles: Vec<RoleName> = listed
        .iter()
        .filter_map(|role| role.role_name()?.parse().ok())
        .collect();
    roles.sort();
    Ok(roles)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use aws_config::{BehaviorVersion, Region, SdkConfig};
    use aws_sdk_sso::config::http::{HttpRequest, HttpResponse};
    use aws_smithy_async::test_util::instant_time_and_sleep;
    use aws_smithy_runtime_api::client::http::{
        HttpConnector, HttpConnectorFuture, SharedHttpConnector, http_client_fn,
    };
    use aws_smithy_runtime_api::http::StatusCode;
    use aws_smithy_types::body::SdkBody;

    use super::*;

    /// A portal that throttles every call six times before answering it.
    #[derive(Debug, Clone)]
    struct ThrottlingPortal(Arc<AtomicU32>);

    impl HttpConnector for ThrottlingPortal {
        fn call(&self, _request: HttpRequest) -> HttpConnectorFuture {
            let throttled = self.0.fetch_add(1, Ordering::SeqCst) % 7 < 6;
            let (status, body) = if throttled {
                (429, r#"{"message":"throttled"}"#)
            } else {
                (
                    200,
                    r#"{"roleList":[{"roleName":"Admin","accountId":"111122223333"}]}"#,
                )
            };
            let mut response =
                HttpResponse::new(StatusCode::try_from(status).unwrap(), SdkBody::from(body));
            if throttled {
                response
                    .headers_mut()
                    .insert("x-amzn-errortype", "TooManyRequestsException");
            }
            HttpConnectorFuture::ready(Ok(response))
        }
    }

    /// 30 calls throttled 6 times each make 180 throttled retries, beyond the roughly 100 the SDK's
    /// shared retry budget allows a process. A manual clock makes backoff and pacing instant.
    #[tokio::test]
    async fn sustained_throttling_does_not_exhaust_retries() {
        let requests = Arc::new(AtomicU32::new(0));
        let portal = ThrottlingPortal(Arc::clone(&requests));
        let (time, sleep) = instant_time_and_sleep(std::time::UNIX_EPOCH);
        let sdk = SdkConfig::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .http_client(http_client_fn(move |_, _| {
                SharedHttpConnector::new(portal.clone())
            }))
            .time_source(time)
            .sleep_impl(sleep)
            .build();
        let client = Client::from_conf(client_config(&sdk).build());
        let token = SecretString::from("token".to_owned());
        let account: AccountId = "111122223333".parse().unwrap();
        for call in 0..30 {
            let roles = list_roles(&client, &token, &account)
                .await
                .unwrap_or_else(|err| panic!("call {call} failed: {err:?}"));
            assert_eq!(roles, ["Admin".parse::<RoleName>().unwrap()]);
        }
        assert_eq!(requests.load(Ordering::SeqCst), 30 * 7);
    }
}
