//! The IAM Identity Center portal API (`sso`): accounts, roles and logout.

use std::sync::Arc;

use aws_sdk_sso::Client;
use aws_sdk_sso::error::{ProvideErrorMetadata, SdkError};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::auth::Session;
use crate::domain::{AccountId, RoleName};
use crate::error::{self, Error, Result};
use crate::secret::{ExposeSecret, SecretString};

/// Concurrent `ListAccountRoles` calls during a full listing. With adaptive retry, 4-8 stayed
/// robust under throttling; more only queues behind the client-side rate limiter.
const FAN_OUT: usize = 8;

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
        Self {
            client: Client::new(&crate::sdk::load(&session.region).await),
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
