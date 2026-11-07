//! `gac credential-process`: a role's credentials in the JSON that `credential_process` expects.
//! The AWS CLI and SDKs run it for the profiles `gac sync --mode process` writes, so it never
//! prompts, and it answers from the role cache while the credentials last.

use serde::Serialize;

use crate::auth::role::{self, RoleCache};
use crate::auth::{self, Session};
use crate::cli::CredentialProcessArgs;
use crate::cli::context::Context;
use crate::domain::{AccountId, RoleName};
use crate::error::{Error, Result};
use crate::secret::ExposeSecret;
use crate::ui;

/// The output `credential_process` reads.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct Output<'a> {
    version: u8,
    access_key_id: &'a str,
    secret_access_key: &'a str,
    session_token: &'a str,
    expiration: String,
}

pub async fn run(ctx: &Context, args: CredentialProcessArgs) -> Result<()> {
    let Some(name) = ctx.typed_session() else {
        return Err(Error::usage("gac credential-process needs --session NAME")
            .with_hint("pass --session, --account-id and --role-name, as `gac sync --mode process` writes them"));
    };
    let account: AccountId = args.account_id.parse()?;
    let role: RoleName = args.role_name.parse()?;
    let files = ctx.files().await?;
    let session = Session::from(files.sso_session(name)?);
    // The AWS CLI and SDKs run this unattended, so a missing login is an error, never a prompt.
    let creds = role::credentials(
        &RoleCache::new(ctx.paths.cli_cache_dir()),
        &session,
        &account,
        &role,
        async || auth::usable_token(&ctx.token_store(), &session).await,
    )
    .await?;
    let output = Output {
        version: 1,
        access_key_id: &creds.access_key_id,
        secret_access_key: creds.secret_access_key.expose_secret(),
        session_token: creds.session_token.expose_secret(),
        expiration: creds.expiration.strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
    };
    let mut json = serde_json::to_string(&output).expect("serializing plain data cannot fail");
    json.push('\n');
    ui::output(json).map_err(|err| Error::io("could not write to stdout", err))
}
