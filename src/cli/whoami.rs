//! `gac whoami`: the identity AWS tools use right now, and which rule picked it. It reads only
//! local files: no refresh, no portal call, no prompt, so it suits a shell prompt.

use std::fmt::Write as _;

use jiff::Timestamp;
use serde::Serialize;

use crate::auth::botocore_json::timestamp;
use crate::auth::role::EXPIRY_WINDOW;
use crate::cli::WhoamiArgs;
use crate::cli::context::Context;
use crate::cli::status::{self, TokenStatus};
use crate::cli::target::{self, RoleTarget, Source};
use crate::error::Result;
use crate::ui;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Whoami {
    /// The profile's name, `default` for `[default]`.
    profile: String,
    /// `--profile`, `AWS_PROFILE`, `AWS_DEFAULT_PROFILE` or `[default]`.
    source: &'static str,
    session: String,
    account_id: String,
    /// From the last listing, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    account_name: Option<String>,
    role_name: String,
    /// For a chained profile, the SSO role the chain starts from.
    #[serde(skip_serializing_if = "Option::is_none")]
    sso_role: Option<SsoRole>,
    /// The role ARNs then assumed in turn, the last one being `accountId`/`roleName`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    chain: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<String>,
    /// `AWS_REGION`, `AWS_DEFAULT_REGION` or `profile`.
    #[serde(skip_serializing_if = "Option::is_none")]
    region_source: Option<&'static str>,
    token: TokenStatus,
    credentials: CredentialsStatus,
    /// `AWS_ACCESS_KEY_ID` is set, so AWS tools use those keys and not this profile.
    environment_credentials: bool,
    /// The role a surrounding `gac exec` runs as.
    #[serde(skip_serializing_if = "Option::is_none")]
    exec_role: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SsoRole {
    account_id: String,
    role_name: String,
}

/// The role credentials in the AWS CLI's cache.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CredentialsStatus {
    /// `valid`, `expiring` (inside the refresh window), `expired` or `missing`.
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
}

pub async fn run(ctx: &Context, args: WhoamiArgs) -> Result<()> {
    let files = ctx.files().await?;
    let target = target::resolve(ctx, &files, args.profile.as_deref(), None).await?;
    let whoami = describe(ctx, &target, Timestamp::now());
    let text = if args.json {
        ui::json(&whoami)
    } else {
        render(&whoami, &target, Timestamp::now())
    };
    ui::output(text)
}

fn describe(ctx: &Context, target: &RoleTarget, now: Timestamp) -> Whoami {
    let account_name = ctx.cached_accounts(&target.session).and_then(|accounts| {
        accounts
            .into_iter()
            .find(|account| account.id == *target.final_account())
            .map(|account| account.name)
    });
    let (region, region_source) = match env_var("AWS_REGION")
        .map(|region| (region, "AWS_REGION"))
        .or_else(|| env_var("AWS_DEFAULT_REGION").map(|region| (region, "AWS_DEFAULT_REGION")))
    {
        Some((region, var)) => (Some(region), Some(var)),
        None => match &target.region {
            Some(region) => (Some(region.to_string()), Some("profile")),
            None => (None, None),
        },
    };
    let expiration = target.cached_expiration(ctx);
    let credentials = CredentialsStatus {
        state: match expiration {
            None => "missing",
            Some(at) if at <= now => "expired",
            Some(at) if at.duration_since(now) < EXPIRY_WINDOW => "expiring",
            Some(_) => "valid",
        },
        expires_at: expiration.map(timestamp::format),
    };
    Whoami {
        profile: target.profile.clone().unwrap_or_default(),
        source: target.source.as_str(),
        session: target
            .session
            .name()
            .map_or_else(|| target.session.label(), ToString::to_string),
        account_id: target.final_account().to_string(),
        account_name,
        role_name: target.final_role().to_string(),
        sso_role: (!target.chain.is_empty()).then(|| SsoRole {
            account_id: target.account.to_string(),
            role_name: target.role.to_string(),
        }),
        chain: target
            .chain
            .iter()
            .map(|step| step.role_arn.to_string())
            .collect(),
        region,
        region_source,
        token: status::token_status(&ctx.token_store(), &target.session, now),
        credentials,
        environment_credentials: env_var("AWS_ACCESS_KEY_ID").is_some(),
        exec_role: env_var("GAC_REDUX_EXEC"),
    }
}

fn render(whoami: &Whoami, target: &RoleTarget, now: Timestamp) -> String {
    let mut out = String::new();
    let mut line = |label: &str, value: String| {
        let _ = writeln!(out, "{label:<13}{value}");
    };
    line(
        "profile",
        match target.source {
            Source::Default => "[default] (no --profile or AWS_PROFILE)".to_owned(),
            source => format!("{} (from {})", whoami.profile, source.as_str()),
        },
    );
    line("session", whoami.session.clone());
    line(
        "account",
        match &whoami.account_name {
            Some(name) => format!("{} ({name})", whoami.account_id),
            None => whoami.account_id.clone(),
        },
    );
    line("role", whoami.role_name.clone());
    if let Some(sso) = &whoami.sso_role {
        let mut via = format!("{} in {} (SSO)", sso.role_name, sso.account_id);
        for arn in &whoami.chain[..whoami.chain.len() - 1] {
            let _ = write!(via, ", then {arn}");
        }
        line("assumed via", via);
    }
    line(
        "region",
        match (&whoami.region, whoami.region_source) {
            (Some(region), Some("profile") | None) => region.clone(),
            (Some(region), Some(var)) => format!("{region} (from {var})"),
            (None, _) => "not set".to_owned(),
        },
    );
    let mut token = status::describe_token(&whoami.token, now);
    if whoami.token.expires_at.is_none() {
        let _ = write!(token, "; run `gac login {}`", target.session.login_args());
    }
    line("token", token);
    let credentials = &whoami.credentials;
    line(
        "credentials",
        match (credentials.state, &credentials.expires_at) {
            ("valid", Some(at)) => {
                let left = timestamp::parse(at).map(|at| at.duration_since(now));
                match left {
                    Some(left) => format!("cached until {at} ({} left)", status::human(left)),
                    None => format!("cached until {at}"),
                }
            }
            ("expiring" | "expired", Some(at)) => {
                format!("cached until {at}; the next use fetches new ones")
            }
            _ => "none cached; the next use fetches them".to_owned(),
        },
    );
    if whoami.environment_credentials {
        let by = match &whoami.exec_role {
            Some(role) => format!(" by `gac exec` as {role}"),
            None => String::new(),
        };
        let _ = writeln!(
            out,
            "\nAWS_ACCESS_KEY_ID is set{by}: AWS tools use those keys, not this profile."
        );
    }
    out
}

fn env_var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}
