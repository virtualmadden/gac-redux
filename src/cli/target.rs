//! Which account and role a command acts on: the rows `gac list` shows, an `ACCOUNT/ROLE` picked
//! from them, or a profile's `sso_account_id` and `sso_role_name`.

use crate::auth::Session;
use crate::auth::role::{self, RoleCache, RoleCredentials};
use crate::aws_files::AwsFiles;
use crate::cli::context::{self, Context};
use crate::domain::{AccountId, Region, RoleName, SessionName};
use crate::error::{Error, Result};
use crate::portal::Account;
use crate::profiles;
use crate::ui;

/// One account and role a session can use.
#[derive(Debug, Clone)]
pub struct Row {
    pub session: SessionName,
    pub account: Account,
    pub role: RoleName,
}

impl Row {
    pub fn label(&self) -> String {
        format!("{}/{}", self.account.name, self.role)
    }
}

/// The account and role a command gets credentials for.
#[derive(Debug, Clone)]
pub struct RoleTarget {
    pub session: Session,
    pub account: AccountId,
    pub role: RoleName,
    /// The profile's `region`, if a profile named the role and set one.
    pub region: Option<Region>,
    /// How to name it to the user: `payments-prod/ReadOnly`, or `profile dev`.
    pub label: String,
}

impl RoleTarget {
    /// The role's credentials, from the AWS CLI's role cache while they last.
    pub async fn credentials(&self, ctx: &Context) -> Result<RoleCredentials> {
        role::credentials(
            &ctx.token_store(),
            &RoleCache::new(ctx.paths.cli_cache_dir()),
            &self.session,
            &self.account,
            &self.role,
        )
        .await
    }
}

/// The role `target` (`ACCOUNT/ROLE`) names, or else that of `profile`, of `AWS_PROFILE`
/// (`AWS_DEFAULT_PROFILE`), or of `[default]`, as the SDKs would pick the profile.
pub async fn resolve(
    ctx: &Context,
    files: &AwsFiles,
    profile: Option<&str>,
    target: Option<&str>,
) -> Result<RoleTarget> {
    if let Some(target) = target {
        let row = find(&rows(ctx, files).await?, target)?;
        return Ok(RoleTarget {
            session: files.sso_session(&row.session)?.into(),
            label: row.label(),
            account: row.account.id,
            role: row.role,
            region: None,
        });
    }
    if ctx.typed_session().is_some() {
        return Err(
            Error::usage("--session picks where ACCOUNT/ROLE is looked up")
                .with_hint("pass ACCOUNT/ROLE as well, or --profile NAME without --session"),
        );
    }
    let (name, from) = match profile {
        Some(name) => (name.to_owned(), "--profile"),
        None => match profile_from_env() {
            Some((name, var)) => (name, var),
            None => ("default".to_owned(), "default"),
        },
    };
    let pick_hint = "run `gac select` to pick one, or pass --profile NAME or ACCOUNT/ROLE";
    let Some(section) = files.config_profile(&name) else {
        return Err(if from == "default" {
            Error::config("there is no [default] profile to take the account and role from")
                .with_hint(pick_hint)
        } else {
            Error::config(format!(
                "no profile `{name}` in the AWS config file (from {from})"
            ))
        });
    };
    let session = context::session_of_profile(files, &name)?;
    let label = if name == "default" {
        "the [default] profile".to_owned()
    } else {
        format!("profile `{name}`")
    };
    let (Some(account), Some(role)) = (section.get("sso_account_id"), section.get("sso_role_name"))
    else {
        let err = Error::config(format!("{label} names no sso_account_id and sso_role_name"));
        return Err(if name == "default" {
            err.with_hint(pick_hint)
        } else {
            err
        });
    };
    Ok(RoleTarget {
        session,
        account: account.parse()?,
        role: role.parse()?,
        region: section.get("region").map(str::parse).transpose()?,
        label,
    })
}

/// The profile the environment names, and the variable that named it.
fn profile_from_env() -> Option<(String, &'static str)> {
    ["AWS_PROFILE", "AWS_DEFAULT_PROFILE"]
        .into_iter()
        .find_map(|var| Some((std::env::var(var).ok().filter(|v| !v.is_empty())?, var)))
}

/// Every account and role of `--session`, or of every session. Sessions that need a login are
/// skipped with a warning while others can still be listed.
pub async fn rows(ctx: &Context, files: &AwsFiles) -> Result<Vec<Row>> {
    let names: Vec<SessionName> = match ctx.typed_session() {
        Some(name) => vec![name.clone()],
        None => files
            .session_names()
            .into_iter()
            .map(str::parse)
            .collect::<Result<_>>()?,
    };
    if names.is_empty() {
        return Err(
            Error::config("no [sso-session] is configured in the AWS config file")
                .with_hint("run `gac setup`"),
        );
    }
    let mut rows = Vec::new();
    let mut needs_login = None;
    for name in &names {
        let session = Session::from(files.sso_session(name)?);
        match ctx.accounts(&session, false).await {
            Ok(snapshot) => {
                for account in snapshot.items {
                    for role in &account.roles {
                        rows.push(Row {
                            session: name.clone(),
                            account: account.clone(),
                            role: role.clone(),
                        });
                    }
                }
            }
            Err(err @ Error::LoginRequired { .. }) if names.len() > 1 => {
                ui::warn(format!(
                    "skipping session `{name}`: {err} (run `gac login --session {name}`)"
                ));
                needs_login = Some(err);
            }
            Err(err) => return Err(err),
        }
    }
    if rows.is_empty() {
        return Err(needs_login.unwrap_or_else(|| {
            Error::config("no accounts or roles are assigned to you in IAM Identity Center")
        }));
    }
    Ok(rows)
}

/// The row `ACCOUNT/ROLE` names, where ACCOUNT is the account name, its profile-name slug or its
/// id, ignoring case.
pub fn find(rows: &[Row], target: &str) -> Result<Row> {
    let wanted = target.to_lowercase();
    let matches: Vec<&Row> = rows
        .iter()
        .filter(|row| {
            let role = row.role.as_str();
            [
                row.account.name.clone(),
                profiles::account_slug(&row.account),
                row.account.id.to_string(),
            ]
            .iter()
            .any(|account| format!("{account}/{role}").to_lowercase() == wanted)
        })
        .collect();
    match matches.as_slice() {
        [only] => Ok((*only).clone()),
        [] => Err(
            Error::usage(format!("no account and role match `{target}`"))
                .with_hint("run `gac list` to see them, and pass ACCOUNT/ROLE"),
        ),
        many => Err(Error::usage(format!(
            "`{target}` matches in more than one session: {}",
            many.iter()
                .map(|row| row.session.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))
        .with_hint("pass --session NAME as well")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(session: &str, id: &str, name: &str, role: &str) -> Row {
        Row {
            session: session.parse().unwrap(),
            account: Account {
                id: id.parse().unwrap(),
                name: name.into(),
                email: None,
                roles: Vec::new(),
            },
            role: role.parse().unwrap(),
        }
    }

    #[test]
    fn finds_a_target_by_name_slug_or_id() {
        let rows = [
            row("corp", "111122223333", "Payments Prod", "ReadOnly"),
            row("corp", "111122223333", "Payments Prod", "Admin"),
            row("other", "444455556666", "Payments Prod", "ReadOnly"),
        ];
        assert_eq!(
            find(&rows, "payments-prod/admin").unwrap().role.as_str(),
            "Admin"
        );
        assert_eq!(
            find(&rows, "444455556666/ReadOnly")
                .unwrap()
                .session
                .as_str(),
            "other"
        );
        let ambiguous = find(&rows, "Payments Prod/ReadOnly").unwrap_err();
        assert!(ambiguous.to_string().contains("corp, other"));
        assert!(find(&rows, "nope/ReadOnly").is_err());
    }
}
