//! Which account and role a command acts on: the rows `gac list` shows, an `ACCOUNT/ROLE` picked
//! from them, or a profile's `sso_account_id` and `sso_role_name`, followed through any
//! `role_arn`/`source_profile` chain.

use jiff::Timestamp;

use crate::auth::Session;
use crate::auth::assume::{self, AssumeCache, AssumeRole};
use crate::auth::role::{self, RoleCache, RoleCredentials};
use crate::aws_files::AwsFiles;
use crate::cli::context::{self, Context};
use crate::domain::{AccountId, Region, RoleName, SessionName};
use crate::error::{Error, Result};
use crate::partition::Partition;
use crate::portal::Account;
use crate::profiles;
use crate::ui;

/// How many `source_profile` links a chain may have; more is almost surely a loop.
const MAX_CHAIN: usize = 5;

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
    /// The SSO role the credentials start from.
    pub account: AccountId,
    pub role: RoleName,
    /// The roles then assumed in turn, for a chained profile.
    pub chain: Vec<AssumeRole>,
    /// The profile's `region`, if a profile named the role and set one.
    pub region: Option<Region>,
    /// How to name it to the user: `payments-prod/ReadOnly`, or `profile dev`.
    pub label: String,
    /// The profile that named it; `None` for `ACCOUNT/ROLE`.
    pub profile: Option<String>,
    /// What picked it.
    pub source: Source,
}

/// What picked the role, in the order [`resolve`] tries them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// `ACCOUNT/ROLE` on the command line.
    Target,
    /// `--profile`.
    Flag,
    /// `AWS_PROFILE` or `AWS_DEFAULT_PROFILE`.
    Env(&'static str),
    /// The `[default]` profile.
    Default,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Target => "ACCOUNT/ROLE",
            Self::Flag => "--profile",
            Self::Env(var) => var,
            Self::Default => "[default]",
        }
    }
}

impl RoleTarget {
    /// The account whose credentials a command ends up with: the last assumed role's, if any.
    pub fn final_account(&self) -> &AccountId {
        self.chain
            .last()
            .map_or(&self.account, |step| step.role_arn.account())
    }

    /// The role a command ends up with.
    pub fn final_role(&self) -> &RoleName {
        self.chain
            .last()
            .map_or(&self.role, |step| step.role_arn.role())
    }

    /// When the cached credentials of the final role expire, used or not.
    pub fn cached_expiration(&self, ctx: &Context) -> Option<Timestamp> {
        match self.chain.last() {
            Some(step) => AssumeCache::new(ctx.paths.cli_cache_dir()).expiration(step),
            None => RoleCache::new(ctx.paths.cli_cache_dir()).expiration(&RoleCache::key(
                &self.session,
                &self.account,
                &self.role,
            )),
        }
    }

    /// Drops the cached credentials of every role in the chain, so the next
    /// [`Self::credentials`] fetches new ones.
    pub fn forget_credentials(&self, ctx: &Context) -> Result<()> {
        RoleCache::new(ctx.paths.cli_cache_dir()).remove(&RoleCache::key(
            &self.session,
            &self.account,
            &self.role,
        ))?;
        let cache = AssumeCache::new(ctx.paths.cli_cache_dir());
        self.chain.iter().try_for_each(|step| cache.remove(step))
    }

    /// Where STS is asked: the profile's region, else the main region of its partition.
    fn sts_region(&self) -> Region {
        self.region.clone().unwrap_or_else(|| {
            Partition::of(&self.session.region)
                .default_region
                .parse()
                .expect("a valid region")
        })
    }

    /// The final role's credentials: the SSO role's, then each assumed role's in turn, each from
    /// the AWS CLI's cache while it lasts. A missing login is offered at the terminal, as for
    /// every command that lists.
    pub async fn credentials(&self, ctx: &Context) -> Result<RoleCredentials> {
        let mut creds = role::credentials(
            &RoleCache::new(ctx.paths.cli_cache_dir()),
            &self.session,
            &self.account,
            &self.role,
            async || ctx.usable_token(&self.session).await,
        )
        .await?;
        let cache = AssumeCache::new(ctx.paths.cli_cache_dir());
        let region = self.sts_region();
        for step in &self.chain {
            creds = assume::credentials(&cache, step, &creds, &region).await?;
        }
        Ok(creds)
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
            chain: Vec::new(),
            region: None,
            profile: None,
            source: Source::Target,
        });
    }
    if ctx.typed_session().is_some() {
        return Err(
            Error::usage("--session picks where ACCOUNT/ROLE is looked up")
                .with_hint("pass ACCOUNT/ROLE as well, or --profile NAME without --session"),
        );
    }
    let (name, source) = match profile {
        Some(name) => (name.to_owned(), Source::Flag),
        None => match profile_from_env() {
            Some((name, var)) => (name, Source::Env(var)),
            None => ("default".to_owned(), Source::Default),
        },
    };
    // `gac select` needs a session, so without one the first step is `gac setup`.
    let pick_hint = if files.session_names().is_empty() {
        "run `gac setup`, then `gac select` to pick an account and role"
    } else {
        "run `gac select` to pick one, or pass --profile NAME or ACCOUNT/ROLE"
    };
    let Some(section) = files.config_profile(&name) else {
        return Err(if source == Source::Default {
            Error::config("there is no [default] profile to take the account and role from")
                .with_hint(pick_hint)
        } else {
            let err = Error::config(format!(
                "no profile `{name}` in the AWS config file (from {})",
                source.as_str()
            ));
            match source {
                Source::Env(var) => err.with_hint(format!(
                    "unset {var} to use [default], or pass --profile NAME"
                )),
                _ => err.with_hint(
                    "run `gac sync` to write the profiles, or `gac list` to see the roles",
                ),
            }
        });
    };
    let label = if name == "default" {
        "the [default] profile".to_owned()
    } else {
        format!("profile `{name}`")
    };
    let region = section.get("region").map(str::parse).transpose()?;
    let hint = (name == "default").then_some(pick_hint);
    let (session, account, role, chain) = role_chain(files, &name, 0, hint)?;
    Ok(RoleTarget {
        session,
        account,
        role,
        chain,
        region,
        label,
        profile: Some(name),
        source,
    })
}

/// The SSO role profile `name` signs in with, and the roles it then assumes, first to last.
/// `hint` is added when the profile names no role at all.
fn role_chain(
    files: &AwsFiles,
    name: &str,
    depth: usize,
    hint: Option<&str>,
) -> Result<(Session, AccountId, RoleName, Vec<AssumeRole>)> {
    let Some(section) = files.config_profile(name) else {
        return Err(Error::config(format!(
            "no profile `{name}` in the AWS config file, though a source_profile names it"
        )));
    };
    if let Some(arn) = section.get("role_arn") {
        let unsupported = |what: &str| {
            Error::config(format!(
                "profile `{name}` uses {what}, which gac does not follow"
            ))
            .with_hint("use source_profile with an SSO profile, or the AWS CLI for this one")
        };
        if section.get("credential_source").is_some() {
            return Err(unsupported("credential_source"));
        }
        if section.get("mfa_serial").is_some() {
            return Err(unsupported("mfa_serial (an MFA prompt)"));
        }
        let Some(source) = section.get("source_profile") else {
            return Err(Error::config(format!(
                "profile `{name}` has a role_arn but no source_profile"
            )));
        };
        if depth >= MAX_CHAIN {
            return Err(Error::config(format!(
                "the source_profile chain through profile `{name}` is longer than {MAX_CHAIN} links"
            ))
            .with_hint("check the source_profile settings for a loop"));
        }
        let (session, account, role, mut chain) = role_chain(files, source, depth + 1, None)?;
        chain.push(AssumeRole {
            role_arn: arn.parse()?,
            session_name: section.get("role_session_name").map(str::to_owned),
            external_id: section.get("external_id").map(str::to_owned),
            duration_seconds: section
                .get("duration_seconds")
                .map(|seconds| {
                    seconds.parse().map_err(|_| {
                        Error::config(format!(
                            "profile `{name}` has an unreadable duration_seconds `{seconds}`"
                        ))
                    })
                })
                .transpose()?,
        });
        return Ok((session, account, role, chain));
    }
    if let Some((session, account, role)) = section
        .get("credential_process")
        .and_then(profiles::parse_process_command)
    {
        return Ok((
            files.sso_session(&session)?.into(),
            account,
            role,
            Vec::new(),
        ));
    }
    let session = context::session_of_profile(files, name)?;
    let (Some(account), Some(role)) = (section.get("sso_account_id"), section.get("sso_role_name"))
    else {
        let label = if name == "default" {
            "the [default] profile".to_owned()
        } else {
            format!("profile `{name}`")
        };
        let err = Error::config(format!(
            "{label} names no sso_account_id and sso_role_name, nor a role_arn to assume"
        ));
        return Err(match hint {
            Some(hint) => err.with_hint(hint),
            None => err,
        });
    };
    Ok((session, account.parse()?, role.parse()?, Vec::new()))
}

/// The profile that signs in as `row`: one gac synced, else any other, by name. `[default]`
/// does not count, since it changes with `gac select`.
pub fn profile_of<'a>(ctx: &Context, files: &'a AwsFiles, row: &Row) -> Result<Option<&'a str>> {
    let signs_in_as_row = |name: &&str| {
        let Some(section) = files.config_profile(name).filter(|_| *name != "default") else {
            return false;
        };
        if let Some((session, account, role)) = section
            .get("credential_process")
            .and_then(profiles::parse_process_command)
        {
            return session == row.session && account == row.account.id && role == row.role;
        }
        section.get("sso_session") == Some(row.session.as_str())
            && section.get("sso_account_id") == Some(row.account.id.as_str())
            && section.get("sso_role_name") == Some(row.role.as_str())
    };
    let text = files.config_text();
    let synced: Vec<&str> = ctx
        .blocks(files)?
        .iter()
        .flat_map(|block| block.profile_names(text))
        .collect();
    let candidates: Vec<&str> = files
        .config_profile_names()
        .into_iter()
        .filter(signs_in_as_row)
        .collect();
    Ok(candidates
        .iter()
        .find(|name| synced.contains(name))
        .or(candidates.first())
        .copied())
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
        return Err(context::no_sessions());
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
