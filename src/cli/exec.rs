//! `gac exec`: run a command with role credentials in its environment, for tools that read
//! `AWS_ACCESS_KEY_ID` and friends but not SSO profiles.

use std::ffi::{OsStr, OsString};
use std::process::Command;

use crate::auth::role::RoleCredentials;
use crate::cli::ExecArgs;
use crate::cli::context::Context;
use crate::cli::target::{self, RoleTarget};
use crate::domain::Region;
use crate::error::{Error, Result};
use crate::secret::ExposeSecret;

/// Set in the command's environment to the role it runs as, so a nested `gac exec` notices.
const NESTED: &str = "GAC_REDUX_EXEC";

pub async fn run(ctx: &Context, args: ExecArgs) -> Result<()> {
    if !args.force
        && let Some(outer) = std::env::var_os(NESTED).filter(|v| !v.is_empty())
    {
        return Err(Error::usage(format!(
            "already running inside `gac exec` as {}",
            outer.to_string_lossy()
        ))
        .with_hint("exit that command first, or pass --force to run inside it anyway"));
    }
    let region = args
        .region
        .as_deref()
        .map(str::parse::<Region>)
        .transpose()?;
    let files = ctx.files().await?;
    let target =
        target::resolve(ctx, &files, args.profile.as_deref(), args.target.as_deref()).await?;
    let creds = target.credentials(ctx).await?;
    tracing::debug!(role = %target.label, expiration = %creds.expiration, "running the command");

    let (program, rest) = args.command.split_first().expect("clap requires a command");
    let mut command = Command::new(program);
    command.args(rest);
    for (name, value) in variables(&target, &creds, region.as_ref()) {
        match value {
            Some(value) => command.env(name, value),
            None => command.env_remove(name),
        };
    }
    command.env(NESTED, &target.label);
    exec(command, program)
}

/// The variables to set, and with `None` to unset, so a process uses the role's credentials:
/// keys, expiry, and a region when one is known, but no profile that could pick another
/// identity. The region is `region`, else none if the environment already has one (the SDKs
/// prefer it over a profile's), else the profile's.
pub fn variables(
    target: &RoleTarget,
    creds: &RoleCredentials,
    region: Option<&Region>,
) -> Vec<(&'static str, Option<String>)> {
    let mut vars = vec![
        ("AWS_ACCESS_KEY_ID", Some(creds.access_key_id.clone())),
        (
            "AWS_SECRET_ACCESS_KEY",
            Some(creds.secret_access_key.expose_secret().to_owned()),
        ),
        (
            "AWS_SESSION_TOKEN",
            Some(creds.session_token.expose_secret().to_owned()),
        ),
        (
            "AWS_CREDENTIAL_EXPIRATION",
            Some(creds.expiration.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()),
        ),
        ("AWS_PROFILE", None),
        ("AWS_DEFAULT_PROFILE", None),
        ("AWS_SECURITY_TOKEN", None),
    ];
    let inherited = ["AWS_REGION", "AWS_DEFAULT_REGION"]
        .iter()
        .any(|var| std::env::var_os(var).is_some_and(|v| !v.is_empty()));
    let region = region.or(target.region.as_ref().filter(|_| !inherited));
    if let Some(region) = region {
        vars.push(("AWS_REGION", Some(region.to_string())));
        vars.push(("AWS_DEFAULT_REGION", Some(region.to_string())));
    }
    vars
}

/// Replaces this process with the command, so its exit code and signals are the command's own.
#[cfg(unix)]
fn exec(mut command: Command, program: &OsStr) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let source = command.exec();
    Err(spawn_error(program, source))
}

/// Runs the command and exits with its code: Windows cannot replace a process.
#[cfg(not(unix))]
fn exec(mut command: Command, program: &OsStr) -> Result<()> {
    let status = command
        .status()
        .map_err(|source| spawn_error(program, source))?;
    std::process::exit(status.code().unwrap_or(1));
}

fn spawn_error(program: &OsStr, source: std::io::Error) -> Error {
    Error::Spawn {
        command: OsString::from(program).to_string_lossy().into_owned(),
        source,
    }
}
