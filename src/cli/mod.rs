//! The command line: clap types and one orchestration function per command.

mod context;
mod doctor;
mod exec;
mod generate;
mod list;
mod login;
mod logout;
mod select;
mod setup;
mod status;
mod sync;
mod target;

use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::PathBuf;

use clap::error::ErrorKind;
use clap::parser::ValueSource;
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use crate::error::{Error, Result};
use context::Context;

const GLOBAL: &str = "Global options";

/// Short-lived AWS credentials through IAM Identity Center.
///
/// gac logs you in, keeps native sso-session profiles in ~/.aws/config in step with your
/// account and role assignments, and shares its token cache with the AWS CLI and SDKs.
#[derive(Debug, Parser)]
#[command(
    name = "gac-redux",
    bin_name = "gac",
    version,
    arg_required_else_help = true,
    max_term_width = 100
)]
pub struct Cli {
    /// The [sso-session] to use, overriding the session of the [default] profile.
    // `run` keeps the value only when typed on the command line: clap counts an env value as the
    // flag being given, so --profile and --all would conflict with an exported GAC_REDUX_SESSION.
    // Context reads GAC_REDUX_SESSION itself; `env` is here for the help text.
    #[arg(
        long,
        global = true,
        env = "GAC_REDUX_SESSION",
        hide_env_values = true,
        value_name = "NAME",
        help_heading = GLOBAL
    )]
    session: Option<String>,

    /// Never prompt; fail with a hint instead.
    #[arg(long, global = true, help_heading = GLOBAL)]
    no_input: bool,

    /// Log to stderr: -v for debug, -vv for trace. Secrets are never logged.
    #[arg(short, long, global = true, action = clap::ArgAction::Count, help_heading = GLOBAL)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create an [sso-session], or reuse one `aws configure sso` already wrote.
    Setup(SetupArgs),
    /// Sign in to IAM Identity Center and write the shared token cache.
    Login(LoginArgs),
    /// Revoke the session, delete its cached token and the AWS CLI's SSO role credentials.
    Logout(LogoutArgs),
    /// Pick the account and role of the [default] profile from a list.
    Select(SelectArgs),
    /// Show sessions, token and registration expiry, and managed blocks. No secrets.
    Status(StatusArgs),
    /// Write native sso-session profiles for your accounts and roles into a managed block.
    Sync(SyncArgs),
    /// List the accounts and roles you can use.
    List(ListArgs),
    /// Run a command with a role's credentials in its environment.
    Exec(ExecArgs),
    /// Check the AWS files and caches for problems; --fix applies the mechanical fixes.
    Doctor(DoctorArgs),
    /// Print a shell completion script, e.g. `source <(gac completions zsh)`.
    Completions(CompletionsArgs),
    /// Write the man pages into a directory. Used to build the release archives.
    #[command(hide = true)]
    Man(ManArgs),
}

#[derive(Debug, Args)]
struct SetupArgs {
    /// The access portal start URL, e.g. `https://my-portal.awsapps.com/start`.
    #[arg(long, value_name = "URL")]
    start_url: Option<String>,

    /// The region of the Identity Center instance.
    #[arg(long, value_name = "REGION")]
    region: Option<String>,
}

#[derive(Debug, Args)]
struct LoginArgs {
    /// Log in for the session of this profile; legacy inline-SSO profiles work too.
    #[arg(short, long, value_name = "NAME")]
    profile: Option<String>,

    /// Use the device code flow (default over SSH).
    #[arg(long, conflicts_with = "pkce")]
    device_code: bool,

    /// Use the browser PKCE flow even over SSH.
    #[arg(long)]
    pkce: bool,

    /// Print the sign-in link instead of opening a browser.
    #[arg(long)]
    no_browser: bool,

    /// Listen for the PKCE redirect on this port instead of a random one.
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u16).range(1..))]
    port: Option<u16>,
}

#[derive(Debug, Args)]
struct LogoutArgs {
    /// Log out of the session of this profile.
    #[arg(short, long, value_name = "NAME", conflicts_with = "all")]
    profile: Option<String>,

    /// Log out of every configured session and legacy profile.
    #[arg(long)]
    all: bool,
}

#[derive(Debug, Args)]
struct SelectArgs {
    /// Choose without the list, by account name or id, e.g. `payments-prod/ReadOnly`.
    #[arg(value_name = "ACCOUNT/ROLE", conflicts_with = "clear")]
    target: Option<String>,

    /// Take the account and role out of [default] again.
    #[arg(long)]
    clear: bool,

    /// Let gac manage a [default] section you wrote, without asking.
    #[arg(long)]
    adopt: bool,
}

#[derive(Debug, Args)]
struct StatusArgs {
    /// Print JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct SyncArgs {
    /// Profile-name template using `{account}`, `{account_id}`, `{role}` and `{session}` [default: `{account}/{role}`]
    #[arg(long, value_name = "TEMPLATE")]
    name: Option<String>,

    /// Only sync ACCOUNT/ROLE pairs matching this glob (repeatable).
    #[arg(long, value_name = "GLOB")]
    include: Vec<String>,

    /// Skip ACCOUNT/ROLE pairs matching this glob (repeatable; wins over --include).
    #[arg(long, value_name = "GLOB")]
    exclude: Vec<String>,

    /// Set `region` in every synced profile.
    #[arg(long, value_name = "REGION")]
    region: Option<String>,

    /// Forget the settings stored in the block and start from the defaults.
    #[arg(long)]
    reset: bool,

    /// Fetch accounts and roles from the portal even if the inventory cache is fresh.
    #[arg(long)]
    refresh: bool,

    /// Print the change as a diff and write nothing.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
struct ListArgs {
    /// Print JSON.
    #[arg(long)]
    json: bool,

    /// Fetch from the portal even if the inventory cache is fresh.
    #[arg(long)]
    refresh: bool,
}

#[derive(Debug, Args)]
#[command(
    after_help = "The role is ACCOUNT/ROLE, else that of --profile, AWS_PROFILE or the [default] profile.\nThe command gets AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN,\nAWS_CREDENTIAL_EXPIRATION and, when known, AWS_REGION; AWS_PROFILE is unset.\nExits with the command's exit code."
)]
struct ExecArgs {
    /// Use the account and role of this profile.
    #[arg(short, long, value_name = "NAME", conflicts_with = "target")]
    profile: Option<String>,

    /// Set `AWS_REGION` and `AWS_DEFAULT_REGION` to this region.
    #[arg(long, value_name = "REGION")]
    region: Option<String>,

    /// Run even inside another `gac exec`.
    #[arg(long)]
    force: bool,

    /// The account and role, by account name or id, e.g. `payments-prod/ReadOnly`.
    #[arg(value_name = "ACCOUNT/ROLE")]
    target: Option<String>,

    /// The command and its arguments, after `--`.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    command: Vec<OsString>,
}

#[derive(Debug, Args)]
struct DoctorArgs {
    /// Print JSON.
    #[arg(long)]
    json: bool,

    /// Apply the fixes that are mechanical, then check again. A fix to lines you wrote shows its diff and asks first.
    #[arg(long)]
    fix: bool,

    /// With --fix, apply the fixes to lines you wrote without asking.
    #[arg(long, requires = "fix")]
    yes: bool,
}

#[derive(Debug, Args)]
struct CompletionsArgs {
    /// The shell to complete for.
    #[arg(value_enum)]
    shell: clap_complete::Shell,
}

#[derive(Debug, Args)]
struct ManArgs {
    /// The directory to write `gac.1` and the `gac-COMMAND.1` pages into.
    #[arg(value_name = "DIR")]
    dir: PathBuf,
}

/// Parses `args`, runs the command, and returns its outcome. Usage errors exit inside clap
/// with code 2.
pub fn run<I, T>(args: I) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let mut cmd = Cli::command();
    let matches = cmd
        .try_get_matches_from_mut(args)
        .unwrap_or_else(|err| err.exit());
    let mut cli = Cli::from_arg_matches(&matches).unwrap_or_else(|err| err.format(&mut cmd).exit());
    if matches.value_source("session") != Some(ValueSource::CommandLine) {
        cli.session = None;
    } else if let Some((name, other)) = cli.command.session_conflict() {
        let sub = cmd
            .find_subcommand_mut(name)
            .expect("the subcommand exists");
        sub.error(
            ErrorKind::ArgumentConflict,
            format!("the argument '--session <NAME>' cannot be used with '{other}'"),
        )
        .exit();
    }
    init_tracing(cli.verbose);
    match &cli.command {
        Command::Completions(args) => return generate::completions(args),
        Command::Man(args) => return generate::man(args),
        _ => {}
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| Error::io("could not start the async runtime", err))?;
    runtime.block_on(async {
        tokio::select! {
            result = dispatch(cli) => result,
            _ = tokio::signal::ctrl_c() => Err(Error::Interrupted),
        }
    })
}

impl Command {
    /// The subcommand and its flag that a typed `--session` conflicts with, if one is given.
    fn session_conflict(&self) -> Option<(&'static str, &'static str)> {
        match self {
            Command::Login(LoginArgs {
                profile: Some(_), ..
            }) => Some(("login", "--profile <NAME>")),
            Command::Logout(LogoutArgs {
                profile: Some(_), ..
            }) => Some(("logout", "--profile <NAME>")),
            Command::Logout(LogoutArgs { all: true, .. }) => Some(("logout", "--all")),
            Command::Select(SelectArgs { clear: true, .. }) => Some(("select", "--clear")),
            Command::Exec(ExecArgs {
                profile: Some(_), ..
            }) => Some(("exec", "--profile <NAME>")),
            _ => None,
        }
    }
}

async fn dispatch(cli: Cli) -> Result<()> {
    let ctx = Context::new(cli.session.as_deref(), cli.no_input)?;
    match cli.command {
        Command::Setup(args) => setup::run(&ctx, args).await,
        Command::Login(args) => login::run(&ctx, args).await,
        Command::Logout(args) => logout::run(&ctx, args).await,
        Command::Select(args) => select::run(&ctx, args).await,
        Command::Status(args) => status::run(&ctx, args).await,
        Command::Sync(args) => sync::run(&ctx, args).await,
        Command::List(args) => list::run(&ctx, args).await,
        Command::Exec(args) => exec::run(&ctx, args).await,
        Command::Doctor(args) => doctor::run(&ctx, args).await,
        Command::Completions(_) | Command::Man(_) => unreachable!("handled before the runtime"),
    }
}

fn init_tracing(verbose: u8) {
    let default = match verbose {
        0 => "gac_redux=warn",
        1 => "gac_redux=debug",
        _ => {
            "gac_redux=trace,aws_config=debug,aws_smithy_runtime=debug,aws_sdk_sso=debug,aws_sdk_ssooidc=debug"
        }
    };
    let filter =
        EnvFilter::try_from_env("GAC_REDUX_LOG").unwrap_or_else(|_| EnvFilter::new(default));
    let ansi = std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(ansi)
        .without_time()
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
    }
}
