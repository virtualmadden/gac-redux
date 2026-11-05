//! The command line: clap types and one orchestration function per command.

mod context;
mod doctor;
mod list;
mod login;
mod logout;
mod setup;
mod status;
mod sync;

use std::ffi::OsString;
use std::io::IsTerminal;

use clap::{Args, Parser, Subcommand};
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
    name = "gac",
    bin_name = "gac",
    version,
    arg_required_else_help = true,
    max_term_width = 100
)]
pub struct Cli {
    /// The [sso-session] to use; needed only when more than one is configured
    ///
    /// [env: GAC_SESSION]
    // Context reads GAC_SESSION, not clap: clap counts an env value as the flag being given, so
    // --profile and --all would conflict with an exported GAC_SESSION.
    #[arg(
        long,
        global = true,
        value_name = "NAME",
        help_heading = GLOBAL,
        help = "The [sso-session] to use; needed only when more than one is configured [env: GAC_SESSION]"
    )]
    #[allow(clippy::doc_markdown)] // this is --help text, where backticks would show
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
    /// Revoke the session and delete its cached token.
    Logout(LogoutArgs),
    /// Show sessions, token and registration expiry, and managed blocks. No secrets.
    Status(StatusArgs),
    /// Write native sso-session profiles for your accounts and roles into a managed block.
    Sync(SyncArgs),
    /// List the accounts and roles you can use.
    List(ListArgs),
    /// Check the AWS files and caches for problems, with a fix for each. Read-only.
    Doctor(DoctorArgs),
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
    #[arg(short, long, value_name = "NAME", conflicts_with = "session")]
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
    #[arg(short, long, value_name = "NAME", conflicts_with_all = ["all", "session"])]
    profile: Option<String>,

    /// Log out of every configured session and legacy profile.
    #[arg(long, conflicts_with = "session")]
    all: bool,
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
struct DoctorArgs {
    /// Print JSON.
    #[arg(long)]
    json: bool,
}

/// Parses `args`, runs the command, and returns its outcome. Usage errors exit inside clap
/// with code 2.
pub fn run<I, T>(args: I) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = Cli::parse_from(args);
    init_tracing(cli.verbose);
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

async fn dispatch(cli: Cli) -> Result<()> {
    let ctx = Context::new(cli.session.as_deref(), cli.no_input)?;
    match cli.command {
        Command::Setup(args) => setup::run(&ctx, args).await,
        Command::Login(args) => login::run(&ctx, args).await,
        Command::Logout(args) => logout::run(&ctx, args).await,
        Command::Status(args) => status::run(&ctx, args).await,
        Command::Sync(args) => sync::run(&ctx, args).await,
        Command::List(args) => list::run(&ctx, args).await,
        Command::Doctor(args) => doctor::run(&ctx, args).await,
    }
}

fn init_tracing(verbose: u8) {
    let default = match verbose {
        0 => "gac=warn",
        1 => "gac=debug",
        _ => {
            "gac=trace,aws_config=debug,aws_smithy_runtime=debug,aws_sdk_sso=debug,aws_sdk_ssooidc=debug"
        }
    };
    let filter = EnvFilter::try_from_env("GAC_LOG").unwrap_or_else(|_| EnvFilter::new(default));
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
    use clap::CommandFactory;

    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
    }
}
