//! `gac console`: open the AWS console signed in as a role, without the access portal.

use crate::cli::ConsoleArgs;
use crate::cli::context::Context;
use crate::cli::target;
use crate::domain::Region;
use crate::error::Result;
use crate::federation::{self, SigninError};
use crate::partition::Partition;
use crate::secret::ExposeSecret;
use crate::ui;

pub async fn run(ctx: &Context, args: ConsoleArgs) -> Result<()> {
    let region = args
        .region
        .as_deref()
        .map(str::parse::<Region>)
        .transpose()?;
    let files = ctx.files().await?;
    let target =
        target::resolve(ctx, &files, args.profile.as_deref(), args.target.as_deref()).await?;
    // The console's region: --region, else the one the shell's AWS tools use, else the
    // profile's, as for `gac exec`.
    let region = region
        .or_else(|| env_region().and_then(|region| region.parse().ok()))
        .or_else(|| target.region.clone());
    let partition = Partition::of(&target.session.region);
    let destination = partition.destination(args.destination.as_deref(), region.as_ref())?;
    let issuer = target.session.start_url.as_str();
    let creds = target.credentials(ctx).await?;
    let url = match federation::signin_url(&partition, &creds, issuer, &destination) {
        Ok(url) => url,
        // Cached credentials can be revoked before they expire, say by a permission set
        // change: fetch new ones and try once more.
        Err(SigninError::Refused(status)) => {
            tracing::debug!(%status, "the federation endpoint refused the credentials; fetching new ones");
            target.forget_credentials(ctx)?;
            let creds = target.credentials(ctx).await?;
            federation::signin_url(&partition, &creds, issuer, &destination)
                .map_err(SigninError::into_error)?
        }
        Err(err) => return Err(err.into_error()),
    };
    let url = url.expose_secret();

    if args.print {
        return ui::output(format!("{url}\n"));
    }
    let over_ssh = ["SSH_CONNECTION", "SSH_TTY"]
        .iter()
        .any(|var| std::env::var_os(var).is_some_and(|v| !v.is_empty()));
    if !over_ssh && ui::browser::open(url) {
        ui::notice(format!(
            "Opened the AWS console as {} in your browser.",
            target.label
        ));
        return Ok(());
    }
    ui::notice(format!(
        "Open this link to sign in to the AWS console as {}. It works once, within 15 minutes; keep it private:",
        target.label
    ));
    ui::notice(format!("  {url}"));
    Ok(())
}

fn env_region() -> Option<String> {
    ["AWS_REGION", "AWS_DEFAULT_REGION"]
        .iter()
        .find_map(|var| std::env::var(var).ok().filter(|v| !v.is_empty()))
}
