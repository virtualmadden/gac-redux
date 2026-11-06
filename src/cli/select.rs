//! `gac select`: pick the default session from a list, or name it with `--session`.

use jiff::Timestamp;

use crate::auth::Session;
use crate::aws_files::AwsFiles;
use crate::cli::SelectArgs;
use crate::cli::context::Context;
use crate::cli::status::token_summary;
use crate::domain::SessionName;
use crate::error::{Error, Result};
use crate::ui;

pub async fn run(ctx: &Context, args: SelectArgs) -> Result<()> {
    if args.clear {
        ctx.save_selected(None)?;
        ui::notice("Cleared the default session.");
        return Ok(());
    }
    let files = ctx.files().await?;
    let names = files.session_names();
    if names.is_empty() {
        return Err(
            Error::config("no [sso-session] is configured in the AWS config file")
                .with_hint("run `gac setup`"),
        );
    }

    let name = if let Some(name) = ctx.typed_session() {
        if !files.has_session(name.as_str()) {
            return Err(
                Error::config(format!("no [sso-session {name}] in the AWS config file"))
                    .with_hint(format!("pick one of: {}", names.join(", "))),
            );
        }
        name.clone()
    } else {
        if !ctx.can_prompt() {
            return Err(
                Error::usage("gac select needs an interactive terminal to show the list")
                    .with_hint("pass --session NAME to set the default without the list"),
            );
        }
        pick(ctx, &files, &names)?
    };

    ctx.save_selected(Some(&name))?;
    ui::notice(format!("The default session is now `{name}`."));
    if let Some(env) = ctx.env_session().filter(|env| **env != name) {
        ui::warn(format!(
            "GAC_REDUX_SESSION={env} is set and takes precedence over the default; unset it to use `{name}`"
        ));
    }
    Ok(())
}

/// Shows one row per session, with its portal host, region and token state, starting on the current
/// default.
fn pick(ctx: &Context, files: &AwsFiles, names: &[&str]) -> Result<SessionName> {
    let store = ctx.token_store();
    let now = Timestamp::now();
    let rows: Vec<[String; 4]> = names
        .iter()
        .map(|name| {
            let config = name
                .parse()
                .and_then(|n: SessionName| files.sso_session(&n));
            match config {
                Ok(config) => {
                    let session = Session::from(config);
                    [
                        (*name).to_owned(),
                        portal_host(session.start_url.as_str()),
                        session.region.to_string(),
                        token_summary(&store, &session, now),
                    ]
                }
                Err(err) => [
                    (*name).to_owned(),
                    err.to_string(),
                    String::new(),
                    String::new(),
                ],
            }
        })
        .collect();
    let options = align(&rows, ctx.selected().map(SessionName::as_str));
    let cursor = ctx
        .selected()
        .and_then(|s| names.iter().position(|n| *n == s.as_str()))
        .unwrap_or(0);
    let index = ui::prompt::select(
        "Default session:",
        options,
        names,
        cursor,
        "↑↓ to move, type to filter, enter to choose, esc to cancel",
    )?;
    names[index].parse()
}

/// The host of a start URL, which names the portal in fewer columns than the whole URL.
fn portal_host(start_url: &str) -> String {
    url::Url::parse(start_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| start_url.to_owned())
}

/// Lays the rows out in columns, marking the current default.
fn align(rows: &[[String; 4]], selected: Option<&str>) -> Vec<String> {
    let width = |column: usize| {
        rows.iter()
            .map(|row| row[column].chars().count())
            .max()
            .unwrap_or(0)
    };
    let widths = [width(0), width(1), width(2)];
    rows.iter()
        .map(|row| {
            let marker = if selected == Some(row[0].as_str()) {
                "  (default)"
            } else {
                ""
            };
            format!(
                "{:w0$}  {:w1$}  {:w2$}  {}{marker}",
                row[0],
                row[1],
                row[2],
                row[3],
                w0 = widths[0],
                w1 = widths[1],
                w2 = widths[2],
            )
            .trim_end()
            .to_owned()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(cells: [&str; 4]) -> [String; 4] {
        cells.map(str::to_owned)
    }

    #[test]
    fn names_the_portal_by_its_host() {
        assert_eq!(
            portal_host("https://my-portal.awsapps.com/start"),
            "my-portal.awsapps.com"
        );
        assert_eq!(portal_host("not a url"), "not a url");
    }

    #[test]
    fn aligns_rows_and_marks_the_default() {
        let rows = [
            row([
                "corp",
                "corp.awsapps.com",
                "us-east-1",
                "logged in, 7h 12m left",
            ]),
            row(["sandbox", "sb.awsapps.com", "eu-west-1", "not logged in"]),
        ];
        insta::assert_snapshot!(align(&rows, Some("sandbox")).join("\n"), @r"
        corp     corp.awsapps.com  us-east-1  logged in, 7h 12m left
        sandbox  sb.awsapps.com    eu-west-1  not logged in  (default)
        ");
    }
}
