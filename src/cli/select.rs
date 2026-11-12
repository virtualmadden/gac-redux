//! `gac select`: pick the account and role of the `[default]` profile, which the AWS CLI and SDKs
//! use when no profile is named.

use crate::aws_files::default_block::{
    self, ACCOUNT_KEY, DefaultError, Found, ROLE_KEY, SESSION_KEY,
};
use crate::aws_files::section::Section;
use crate::aws_files::{AwsFiles, managed_block};
use crate::cli::SelectArgs;
use crate::cli::context::Context;
use crate::cli::target::{self, Row};
use crate::domain::SessionName;
use crate::error::{Error, Result};
use crate::profiles::SyncSettings;
use crate::ui;

pub async fn run(ctx: &Context, args: SelectArgs) -> Result<()> {
    let files = ctx.files().await?;
    if args.print {
        return print(ctx, &files, &args).await;
    }
    let text = files.config_text();
    let found = default_block::find(text).map_err(|err| broken(ctx, &err))?;
    if args.clear {
        return clear(ctx, text, found).await;
    }

    let rows = target::rows(ctx, &files).await?;
    let current = match &found {
        Found::Managed(section) | Found::HandWritten(section) => Some(section),
        Found::Absent => None,
    };
    let chosen = choose(ctx, &rows, &args, current, "Default profile:")?;

    if files.credentials_profile("default").is_some() {
        return Err(Error::config(
            "the credentials file has a [default] section; an SSO [default] in the config file would hide its keys",
        )
        .with_hint(format!(
            "move the keys in {} to another profile name, then run gac select again",
            ctx.paths.credentials_file().display()
        )));
    }
    let (mut section, range) = match found {
        Found::Managed(section) => {
            let range = section.range.clone();
            (section, Some(range))
        }
        Found::HandWritten(section) => {
            if !adopt(ctx, &args)? {
                ui::notice("Left [default] as it is. Nothing was written.");
                return Ok(());
            }
            let range = section.range.clone();
            (section, Some(range))
        }
        Found::Absent => (default_block::empty(), None),
    };

    section.set(SESSION_KEY, chosen.session.as_str(), &[]);
    if section.get("region").is_none()
        && let Some(region) = sync_region(ctx, &files, &chosen.session)?
    {
        section.set("region", region.as_str(), &[SESSION_KEY]);
    }
    section.set(
        ACCOUNT_KEY,
        chosen.account.id.as_str(),
        &[SESSION_KEY, "region"],
    );
    section.set(ROLE_KEY, chosen.role.as_str(), &[ACCOUNT_KEY]);
    section.align();
    write(ctx, text, &section, range).await?;

    ui::notice(format!(
        "The default profile is now {} (account {}, session `{}`).",
        chosen.label(),
        chosen.account.id,
        chosen.session
    ));
    for var in ["AWS_PROFILE", "AWS_DEFAULT_PROFILE"] {
        if let Some(value) = std::env::var(var).ok().filter(|v| !v.is_empty()) {
            ui::warn(format!(
                "{var}={value} is set in this shell and takes precedence over [default]"
            ));
        }
    }
    if let Some(env) = ctx.env_session().filter(|env| **env != chosen.session) {
        ui::warn(format!(
            "GAC_REDUX_SESSION={env} is set, so gac commands still use session `{env}`"
        ));
    }
    Ok(())
}

/// `--print`: the chosen role's profile name on stdout, for `export AWS_PROFILE=...`. Writes
/// nothing.
async fn print(ctx: &Context, files: &AwsFiles, args: &SelectArgs) -> Result<()> {
    let rows = target::rows(ctx, files).await?;
    let chosen = choose(ctx, &rows, args, None, "Profile:")?;
    let Some(name) = target::profile_of(ctx, files, &chosen)? else {
        return Err(Error::config(format!(
            "no profile in the AWS config file signs in as {}",
            chosen.label()
        ))
        .with_hint(format!(
            "run `gac sync --session {}` to write one, or `gac exec {}` to use it directly",
            chosen.session,
            chosen.label()
        )));
    };
    ui::output(format!("{name}\n"))
}

/// The row ACCOUNT/ROLE names, or else the one picked from the list.
fn choose(
    ctx: &Context,
    rows: &[Row],
    args: &SelectArgs,
    current: Option<&Section>,
    message: &str,
) -> Result<Row> {
    if let Some(target) = &args.target {
        return target::find(rows, target);
    }
    if !ctx.can_prompt() {
        return Err(
            Error::usage("gac select needs an interactive terminal to show the list")
                .with_hint("pass ACCOUNT/ROLE, e.g. `gac select payments-prod/ReadOnly`"),
        );
    }
    pick(rows, current, message)
}

/// Takes the account and role out of the default block, leaving the rest of `[default]`.
async fn clear(ctx: &Context, text: &str, found: Found) -> Result<()> {
    let Found::Managed(mut section) = found else {
        ui::notice("gac does not manage [default], so there is nothing to clear.");
        return Ok(());
    };
    if section.get(ACCOUNT_KEY).is_none() && section.get(ROLE_KEY).is_none() {
        ui::notice("[default] has no account or role. Nothing to clear.");
        return Ok(());
    }
    section.remove(ACCOUNT_KEY);
    section.remove(ROLE_KEY);
    section.align();
    let range = section.range.clone();
    write(ctx, text, &section, Some(range)).await?;
    ui::notice(
        "Cleared the account and role from [default]: AWS commands now need --profile or AWS_PROFILE.",
    );
    Ok(())
}

/// Renders the section as the default block in place of `range`, or appended, and writes it.
async fn write(
    ctx: &Context,
    text: &str,
    section: &Section,
    range: Option<std::ops::Range<usize>>,
) -> Result<()> {
    let block = default_block::render(section, managed_block::line_ending(text));
    let updated = match range {
        Some(range) => format!("{}{block}{}", &text[..range.start], &text[range.end..]),
        None => managed_block::append(text, &block),
    };
    if updated == text {
        return Ok(());
    }
    ctx.write_config(text, &updated).await
}

/// Whether gac may take over the `[default]` section the user wrote.
fn adopt(ctx: &Context, args: &SelectArgs) -> Result<bool> {
    if args.adopt {
        return Ok(true);
    }
    if !ctx.can_prompt() {
        return Err(
            Error::usage("the config file has a [default] section that gac did not write")
                .with_hint("pass --adopt to let gac manage it; its lines are kept"),
        );
    }
    ui::prompt::confirm(
        "Let gac manage the [default] section you wrote?",
        "its lines are kept; `gac select --clear` removes the account and role again",
        false,
    )
}

/// Shows the rows as `gac list` does, starting on the first, and returns the one chosen.
fn pick(rows: &[Row], current: Option<&Section>, message: &str) -> Result<Row> {
    let current =
        current.and_then(|s| Some((s.get(SESSION_KEY)?, s.get(ACCOUNT_KEY)?, s.get(ROLE_KEY)?)));
    let several_sessions = rows.iter().any(|row| row.session != rows[0].session);
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            let mut cells = vec![
                row.account.id.to_string(),
                row.account.name.clone(),
                row.role.to_string(),
            ];
            if several_sessions {
                cells.push(row.session.to_string());
            }
            let is_current = current.is_some_and(|(session, account, role)| {
                session == row.session.as_str()
                    && account == row.account.id.as_str()
                    && role == row.role.as_str()
            });
            cells.push(if is_current { "(default)" } else { "" }.to_owned());
            cells
        })
        .collect();
    let labels: Vec<String> = rows.iter().map(Row::label).collect();
    let answers: Vec<&str> = labels.iter().map(String::as_str).collect();
    let index = ui::prompt::select(
        message,
        align(&cells),
        &answers,
        0,
        "↑↓ to move, type to filter, enter to choose, esc to cancel",
    )?;
    Ok(rows[index].clone())
}

/// Lays the cells out in left-aligned columns, two spaces apart, without trailing spaces.
fn align(rows: &[Vec<String>]) -> Vec<String> {
    let columns = rows.first().map_or(0, Vec::len);
    let widths: Vec<usize> = (0..columns)
        .map(|c| {
            rows.iter()
                .map(|row| row[c].chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    rows.iter()
        .map(|row| {
            row.iter()
                .zip(&widths)
                .map(|(cell, width)| format!("{cell:<width$}"))
                .collect::<Vec<_>>()
                .join("  ")
                .trim_end()
                .to_owned()
        })
        .collect()
}

/// The `region` the session's sync block sets, if any.
fn sync_region(
    ctx: &Context,
    files: &AwsFiles,
    session: &SessionName,
) -> Result<Option<crate::domain::Region>> {
    let blocks = ctx.blocks(files)?;
    let Some(block) = blocks.iter().find(|b| b.header.session == session.as_str()) else {
        return Ok(None);
    };
    Ok(SyncSettings::from_header(&block.header)?.region)
}

fn broken(ctx: &Context, err: &DefaultError) -> Error {
    Error::config(format!(
        "gac cannot tell which [default] to use in {}: {err}",
        ctx.paths.config_file().display()
    ))
    .with_hint("leave one [default] section, and repair or delete broken `# BEGIN gac-redux default` / `# END gac-redux default` lines by hand")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aligns_rows_like_gac_list() {
        let cells = [
            vec!["111122223333", "payments-prod", "AdministratorAccess", ""],
            vec!["444455556666", "Shared Services", "ReadOnly", "(default)"],
        ]
        .map(|row| row.into_iter().map(str::to_owned).collect());
        insta::assert_snapshot!(align(&cells).join("\n"), @r"
        111122223333  payments-prod    AdministratorAccess
        444455556666  Shared Services  ReadOnly             (default)
        ");
    }
}
