//! `gac doctor`: checks with a suggested fix for each, and with `--fix`, the fixes that are
//! mechanical. A fix that edits lines the user wrote shows its diff and asks first.

use jiff::Timestamp;
use serde::Serialize;

use crate::aws_files::AwsFiles;
use crate::cli::DoctorArgs;
use crate::cli::context::Context;
use crate::doctor::Report;
use crate::doctor::aws::{self, Diagnosis, Inputs};
use crate::doctor::fix::{self, Fix};
use crate::error::{Error, Result};
use crate::ui;

#[derive(Debug, Serialize)]
struct Output<'a> {
    #[serde(flatten)]
    report: &'a Report,
    /// What `--fix` changed, before the report was made again.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    fixed: Vec<String>,
}

pub async fn run(ctx: &Context, args: DoctorArgs) -> Result<()> {
    let (mut diagnosis, files) = diagnose(ctx).await;
    let mut fixed = Vec::new();
    if args.fix {
        match files {
            Ok(files) => fixed = apply(ctx, &files, &diagnosis, args.yes).await?,
            Err(_) => ui::notice("Nothing fixed: the config file must parse first."),
        }
        if !fixed.is_empty() {
            diagnosis = diagnose(ctx).await.0;
        }
    }
    let report = &diagnosis.report;
    let text = if args.json {
        let mut json = serde_json::to_string_pretty(&Output { report, fixed })
            .expect("serializing plain data cannot fail");
        json.push('\n');
        json
    } else {
        report.render()
    };
    ui::output(text).map_err(|err| Error::io("could not write to stdout", err))?;
    if report.has_failures() {
        return Err(Error::config("doctor found problems that need fixing"));
    }
    Ok(())
}

/// The checks, and the snapshot of the AWS files they ran on.
async fn diagnose(ctx: &Context) -> (Diagnosis, Result<AwsFiles>) {
    let files = ctx.files().await;
    let diagnosis = aws::run(&Inputs {
        paths: &ctx.paths,
        files: files.as_ref().map_err(ToString::to_string),
        home_var: std::env::var_os("HOME"),
        userprofile_var: std::env::var_os("USERPROFILE"),
        now: Timestamp::now(),
    });
    (diagnosis, files)
}

/// Applies the fixes the user agrees to and returns what each did. The config file is written
/// once, after every fix to it was decided.
async fn apply(
    ctx: &Context,
    files: &AwsFiles,
    diagnosis: &Diagnosis,
    yes: bool,
) -> Result<Vec<String>> {
    let planned = fix::plan(&diagnosis.actions, files);
    if planned.is_empty() {
        ui::notice("Nothing to fix.");
        return Ok(Vec::new());
    }
    let original = files.config_text();
    let mut text = original.to_owned();
    let mut done: Vec<&Fix> = Vec::new();
    for fix in &planned {
        if !fix.edits_config() {
            match fix.apply_to_disk() {
                Ok(()) => {
                    ui::notice(format!("Fixed: {}", fix.summary));
                    done.push(fix);
                }
                Err(err) => ui::notice(format!("Skipped: {}: {err}", fix.summary)),
            }
            continue;
        }
        let updated = match fix.apply_to_config(&text) {
            Ok(updated) => updated,
            Err(reason) => {
                ui::notice(format!("Skipped: {}: {reason}", fix.summary));
                continue;
            }
        };
        if fix.needs_consent && !yes && !consent(ctx, fix, &text, &updated)? {
            continue;
        }
        text = updated;
        done.push(fix);
    }
    if text != original {
        ctx.write_config(original, &text).await?;
        for fix in done.iter().filter(|f| f.edits_config()) {
            ui::notice(format!("Fixed: {}", fix.summary));
        }
    }
    let mut next: Vec<&str> = done.iter().filter_map(|f| f.next.as_deref()).collect();
    next.dedup();
    for step in next {
        ui::notice(format!("Next: {step}"));
    }
    Ok(done.iter().map(|f| f.summary.clone()).collect())
}

/// Shows what a fix changes in lines the user wrote and asks to apply it.
fn consent(ctx: &Context, fix: &Fix, text: &str, updated: &str) -> Result<bool> {
    if !ctx.can_prompt() {
        ui::notice(format!(
            "Skipped: {}: it edits lines you wrote; run gac doctor --fix in a terminal to review it, or pass --yes",
            fix.summary
        ));
        return Ok(false);
    }
    let path = ctx.paths.config_file().display().to_string();
    let diff = similar::TextDiff::from_lines(text, updated)
        .unified_diff()
        .context_radius(2)
        .header(&path, &path)
        .to_string();
    ui::notice(diff.trim_end());
    let mut message = fix.summary.clone();
    if let Some(first) = message.get_mut(..1) {
        first.make_ascii_uppercase();
    }
    message.push('?');
    ui::prompt::confirm(&message, "it edits lines you wrote, as shown above")
}
