//! `gac sync`: write and prune the session's managed block of native profiles.

use std::collections::BTreeSet;

use crate::aws_files::managed_block::Block;
use crate::aws_files::{AwsFiles, guards, managed_block};
use crate::cli::SyncArgs;
use crate::cli::context::Context;
use crate::error::{Error, Result};
use crate::profiles::{self, PlannedProfile, SyncSettings};
use crate::ui;

pub async fn run(ctx: &Context, args: SyncArgs) -> Result<()> {
    let files = ctx.files().await?;
    let session = ctx.resolve_session(&files, None)?;
    let name = session
        .name()
        .expect("sync resolves only named sessions")
        .clone();
    let text = files.config_text();
    let blocks = ctx.blocks(&files)?;
    let existing = blocks.iter().find(|b| b.header.session == name.as_str());

    let settings = settings(existing, &args)?;

    let snapshot = ctx.accounts(&session, args.refresh).await?;
    let planned = profiles::plan(&snapshot.items, &settings, &name)?;

    let outside = AwsFiles::parse(
        existing.map_or_else(
            || text.to_owned(),
            |block| managed_block::without(text, block),
        ),
        "",
    )
    .await?;
    let kept = unguarded(planned, &files, &outside);

    // A session `gac setup` created lives in this block and stays in it.
    let mut body = if outside.has_session(name.as_str()) {
        Vec::new()
    } else {
        let mut lines = profiles::render_session(&files.sso_session(&name)?);
        if !kept.is_empty() {
            lines.push(String::new());
        }
        lines
    };
    body.extend(profiles::render_body(
        &kept,
        &name,
        settings.region.as_ref(),
    ));
    let block = managed_block::render(
        &settings.to_header(&name),
        &body,
        managed_block::line_ending(text),
    );
    let updated =
        managed_block::upsert(text, name.as_str(), &block).expect("the markers were scanned above");

    let before = existing
        .map(|b| b.profile_names(text).map(str::to_owned).collect())
        .unwrap_or_default();
    let after: BTreeSet<String> = kept.iter().map(|p| p.name.to_string()).collect();
    let added = after.difference(&before).count();
    let removed = before.difference(&after).count();
    let config_path = ctx.paths.config_file().display().to_string();

    if args.dry_run {
        if updated == text {
            ui::notice(format!(
                "No changes: {} profiles in the `{name}` block.",
                after.len()
            ));
        } else {
            let diff = similar::TextDiff::from_lines(text, &updated)
                .unified_diff()
                .context_radius(3)
                .header(&config_path, &config_path)
                .to_string();
            ui::output(diff).map_err(|err| Error::io("could not write to stdout", err))?;
            ui::notice(format!(
                "Dry run: {added} to add, {removed} to remove. Nothing was written."
            ));
        }
        return Ok(());
    }
    if updated == text {
        ui::notice(format!(
            "Already up to date: {} profiles in the `{name}` block.",
            after.len()
        ));
        return Ok(());
    }
    ctx.write_config(text, &updated).await?;
    ui::notice(format!(
        "Synced {} profiles into the `{name}` block of {config_path} ({added} added, {removed} removed).",
        after.len()
    ));
    Ok(())
}

/// The stored settings (unless `--reset`), overridden by any flags given.
fn settings(existing: Option<&Block>, args: &SyncArgs) -> Result<SyncSettings> {
    let mut settings = match existing {
        Some(block) if !args.reset => SyncSettings::from_header(&block.header)?,
        _ => SyncSettings::default(),
    };
    if let Some(template) = &args.name {
        settings.name = template.parse()?;
    }
    if let Some(region) = &args.region {
        settings.region = Some(region.parse()?);
    }
    if !args.include.is_empty() {
        settings.include.clone_from(&args.include);
    }
    if !args.exclude.is_empty() {
        settings.exclude.clone_from(&args.exclude);
    }
    Ok(settings)
}

/// Drops, with a warning, every profile whose name would create the T5 layout or shadow a
/// profile the user (or another block) owns. `outside` is the config without this block.
fn unguarded(
    planned: Vec<PlannedProfile>,
    files: &AwsFiles,
    outside: &AwsFiles,
) -> Vec<PlannedProfile> {
    let mut kept = Vec::with_capacity(planned.len());
    for profile in planned {
        match guards::sync_conflict(profile.name.as_str(), outside, files) {
            None => kept.push(profile),
            Some(conflict) => ui::warn(format!(
                "skipped profile `{}`: {}",
                profile.name,
                conflict.describe()
            )),
        }
    }
    kept
}
