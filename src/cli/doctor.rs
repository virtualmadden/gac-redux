//! `gac doctor`: read-only checks with a suggested fix for each.

use jiff::Timestamp;

use crate::cli::DoctorArgs;
use crate::cli::context::Context;
use crate::doctor::aws::{self, Inputs};
use crate::error::{Error, Result};
use crate::ui;

pub async fn run(ctx: &Context, args: DoctorArgs) -> Result<()> {
    let files = ctx.files().await;
    let report = aws::run(&Inputs {
        paths: &ctx.paths,
        files: files.as_ref().map_err(ToString::to_string),
        home_var: std::env::var_os("HOME"),
        userprofile_var: std::env::var_os("USERPROFILE"),
        now: Timestamp::now(),
    });
    let text = if args.json {
        let mut json =
            serde_json::to_string_pretty(&report).expect("serializing plain data cannot fail");
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
