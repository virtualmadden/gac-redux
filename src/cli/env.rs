//! `gac env`: print a role's credentials as shell commands, `eval "$(gac env)"`, or as JSON.

use clap::ValueEnum;

use crate::cli::EnvArgs;
use crate::cli::context::Context;
use crate::cli::exec;
use crate::cli::target;
use crate::domain::Region;
use crate::error::Result;
use crate::ui;

/// The variables `--unset` clears: the ones that carry the credentials.
const CREDENTIALS: [&str; 4] = [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_CREDENTIAL_EXPIRATION",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// `export NAME='value'`, for sh, bash and zsh.
    Sh,
    /// `set -gx NAME 'value'`.
    Fish,
    /// `$env:NAME = 'value'`.
    Powershell,
    /// An object of the variables, with `null` for those to unset.
    Json,
}

pub async fn run(ctx: &Context, args: EnvArgs) -> Result<()> {
    let vars: Vec<(&str, Option<String>)> = if args.unset {
        CREDENTIALS.iter().map(|name| (*name, None)).collect()
    } else {
        let region = args
            .region
            .as_deref()
            .map(str::parse::<Region>)
            .transpose()?;
        let files = ctx.files().await?;
        let target =
            target::resolve(ctx, &files, args.profile.as_deref(), args.target.as_deref()).await?;
        let creds = target.credentials(ctx).await?;
        exec::variables(&target, &creds, region.as_ref())
    };
    ui::output(render(args.format, &vars))
}

fn render(format: Format, vars: &[(&str, Option<String>)]) -> String {
    if format == Format::Json {
        let object: serde_json::Map<String, serde_json::Value> = vars
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.clone().into()))
            .collect();
        return ui::json(&object);
    }
    let mut out = String::new();
    for (name, value) in vars {
        let line = match (format, value) {
            (Format::Sh, Some(value)) => format!("export {name}={}", sh_quote(value)),
            (Format::Sh, None) => format!("unset {name}"),
            (Format::Fish, Some(value)) => format!("set -gx {name} {}", fish_quote(value)),
            (Format::Fish, None) => format!("set -e {name}"),
            (Format::Powershell, Some(value)) => {
                format!("$env:{name} = {}", powershell_quote(value))
            }
            (Format::Powershell, None) => {
                format!("Remove-Item -Path Env:{name} -ErrorAction SilentlyContinue")
            }
            (Format::Json, _) => unreachable!("rendered above"),
        };
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// POSIX single quotes: nothing inside is special, and `'` is written as `'\''`.
fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// fish single quotes: only `\` and `'` need a backslash.
fn fish_quote(value: &str) -> String {
    format!("'{}'", value.replace('\\', r"\\").replace('\'', r"\'"))
}

/// PowerShell verbatim strings: `'` is doubled.
fn powershell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars() -> Vec<(&'static str, Option<String>)> {
        vec![
            ("AWS_ACCESS_KEY_ID", Some("ASIAEXAMPLE".into())),
            ("AWS_SECRET_ACCESS_KEY", Some(r"a/b+c=d'e\f".into())),
            ("AWS_PROFILE", None),
        ]
    }

    #[test]
    fn renders_every_format() {
        insta::assert_snapshot!(render(Format::Sh, &vars()), @r#"
        export AWS_ACCESS_KEY_ID='ASIAEXAMPLE'
        export AWS_SECRET_ACCESS_KEY='a/b+c=d'\''e\f'
        unset AWS_PROFILE
        "#);
        insta::assert_snapshot!(render(Format::Fish, &vars()), @r"
        set -gx AWS_ACCESS_KEY_ID 'ASIAEXAMPLE'
        set -gx AWS_SECRET_ACCESS_KEY 'a/b+c=d\'e\\f'
        set -e AWS_PROFILE
        ");
        insta::assert_snapshot!(render(Format::Powershell, &vars()), @r"
        $env:AWS_ACCESS_KEY_ID = 'ASIAEXAMPLE'
        $env:AWS_SECRET_ACCESS_KEY = 'a/b+c=d''e\f'
        Remove-Item -Path Env:AWS_PROFILE -ErrorAction SilentlyContinue
        ");
        insta::assert_snapshot!(render(Format::Json, &vars()), @r#"
        {
          "AWS_ACCESS_KEY_ID": "ASIAEXAMPLE",
          "AWS_PROFILE": null,
          "AWS_SECRET_ACCESS_KEY": "a/b+c=d'e\\f"
        }
        "#);
    }
}
