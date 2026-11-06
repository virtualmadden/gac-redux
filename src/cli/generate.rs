//! `gac completions` and the hidden `gac man`: files generated from the clap definitions. They
//! read no AWS files, so they work on a machine that has none.

use std::io::Write as _;
use std::path::Path;

use clap::CommandFactory;
use roff::{Roff, bold, roman};

use crate::cli::{Cli, CompletionsArgs, ManArgs};
use crate::error::{Error, Result};
use crate::ui;

const BIN: &str = "gac";

pub fn completions(args: &CompletionsArgs) -> Result<()> {
    let mut script = Vec::new();
    clap_complete::generate(args.shell, &mut Cli::command(), BIN, &mut script);
    let script = String::from_utf8(script).expect("completion scripts are UTF-8");
    ui::output(script).map_err(|err| Error::io("could not write to stdout", err))
}

/// Writes `gac.1` and one `gac-COMMAND.1` per visible command into the directory.
pub fn man(args: &ManArgs) -> Result<()> {
    let dir = &args.dir;
    std::fs::create_dir_all(dir).map_err(|err| Error::io_at("create", dir, err))?;
    let mut cmd = Cli::command().name(BIN).disable_help_subcommand(true);
    cmd.build();
    write_pages(&cmd, dir)
}

fn write_pages(cmd: &clap::Command, dir: &Path) -> Result<()> {
    for sub in cmd.get_subcommands().filter(|s| !s.is_hide_set()) {
        write_pages(sub, dir)?;
    }
    let page = clap_mangen::Man::new(cmd.clone())
        .source(format!("gac-redux {}", env!("CARGO_PKG_VERSION")))
        .manual("gac-redux manual");
    let path = dir.join(page.get_filename());
    let mut roff = Vec::new();
    let rendered = if cmd.get_name() == BIN {
        page.render_title(&mut roff)
            .and_then(|()| page.render_name_section(&mut roff))
            .and_then(|()| page.render_synopsis_section(&mut roff))
            .and_then(|()| page.render_description_section(&mut roff))
            .and_then(|()| page.render_options_section(&mut roff))
            .and_then(|()| page.render_subcommands_section(&mut roff))
            .and_then(|()| roff.write_all(reference().render().as_bytes()))
    } else {
        page.render(&mut roff)
    };
    rendered.map_err(|err| Error::io_at("render", &path, err))?;
    std::fs::write(&path, roff).map_err(|err| Error::io_at("write", &path, err))
}

/// The sections of `gac.1` that clap knows nothing about.
fn reference() -> Roff {
    let mut page = Roff::new();
    let mut section = |title: &str, items: &[(&str, &str)]| {
        page.control("SH", [title]);
        for (term, text) in items {
            page.control("TP", [])
                .text([bold(*term)])
                .text([roman(*text)]);
        }
    };
    section(
        "ENVIRONMENT",
        &[
            (
                "GAC_REDUX_SESSION",
                "The [sso-session] to use when --session is not given.",
            ),
            (
                "GAC_REDUX_LOG",
                "A tracing filter that replaces the one -v and -vv set.",
            ),
            (
                "AWS_CONFIG_FILE",
                "The AWS config file, ~/.aws/config by default.",
            ),
            (
                "AWS_SHARED_CREDENTIALS_FILE",
                "The AWS credentials file, ~/.aws/credentials by default.",
            ),
            (
                "AWS_ENDPOINT_URL_SSO, AWS_ENDPOINT_URL_SSO_OIDC",
                "Override the Identity Center endpoints, as in the AWS SDKs.",
            ),
            ("NO_COLOR", "Turns off colored output."),
        ],
    );
    section(
        "FILES",
        &[
            (
                "~/.aws/config",
                "gac writes only its own blocks, marked # BEGIN gac-redux and # END gac-redux, and a [default] section you handed over with gac select.",
            ),
            ("~/.aws/credentials", "Read, never written."),
            (
                "~/.aws/sso/cache/",
                "The token cache gac shares with the AWS CLI and SDKs.",
            ),
            (
                "~/.aws/gac-redux/",
                "gac's own state: the account inventory cache and the lock for writing the config file.",
            ),
        ],
    );
    section(
        "EXIT STATUS",
        &[
            ("0", "Success."),
            ("1", "An error."),
            ("2", "A usage error."),
            (
                "3",
                "A login is required; the message says which gac login to run.",
            ),
            ("130", "Interrupted."),
        ],
    );
    section(
        "SEE ALSO",
        &[(
            "https://github.com/virtualmadden/gac-redux",
            "The README, with a quick start.",
        )],
    );
    page
}
