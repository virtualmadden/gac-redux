//! Terminal interaction. stdout carries only the data a command was asked for; prompts, URLs,
//! notices and progress go to stderr. Nothing here knows about AWS.

pub mod browser;
pub mod prompt;

use std::io::{self, IsTerminal, Write};

/// Whether prompts are allowed: both stdin and stderr are terminals and `--no-input` is off.
pub fn can_prompt(no_input: bool) -> bool {
    !no_input && io::stdin().is_terminal() && io::stderr().is_terminal()
}

/// A line for the person at the terminal.
pub fn notice(message: impl AsRef<str>) {
    let _ = writeln!(io::stderr().lock(), "{}", message.as_ref());
}

/// A warning for the person at the terminal.
pub fn warn(message: impl AsRef<str>) {
    let _ = writeln!(io::stderr().lock(), "warning: {}", message.as_ref());
}

/// Writes requested data to stdout. A closed pipe (`gac list | head`) is not an error.
pub fn output(text: impl AsRef<str>) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    match stdout
        .write_all(text.as_ref().as_bytes())
        .and_then(|()| stdout.flush())
    {
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        other => other,
    }
}
