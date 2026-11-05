use std::fmt;
use std::process::ExitCode;

fn main() -> ExitCode {
    match gac::run(std::env::args_os()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let code = err.exit_code();
            eprintln!("{:?}", miette::Report::new(Diagnostic(err)));
            ExitCode::from(code)
        }
    }
}

/// Renders a library error with its `help:` hint.
#[derive(Debug)]
struct Diagnostic(gac::Error);

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for Diagnostic {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        std::error::Error::source(&self.0)
    }
}

impl miette::Diagnostic for Diagnostic {
    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        self.0
            .hint()
            .map(|hint| Box::new(hint) as Box<dyn fmt::Display>)
    }
}
