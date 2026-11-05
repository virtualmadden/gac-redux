//! Interactive prompts. `inquire` draws on stderr, so stdout stays clean.

use inquire::validator::Validation;
use inquire::{InquireError, Text};

use crate::error::{Error, Result};

/// Asks for one line of text, re-asking until `validate` accepts it.
pub fn text(
    message: &str,
    default: Option<&str>,
    help: Option<&str>,
    validate: impl Fn(&str) -> std::result::Result<(), String> + Clone + 'static,
) -> Result<String> {
    let mut prompt = Text::new(message).with_validator(move |input: &str| {
        Ok(match validate(input.trim()) {
            Ok(()) => Validation::Valid,
            Err(reason) => Validation::Invalid(reason.into()),
        })
    });
    if let Some(default) = default {
        prompt = prompt.with_default(default);
    }
    if let Some(help) = help {
        prompt = prompt.with_help_message(help);
    }
    match prompt.prompt() {
        Ok(answer) => Ok(answer.trim().to_owned()),
        Err(InquireError::OperationInterrupted | InquireError::OperationCanceled) => {
            Err(Error::Interrupted)
        }
        Err(err) => Err(Error::io(
            "the prompt failed",
            std::io::Error::other(err.to_string()),
        )),
    }
}
