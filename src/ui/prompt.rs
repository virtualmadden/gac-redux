//! Interactive prompts. `inquire` draws on stderr, so stdout stays clean.

use inquire::list_option::ListOption;
use inquire::validator::Validation;
use inquire::{InquireError, Select, Text};

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
    prompt
        .prompt()
        .map(|answer| answer.trim().to_owned())
        .map_err(prompt_error)
}

/// Asks for one of `options` with the arrow keys, starting on `cursor`, and returns its index.
/// The answer is echoed as its entry in `answers`, which is shorter than the full row.
pub fn select(
    message: &str,
    options: Vec<String>,
    answers: &[&str],
    cursor: usize,
    help: &str,
) -> Result<usize> {
    let answer = |choice: ListOption<&String>| answers[choice.index].to_owned();
    Select::new(message, options)
        .with_starting_cursor(cursor)
        .with_help_message(help)
        .with_formatter(&answer)
        .raw_prompt()
        .map(|choice| choice.index)
        .map_err(prompt_error)
}

fn prompt_error(err: InquireError) -> Error {
    match err {
        InquireError::OperationInterrupted | InquireError::OperationCanceled => Error::Interrupted,
        err => Error::io("the prompt failed", std::io::Error::other(err.to_string())),
    }
}
