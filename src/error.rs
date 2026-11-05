//! The library error type. Each kind maps to one process exit code.

use std::io;
use std::path::Path;

use aws_sdk_ssooidc::error::{DisplayErrorContext, ProvideErrorMetadata, SdkError};

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Exit codes shared by every command.
pub mod exit {
    pub const ERROR: u8 = 1;
    pub const USAGE: u8 = 2;
    pub const LOGIN_REQUIRED: u8 = 3;
    pub const INTERRUPTED: u8 = 130;
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The command line or the environment does not say enough to proceed.
    #[error("{message}")]
    Usage {
        message: String,
        hint: Option<String>,
    },

    /// No usable SSO token: the user has to log in.
    #[error("not logged in to {target}: {reason}")]
    LoginRequired {
        /// What needs a login, such as "session `corp`".
        target: String,
        /// The `gac login` arguments that fix it, such as `--session corp`.
        login_args: String,
        reason: String,
    },

    #[error("interrupted")]
    Interrupted,

    /// AWS configuration that gac cannot use as it stands.
    #[error("{message}")]
    Config {
        message: String,
        hint: Option<String>,
    },

    /// A login flow that did not complete.
    #[error("{message}")]
    Login {
        message: String,
        hint: Option<String>,
    },

    #[error("{operation} failed: {message}")]
    Service {
        operation: &'static str,
        message: String,
    },

    #[error("{context}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },
}

impl Error {
    pub fn usage(message: impl Into<String>) -> Self {
        Self::Usage {
            message: message.into(),
            hint: None,
        }
    }

    pub fn config(message: impl Into<String>) -> Self {
        Self::Config {
            message: message.into(),
            hint: None,
        }
    }

    pub fn login(message: impl Into<String>) -> Self {
        Self::Login {
            message: message.into(),
            hint: None,
        }
    }

    pub fn io(context: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    pub fn io_at(action: &str, path: &Path, source: io::Error) -> Self {
        Self::io(format!("could not {action} {}", path.display()), source)
    }

    /// Attaches a `help:` hint. Kinds without a hint slot are returned unchanged.
    #[must_use]
    pub fn with_hint(mut self, text: impl Into<String>) -> Self {
        match &mut self {
            Self::Usage { hint, .. } | Self::Config { hint, .. } | Self::Login { hint, .. } => {
                *hint = Some(text.into());
            }
            _ => {}
        }
        self
    }

    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Usage { .. } => exit::USAGE,
            Self::LoginRequired { .. } => exit::LOGIN_REQUIRED,
            Self::Interrupted => exit::INTERRUPTED,
            _ => exit::ERROR,
        }
    }

    pub fn hint(&self) -> Option<String> {
        match self {
            Self::Usage { hint, .. } | Self::Config { hint, .. } | Self::Login { hint, .. } => {
                hint.clone()
            }
            Self::LoginRequired { login_args, .. } => Some(format!("run `gac login {login_args}`")),
            _ => None,
        }
    }
}

/// Converts an SDK error into [`Error::Service`], keeping the service's error code and message.
pub(crate) fn service<E, R>(operation: &'static str, err: &SdkError<E, R>) -> Error
where
    E: ProvideErrorMetadata + std::error::Error + 'static,
    R: std::fmt::Debug,
{
    let message = match (err.code(), err.message()) {
        (Some(code), Some(message)) => format!("{code}: {message}"),
        (Some(code), None) => code.to_owned(),
        _ => DisplayErrorContext(err).to_string(),
    };
    Error::Service { operation, message }
}
