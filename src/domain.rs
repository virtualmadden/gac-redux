//! Newtypes parsed once at the boundary, so the rest of the code can trust them.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::Error;

/// The characters the Rust SDK accepts in a profile name (`[A-Za-z0-9_\-/.%@:+]`).
/// Sections named outside this set are ignored by the SDK with only a warning.
pub fn is_sdk_identifier_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '/' | '.' | '%' | '@' | ':' | '+')
}

fn is_sdk_identifier(s: &str) -> bool {
    !s.is_empty() && s.chars().all(is_sdk_identifier_char)
}

macro_rules! string_newtype {
    ($name:ident) => {
        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = Error;

            fn try_from(value: String) -> Result<Self, Error> {
                value.parse()
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> String {
                value.0
            }
        }
    };
}

/// The name of an `[sso-session NAME]` section.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SessionName(String);
string_newtype!(SessionName);

impl FromStr for SessionName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        if is_sdk_identifier(s) {
            Ok(Self(s.to_owned()))
        } else {
            Err(Error::usage(format!(
                "invalid session name `{s}`: use letters, digits and _-/.%@:+"
            )))
        }
    }
}

/// A 12-digit AWS account id.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AccountId(String);
string_newtype!(AccountId);

impl FromStr for AccountId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        if s.len() == 12 && s.bytes().all(|b| b.is_ascii_digit()) {
            Ok(Self(s.to_owned()))
        } else {
            Err(Error::usage(format!(
                "invalid account id `{s}`: expected 12 digits"
            )))
        }
    }
}

/// An IAM Identity Center permission set name, as the portal returns it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RoleName(String);
string_newtype!(RoleName);

impl FromStr for RoleName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        if s.is_empty() || s.chars().any(|c| c.is_whitespace() || c.is_control()) {
            Err(Error::usage(format!("invalid role name `{s}`")))
        } else {
            Ok(Self(s.to_owned()))
        }
    }
}

/// An access portal start URL. Only `https` is accepted, as the AWS CLI requires.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct StartUrl(String);
string_newtype!(StartUrl);

impl FromStr for StartUrl {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let invalid = || {
            Error::usage(format!("invalid start URL `{s}`"))
                .with_hint("expected https://<your-portal>.awsapps.com/start")
        };
        let url = url::Url::parse(s).map_err(|_| invalid())?;
        if url.scheme() != "https" || url.host_str().is_none_or(str::is_empty) {
            return Err(invalid());
        }
        // Keep the user's spelling: the AWS CLI compares and hashes the string as written.
        Ok(Self(s.to_owned()))
    }
}

/// An AWS region code such as `us-east-1`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Region(String);
string_newtype!(Region);

impl FromStr for Region {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let valid = !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !s.starts_with('-')
            && !s.ends_with('-');
        if valid {
            Ok(Self(s.to_owned()))
        } else {
            Err(Error::usage(format!("invalid region `{s}`")))
        }
    }
}

/// A profile name that the AWS CLI and every SDK will accept.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProfileName(String);
string_newtype!(ProfileName);

impl FromStr for ProfileName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        if is_sdk_identifier(s) {
            Ok(Self(s.to_owned()))
        } else {
            Err(Error::usage(format!(
                "invalid profile name `{s}`: the AWS SDKs accept only letters, digits and _-/.%@:+"
            )))
        }
    }
}

/// Splits an `sso_registration_scopes` value. The AWS CLI separates scopes with commas.
pub fn parse_scopes(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_names_follow_the_sdk_identifier_set() {
        assert!("corp".parse::<SessionName>().is_ok());
        assert!("my-org/prod:1".parse::<SessionName>().is_ok());
        assert!("".parse::<SessionName>().is_err());
        assert!("has space".parse::<SessionName>().is_err());
        assert!("brack]et".parse::<SessionName>().is_err());
    }

    #[test]
    fn account_ids_are_twelve_digits() {
        assert!("111122223333".parse::<AccountId>().is_ok());
        assert!("11112222333".parse::<AccountId>().is_err());
        assert!("11112222333x".parse::<AccountId>().is_err());
    }

    #[test]
    fn start_urls_must_be_https() {
        assert!("https://my.awsapps.com/start".parse::<StartUrl>().is_ok());
        assert!("http://my.awsapps.com/start".parse::<StartUrl>().is_err());
        assert!("my.awsapps.com/start".parse::<StartUrl>().is_err());
        let url: StartUrl = "https://My.awsapps.com/start/".parse().unwrap();
        assert_eq!(url.as_str(), "https://My.awsapps.com/start/");
    }

    #[test]
    fn regions_are_lowercase_codes() {
        assert!("us-east-1".parse::<Region>().is_ok());
        assert!("US-EAST-1".parse::<Region>().is_err());
        assert!("-us".parse::<Region>().is_err());
    }

    #[test]
    fn profile_names_reject_characters_the_sdk_ignores() {
        assert!(
            "payments-prod/AdministratorAccess"
                .parse::<ProfileName>()
                .is_ok()
        );
        assert!("a b".parse::<ProfileName>().is_err());
        assert!("a=b".parse::<ProfileName>().is_err());
        assert!("a,b".parse::<ProfileName>().is_err());
    }

    #[test]
    fn scopes_split_on_commas() {
        assert_eq!(
            parse_scopes("sso:account:access, codewhisperer:completions"),
            ["sso:account:access", "codewhisperer:completions"]
        );
        assert_eq!(parse_scopes(" , "), Vec::<String>::new());
    }
}
