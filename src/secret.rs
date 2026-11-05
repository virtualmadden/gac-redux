//! Secret handling. Secrets are typed as [`SecretString`]: `Debug` prints a redaction marker and
//! the memory is zeroized on drop. Nothing here knows about AWS.

pub use secrecy::{ExposeSecret, SecretString};

/// A loggable description of a secret: its length, never its content.
pub fn shape(secret: &SecretString) -> String {
    format!(
        "<redacted, {} chars>",
        secret.expose_secret().chars().count()
    )
}

/// `serde` support for a required secret field. Serializing is the one deliberate exposure: it
/// happens only when writing a private cache file.
pub mod serde_required {
    use super::{ExposeSecret, SecretString};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        secret: &SecretString,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(secret.expose_secret())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<SecretString, D::Error> {
        String::deserialize(deserializer).map(SecretString::from)
    }
}

/// `serde` support for an optional secret field.
pub mod serde_optional {
    use super::{ExposeSecret, SecretString};
    use serde::{Deserialize, Deserializer, Serializer};

    #[allow(clippy::ref_option)] // the signature serde's `with` expects
    pub fn serialize<S: Serializer>(
        secret: &Option<SecretString>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match secret {
            Some(secret) => serializer.serialize_some(secret.expose_secret()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<SecretString>, D::Error> {
        Option::<String>::deserialize(deserializer).map(|value| value.map(SecretString::from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_shape_never_show_the_value() {
        let secret = SecretString::from("FAKE-SECRET-VALUE");
        assert!(!format!("{secret:?}").contains("FAKE-SECRET-VALUE"));
        assert_eq!(shape(&secret), "<redacted, 17 chars>");
    }
}
