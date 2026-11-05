//! PKCE (RFC 7636) with the S256 method, and the `state` value that binds a callback to its
//! request.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use crate::secret::{ExposeSecret, SecretString};

/// RFC 7636 unreserved characters.
const VERIFIER_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

#[derive(Debug)]
pub struct Pkce {
    pub verifier: SecretString,
    pub challenge: String,
}

impl Pkce {
    /// A fresh pair: a 64-character verifier, as the AWS CLI uses.
    pub fn generate() -> Self {
        let verifier: String = (0..64)
            .map(|_| char::from(VERIFIER_CHARS[rand::random_range(0..VERIFIER_CHARS.len())]))
            .collect();
        Self::from_verifier(verifier.into())
    }

    pub fn from_verifier(verifier: SecretString) -> Self {
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.expose_secret().as_bytes()));
        Self {
            verifier,
            challenge,
        }
    }
}

/// An unguessable `state` value.
pub fn random_state() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_is_unpadded_base64url_sha256() {
        // python3 -c 'import base64,hashlib; print(base64.urlsafe_b64encode(hashlib.sha256(
        //   b"dBjftJeZ4CVP-mJ92K9qpgUdAJXN6OGxH7N0Bmx3yTw").digest()).rstrip(b"="))'
        let pkce = Pkce::from_verifier("dBjftJeZ4CVP-mJ92K9qpgUdAJXN6OGxH7N0Bmx3yTw".into());
        assert_eq!(
            pkce.challenge,
            "Vj5UXpwG2MrVbCkfM-sGy4J83UDfdcJNwl6zTuAqPPs"
        );
    }

    #[test]
    fn generates_unreserved_verifiers_and_distinct_states() {
        let pkce = Pkce::generate();
        let verifier = pkce.verifier.expose_secret();
        assert_eq!(verifier.len(), 64);
        assert!(verifier.bytes().all(|b| VERIFIER_CHARS.contains(&b)));
        assert_eq!(pkce.challenge.len(), 43);
        assert_ne!(random_state(), random_state());
    }
}
