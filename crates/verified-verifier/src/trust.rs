// SPDX-License-Identifier: Apache-2.0

//! The relying party's trust, ready to verify with.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, VerifyingKey};
use verified_canonical::Value;
use verified_protocol::{RegistryError, TrustRegistry, TrustedKey};

/// The only signature algorithm the protocol uses.
pub(crate) const ED25519: &str = "Ed25519";

/// The DER encoding of an Ed25519 `SubjectPublicKeyInfo` up to the key: a
/// sequence holding the algorithm identifier 1.3.101.112 and a 33-byte bit
/// string with no unused bits. The 32 key bytes follow.
const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// A trust registry whose Ed25519 keys have been decoded.
///
/// Building one is the only way to hand keys to [`crate::verify`], so a
/// registry with unusable key material is found when it is loaded, not in
/// the middle of verifying a package.
#[derive(Clone, Debug)]
pub struct Trust {
    registry: TrustRegistry,
    /// One entry per registry key, in order: the decoded key, or `None` for
    /// an algorithm this verifier does not support.
    decoded: Vec<Option<VerifyingKey>>,
}

/// A registry that cannot be used. A configuration error, never a statement
/// about a package.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TrustError {
    /// The registry is not well formed.
    #[error("{0}")]
    Registry(#[from] RegistryError),
    /// An Ed25519 key's material cannot be used.
    #[error("key {key_id:?}: {problem}")]
    KeyMaterial {
        /// The record's identifier.
        key_id: String,
        /// What is wrong with its `publicKey`.
        problem: &'static str,
    },
    /// Two records hold the same Ed25519 key under different encodings.
    #[error("keys {0:?} and {1:?} hold the same public key")]
    DuplicateKey(String, String),
}

fn decode(key: &TrustedKey) -> Result<VerifyingKey, TrustError> {
    let fail = |problem| TrustError::KeyMaterial {
        key_id: key.key_id.clone(),
        problem,
    };
    let der = STANDARD
        .decode(&key.public_key)
        .map_err(|_| fail("publicKey is not standard base64"))?;
    let bytes: [u8; 32] = der
        .strip_prefix(&SPKI_PREFIX)
        .and_then(|rest| rest.try_into().ok())
        .ok_or_else(|| fail("publicKey is not the DER SubjectPublicKeyInfo of an Ed25519 key"))?;
    let decoded = VerifyingKey::from_bytes(&bytes)
        .map_err(|_| fail("publicKey is not a point on the curve"))?;
    if decoded.is_weak() {
        return Err(fail(
            "publicKey is a small-order point, which verifies forged signatures",
        ));
    }
    Ok(decoded)
}

impl Trust {
    /// Decodes a registry's keys.
    ///
    /// A key whose algorithm is not `Ed25519` is kept undecoded: a statement
    /// naming it is refused as `UNSUPPORTED_ALGORITHM`.
    pub fn new(registry: TrustRegistry) -> Result<Self, TrustError> {
        let mut decoded: Vec<Option<VerifyingKey>> = Vec::with_capacity(registry.keys().len());
        for (i, key) in registry.keys().iter().enumerate() {
            let material = (key.algorithm == ED25519)
                .then(|| decode(key))
                .transpose()?;
            if let Some(material) = &material
                && let Some(j) = decoded.iter().position(|d| d.as_ref() == Some(material))
            {
                return Err(TrustError::DuplicateKey(
                    registry.keys()[j].key_id.clone(),
                    registry.keys()[i].key_id.clone(),
                ));
            }
            decoded.push(material);
        }
        Ok(Self { registry, decoded })
    }

    /// Reads and decodes a registry: `{ "keys": [ … ] }`.
    pub fn from_value(registry: &Value) -> Result<Self, TrustError> {
        Self::new(TrustRegistry::from_value(registry)?)
    }

    /// The registry this was built from.
    #[must_use]
    pub fn registry(&self) -> &TrustRegistry {
        &self.registry
    }

    /// The key with this identifier, with its decoded material if its
    /// algorithm is supported.
    pub(crate) fn find(&self, key_id: &str) -> Option<(&TrustedKey, Option<&VerifyingKey>)> {
        let i = self
            .registry
            .keys()
            .iter()
            .position(|k| k.key_id == key_id)?;
        Some((&self.registry.keys()[i], self.decoded[i].as_ref()))
    }
}

/// Whether `encoded` (standard base64 of a 64-byte signature) is `key`'s
/// signature over `message`.
///
/// Verification is strict: a signature with a non-canonical encoding, or one
/// that only a small-order component makes valid, does not verify.
pub(crate) fn verifies(key: &VerifyingKey, message: &[u8], encoded: &str) -> bool {
    STANDARD
        .decode(encoded)
        .ok()
        .and_then(|bytes| Signature::from_slice(&bytes).ok())
        .is_some_and(|signature| key.verify_strict(message, &signature).is_ok())
}
