//! Trust registries: the keys a relying party accepts.
//!
//! A registry is the verifier's configuration. It is supplied by the relying
//! party and is never taken from a package: a key a package carries proves
//! nothing about who holds it.

use verified_canonical::Value;

use crate::container::{ShapeError, ShapeProblem};
use crate::shape::{self, At, Shape};
use crate::time::Instant;

/// A public key the relying party trusts for one issuer in one tenant, for a
/// bounded period, and only for statements about the listed source systems.
///
/// The source list is the issuer's authority: a key authorized only for an
/// agent's own runtime cannot sign an observation of another system,
/// whatever the statement is labelled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedKey {
    /// An opaque identifier naming this record.
    pub key_id: String,
    /// The key's algorithm, as stated.
    pub algorithm: String,
    /// The key material, as stated: base64 of a DER `SubjectPublicKeyInfo`.
    pub public_key: String,
    /// The actor the key belongs to (a UUID).
    pub issuer: String,
    /// The tenant the key is trusted for.
    pub tenant: String,
    /// The source systems the issuer may speak for.
    pub sources: Vec<String>,
    /// The first instant the key is valid at.
    pub valid_from: Instant,
    /// The first instant it is no longer valid at, if any.
    pub valid_until: Option<Instant>,
    /// When the key was revoked, if it was.
    pub revoked_at: Option<Instant>,
}

impl TrustedKey {
    /// Whether the key was valid at `at`.
    ///
    /// Asserted times are not authenticated: a holder of a revoked key can
    /// backdate a statement into the key's validity period. Freshness needs
    /// an external timestamp or witness, which this protocol does not have.
    #[must_use]
    pub fn valid_at(&self, at: Instant) -> bool {
        self.valid_from <= at
            && self.valid_until.is_none_or(|until| at < until)
            && self.revoked_at.is_none_or(|revoked| at < revoked)
    }

    /// Whether the key may sign for `source`.
    #[must_use]
    pub fn speaks_for(&self, source: &str) -> bool {
        self.sources.iter().any(|s| s == source)
    }
}

/// The relying party's trust anchors.
///
/// A registry holds each key identifier and each public key at most once: an
/// alias would let another identifier verify the same signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustRegistry {
    keys: Vec<TrustedKey>,
}

/// A registry that cannot be used. This is a configuration error, never a
/// statement about a package.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    /// The registry does not have the registry's shape.
    #[error("{0}")]
    Shape(#[from] ShapeError),
    /// Two records share a key identifier.
    #[error("key identifier {0:?} occurs more than once")]
    DuplicateKeyId(String),
    /// Two records hold the same key material.
    #[error("keys {0:?} and {1:?} hold the same public key")]
    DuplicatePublicKey(String, String),
}

impl TrustRegistry {
    /// Reads `{ "keys": [ … ] }`.
    ///
    /// Every member must be one the registry defines: a misspelt member, such
    /// as a revocation time under another name, is refused rather than
    /// dropped. `validUntil` and `revokedAt` may be `null` or absent.
    pub fn from_value(registry: &Value) -> Result<Self, RegistryError> {
        let at = At::root("registry");
        let root = shape::object(registry, &at, &["keys"])?;
        let keys = shape::each(shape::get(root, "keys"), &at.member("keys"), read_key)?;
        for (i, key) in keys.iter().enumerate() {
            for earlier in &keys[..i] {
                if earlier.key_id == key.key_id {
                    return Err(RegistryError::DuplicateKeyId(key.key_id.clone()));
                }
                if earlier.public_key == key.public_key {
                    return Err(RegistryError::DuplicatePublicKey(
                        earlier.key_id.clone(),
                        key.key_id.clone(),
                    ));
                }
            }
        }
        Ok(Self { keys })
    }

    /// The key with this identifier.
    #[must_use]
    pub fn find(&self, key_id: &str) -> Option<&TrustedKey> {
        self.keys.iter().find(|key| key.key_id == key_id)
    }

    /// Every key, in the registry's order.
    #[must_use]
    pub fn keys(&self) -> &[TrustedKey] {
        &self.keys
    }
}

const REQUIRED: [&str; 7] = [
    "algorithm",
    "issuer",
    "keyId",
    "publicKey",
    "sources",
    "tenant",
    "validFrom",
];
const OPTIONAL: [&str; 2] = ["revokedAt", "validUntil"];
const MEMBERS: &[&str] = &[
    "algorithm",
    "issuer",
    "keyId",
    "publicKey",
    "revokedAt",
    "sources",
    "tenant",
    "validFrom",
    "validUntil",
];

fn read_key(value: &Value, at: &At<'_>) -> Shape<TrustedKey> {
    let Some(o) = value.as_object() else {
        return at.fail(ShapeProblem::NotAnObject);
    };
    let known = |name: &str| REQUIRED.contains(&name) || OPTIONAL.contains(&name);
    if !o.keys().all(known) || !REQUIRED.iter().all(|name| o.get(name).is_some()) {
        return at.fail(ShapeProblem::Members(MEMBERS));
    }
    let member = |name| shape::get(o, name);
    let text = |name| shape::text(member(name), &at.member(name)).map(str::to_owned);
    let optional_time = |name| shape::nullable(member(name), &at.member(name), shape::instant);
    Ok(TrustedKey {
        key_id: text("keyId")?,
        algorithm: text("algorithm")?,
        public_key: text("publicKey")?,
        issuer: shape::uuid(member("issuer"), &at.member("issuer"))?.to_owned(),
        tenant: shape::wrapped(member("tenant"), &at.member("tenant"))?.to_owned(),
        sources: shape::each(member("sources"), &at.member("sources"), |source, at| {
            shape::text(source, at).map(str::to_owned)
        })?,
        valid_from: shape::instant(member("validFrom"), &at.member("validFrom"))?,
        valid_until: optional_time("validUntil")?,
        revoked_at: optional_time("revokedAt")?,
    })
}

#[cfg(test)]
mod tests {
    use verified_canonical::{Limits, parse};

    use super::*;

    fn key(id: &str, material: &str, extra: &str) -> String {
        format!(
            r#"{{"algorithm":"Ed25519","issuer":{{"value":"00000000-0000-4000-8000-000000000111"}},
               "keyId":"{id}","publicKey":"{material}","sources":["erp"],
               "tenant":{{"value":"tenant-a"}},"validFrom":{{"value":"2026-01-01T00:00:00Z"}}{extra}}}"#
        )
    }

    fn registry(keys: &[String]) -> Result<TrustRegistry, RegistryError> {
        let json = format!(r#"{{"keys":[{}]}}"#, keys.join(","));
        TrustRegistry::from_value(&parse(json.as_bytes(), &Limits::DEFAULT).expect("test JSON"))
    }

    fn at(text: &str) -> Instant {
        Instant::parse(text).expect("test instant")
    }

    #[test]
    fn reads_keys_and_finds_them_by_identifier() {
        let registry = registry(&[key("a", "AAAA", ""), key("b", "BBBB", "")]).expect("valid");
        assert_eq!(registry.keys().len(), 2);
        let a = registry.find("a").expect("present");
        assert!(a.speaks_for("erp"));
        assert!(!a.speaks_for("wvp-decision"));
        assert_eq!(a.valid_until, None);
        assert!(registry.find("c").is_none());
    }

    #[test]
    fn validity_is_from_inclusive_until_exclusive_and_before_revocation() {
        let extra = r#","validUntil":{"value":"2027-01-01T00:00:00Z"},"revokedAt":{"value":"2026-06-01T00:00:00Z"}"#;
        let registry = registry(&[key("a", "AAAA", extra)]).expect("valid");
        let key = registry.find("a").expect("present");
        assert!(!key.valid_at(at("2025-12-31T23:59:59.999999999Z")));
        assert!(key.valid_at(at("2026-01-01T00:00:00Z")));
        assert!(key.valid_at(at("2026-05-31T23:59:59Z")));
        assert!(!key.valid_at(at("2026-06-01T00:00:00Z")));
        assert!(!key.valid_at(at("2027-01-01T00:00:00Z")));
    }

    #[test]
    fn refuses_aliases() {
        assert_eq!(
            registry(&[key("a", "AAAA", ""), key("a", "BBBB", "")]),
            Err(RegistryError::DuplicateKeyId("a".into()))
        );
        assert_eq!(
            registry(&[key("a", "AAAA", ""), key("b", "AAAA", "")]),
            Err(RegistryError::DuplicatePublicKey("a".into(), "b".into()))
        );
    }

    #[test]
    fn refuses_a_misspelt_member_rather_than_dropping_it() {
        let misspelt = r#","revokedAT":{"value":"2026-06-01T00:00:00Z"}"#;
        assert!(matches!(
            registry(&[key("a", "AAAA", misspelt)]),
            Err(RegistryError::Shape(_))
        ));
        let not_canonical = r#","revokedAt":{"value":"2026-06-01"}"#;
        assert!(matches!(
            registry(&[key("a", "AAAA", not_canonical)]),
            Err(RegistryError::Shape(_))
        ));
    }
}
