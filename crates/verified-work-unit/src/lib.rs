// SPDX-License-Identifier: Apache-2.0

//! Work-unit identity v1 (`work-unit-1`, a **draft**).
//!
//! A *work unit* is what may be billed once. This crate answers one question
//! and only that one: **are two claims about the same unit of work?**
//!
//! - A [`Scope`] is the parties' declaration of what counts as one unit: a
//!   line of work, an operation, and the claim inputs that identify a unit.
//! - An [`Identity`] is the unit one claim is about, under a scope, for one
//!   tenant.
//! - A [`Nullifier`] is a keyed digest of an identity. Two claims about the
//!   same unit have the same nullifier under the same key, and someone
//!   without the key cannot tell which unit a nullifier stands for.
//!
//! # What this does not answer
//!
//! - **Whether a package is valid.** That is verification
//!   (`verified-verifier`). Derive an identity only from the inputs of a
//!   claim whose verification you rely on; this crate takes the values it is
//!   given.
//! - **Whether a unit was already accepted, billed or settled.** No offline
//!   computation can. That needs a registry with state and an atomic
//!   first-write-wins rule, which belongs to whoever settles. This crate
//!   holds no state. A valid package for a unit that was already billed is
//!   still a valid package.
//! - **Duplicates across tenants.** Identities and keys are per tenant.
//!
//! # Keys
//!
//! A nullifier is private only from those who do not hold the tenant's key.
//! Whoever holds it can test guesses against any nullifier of that tenant.
//! Rotating a key changes every nullifier, so a registry must compare a new
//! unit under every key the tenant has had; this crate computes under one key
//! at a time and leaves that to the registry.
//!
//! Values are compared exactly: no case folding, trimming or removal of
//! leading zeros. `INV-01001` and `INV-1001` are different units.

use std::fmt;

use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;
use verified_canonical::{Object, Sha256Digest, SigningDomain, Value};

/// The identifier of the identity form this crate implements.
pub const VERSION: &str = "work-unit-1";

const fn domain(prefix: &'static str) -> SigningDomain {
    match SigningDomain::new(prefix) {
        Ok(domain) => domain,
        Err(_) => panic!("a work-unit domain is one line"),
    }
}

// Evaluated at compile time: a malformed prefix does not build.
const NULLIFIER_DOMAIN: SigningDomain = domain("verified:work-unit-nullifier:v1\n");
const KEY_DOMAIN: SigningDomain = domain("verified:work-unit-key:v1\n");

/// Why an identity could not be formed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The scope is not `{ scope, operation, identity }` with text members
    /// and a list of input names.
    #[error(
        "a scope is an object with exactly the text members scope and operation and a list of input names, identity"
    )]
    MalformedScope,
    /// The number of values is not the number of inputs the scope names.
    #[error("the scope names {expected} identifying input(s), and {found} value(s) were given")]
    ValueCount {
        /// How many inputs the scope names.
        expected: usize,
        /// How many values were given.
        found: usize,
    },
    /// The claim does not supply an input the scope names.
    #[error("the claim has no input {0:?}, which the scope names")]
    MissingInput(String),
    /// The claim's inputs are not an object.
    #[error("claim inputs are a JSON object")]
    InputsNotAnObject,
    /// A value is not text or a boolean. Claim inputs are never anything
    /// else: the contract language writes every number as text.
    #[error("the value of identifying input {0} is neither text nor a boolean")]
    UnsupportedValue(usize),
}

/// What counts as one unit of work, as the parties declared it.
///
/// A scope is agreed alongside a contract and is not part of it. It stays
/// the same across versions of the contract, so that a new contract version
/// is not a way to bill the same work again. Two contracts that share a
/// scope share units on purpose.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Scope {
    /// The name of the line of work.
    pub scope: String,
    /// What is done to the objects. Different operations on the same object
    /// are different units.
    pub operation: String,
    /// The claim inputs that identify one unit, in order.
    pub identity: Vec<String>,
}

impl Scope {
    /// Reads `{ "scope", "operation", "identity": [input…] }`, refusing any
    /// missing, extra or mistyped member.
    pub fn from_value(scope: &Value) -> Result<Self, Error> {
        let object = scope
            .as_object()
            .filter(|o| o.has_exactly(&["identity", "operation", "scope"]))
            .ok_or(Error::MalformedScope)?;
        let text = |name| {
            let member = object.get(name).and_then(Value::as_str);
            member.map(str::to_owned).ok_or(Error::MalformedScope)
        };
        let identity = object
            .get("identity")
            .and_then(Value::as_array)
            .ok_or(Error::MalformedScope)?
            .iter()
            .map(|input| {
                input
                    .as_str()
                    .map(str::to_owned)
                    .ok_or(Error::MalformedScope)
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            scope: text("scope")?,
            operation: text("operation")?,
            identity,
        })
    }
}

/// The unit of work one claim is about.
///
/// It is the array `[ "work-unit-1", tenant, scope, operation, [value…] ]`,
/// and its bytes are that array's `verified-json-v1` canonical text. The
/// tenant is part of it: the same invoice number for two tenants is two
/// units.
///
/// An identity is plaintext. Show a [`Nullifier`] where the unit itself
/// should not be disclosed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity(Value);

impl Identity {
    /// The identity of the unit with these identifying values, one per input
    /// the scope names, in the scope's order.
    pub fn new(tenant: &str, scope: &Scope, values: &[Value]) -> Result<Self, Error> {
        if values.len() != scope.identity.len() {
            return Err(Error::ValueCount {
                expected: scope.identity.len(),
                found: values.len(),
            });
        }
        if let Some(index) = values
            .iter()
            .position(|value| !matches!(value, Value::String(_) | Value::Bool(_)))
        {
            return Err(Error::UnsupportedValue(index));
        }
        let text = |s: &str| Value::String(s.to_owned());
        Ok(Self(Value::Array(vec![
            text(VERSION),
            text(tenant),
            text(&scope.scope),
            text(&scope.operation),
            Value::Array(values.to_vec()),
        ])))
    }

    /// The identity of the unit a claim is about: the values of the inputs
    /// the scope names, taken from the claim's inputs.
    ///
    /// `inputs` is a `wvp-0.2` claim's inputs object. Whether those inputs
    /// are the ones a verified package carries is the caller's to ensure.
    pub fn of_claim(tenant: &str, scope: &Scope, inputs: &Value) -> Result<Self, Error> {
        let inputs: &Object = inputs.as_object().ok_or(Error::InputsNotAnObject)?;
        let values = scope
            .identity
            .iter()
            .map(|name| {
                inputs
                    .get(name)
                    .cloned()
                    .ok_or_else(|| Error::MissingInput(name.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(tenant, scope, &values)
    }

    /// The identity's canonical text: what a nullifier is computed over.
    #[must_use]
    pub fn canonical(&self) -> String {
        self.0.to_canonical_string()
    }
}

/// A tenant's secret key for nullifiers: 32 bytes.
///
/// Whoever holds it can compute the nullifier of any guessed unit of that
/// tenant. It is never printed: its `Debug` form shows only its commitment.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    /// Wraps key bytes. Generating and storing keys is the caller's.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The key's commitment: the SHA-256 of the key under its own domain.
    /// It pins a key without revealing it, so that a key cannot be switched
    /// silently. A key's commitment never changes.
    #[must_use]
    pub fn commitment(&self) -> Sha256Digest {
        let mut input = KEY_DOMAIN.as_str().as_bytes().to_vec();
        input.extend_from_slice(&self.0);
        Sha256Digest::of(&input)
    }

    /// The nullifier of a unit under this key: HMAC-SHA-256 over the
    /// nullifier domain followed by the identity's canonical text.
    #[must_use]
    pub fn nullifier(&self, identity: &Identity) -> Nullifier {
        // HMAC accepts a key of any length; 32 bytes cannot be refused.
        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(&self.0) else {
            unreachable!("HMAC-SHA-256 takes a key of any length");
        };
        mac.update(&NULLIFIER_DOMAIN.signing_input(&identity.0));
        Nullifier(mac.finalize().into_bytes().into())
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey(commitment sha-256:{})", self.commitment())
    }
}

/// A keyed digest of a unit's identity.
///
/// Equal nullifiers under the same key mean the same unit. Nullifiers under
/// different keys are unrelated even for the same unit, so a nullifier is
/// only meaningful together with the key it was derived under; store the
/// key's identifier beside it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Nullifier([u8; 32]);

impl Nullifier {
    /// The algorithm name a nullifier is reported with.
    pub const ALGORITHM: &'static str = "hmac-sha-256";

    /// The 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The nullifier as 64 lowercase hexadecimal characters.
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.to_string().split_off(Self::ALGORITHM.len() + 1)
    }

    /// The reported form: `{ "algorithm": "hmac-sha-256", "hex": … }`.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let members = [
            ("algorithm", Self::ALGORITHM.to_owned()),
            ("hex", self.to_hex()),
        ];
        Value::Object(
            members
                .into_iter()
                .map(|(key, value)| (key.to_owned(), Value::String(value)))
                .collect(),
        )
    }
}

impl fmt::Display for Nullifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", Self::ALGORITHM)?;
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

impl fmt::Debug for Nullifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
