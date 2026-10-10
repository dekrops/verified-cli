// SPDX-License-Identifier: Apache-2.0

//! The unit of a registered claim (claim registration v1, a **draft**).
//!
//! A registered claim carries the nullifier of its work unit, under a key
//! the two parties share and their agreement pins. A registry compares
//! units without learning what a claim is about. Whoever holds the key and
//! the claim's input values can check that the unit really is the one of
//! those inputs: [`check_registered_unit`].
//!
//! # What this does not do
//!
//! **No signature is verified.** The check assumes a registration that was
//! already verified (`verified_verifier::registration`). On its own it says
//! only that four pieces of text fit together.
//!
//! The key is a secret of the two parties. This crate takes it as an
//! argument and never stores or prints it.

use std::fmt;

use verified_canonical::{Limits, Value, parse_canonical};
use verified_protocol::registration::{NULLIFIER_ALGORITHM, SignedAgreement, SignedClaim};

use crate::{Error, Identity, Scope, SecretKey};

/// The code of a refused unit check. Stable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UnitCheckCode {
    /// The agreement, the claim or the inputs are not well formed and
    /// canonical, or the key is not 32 bytes in lowercase hexadecimal.
    Malformed,
    /// The claim names another agreement.
    AgreementMismatch,
    /// The key is not the one the agreement pins.
    UnitKeyMismatch,
    /// The inputs are not those the claim committed to.
    InputsMismatch,
    /// The inputs lack an identifying input the agreement's scope names.
    MissingInput,
    /// The claim's unit is not the nullifier of its identifying inputs.
    UnitMismatch,
}

impl UnitCheckCode {
    /// The protocol's spelling of the code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "MALFORMED",
            Self::AgreementMismatch => "AGREEMENT_MISMATCH",
            Self::UnitKeyMismatch => "UNIT_KEY_MISMATCH",
            Self::InputsMismatch => "INPUTS_MISMATCH",
            Self::MissingInput => "MISSING_INPUT",
            Self::UnitMismatch => "UNIT_MISMATCH",
        }
    }
}

impl fmt::Display for UnitCheckCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a unit check was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {detail}")]
pub struct UnitRefusal {
    /// The protocol's code for the failed check. Stable.
    pub code: UnitCheckCode,
    /// A description for people. Not stable; do not match on it. It never
    /// contains the key or an input value.
    pub detail: String,
}

fn refuse<T>(code: UnitCheckCode, detail: impl Into<String>) -> Result<T, UnitRefusal> {
    Err(UnitRefusal {
        code,
        detail: detail.into(),
    })
}

fn canonical(text: &[u8], what: &str) -> Result<Value, UnitRefusal> {
    parse_canonical(text, &Limits::DEFAULT)
        .or_else(|e| refuse(UnitCheckCode::Malformed, format!("the {what}: {e}")))
}

/// 32 bytes written as 64 lowercase hexadecimal characters.
fn key(hex: &str) -> Option<SecretKey> {
    let digit = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    };
    let (pairs, []) = hex.as_bytes().as_chunks::<2>() else {
        return None;
    };
    let mut bytes = [0u8; 32];
    if pairs.len() != bytes.len() {
        return None;
    }
    for (byte, [high, low]) in bytes.iter_mut().zip(pairs) {
        *byte = digit(*high)? << 4 | digit(*low)?;
    }
    Some(SecretKey::from_bytes(bytes))
}

/// Checks that a registered claim's unit is the nullifier of its inputs,
/// from the text of the signed agreement, the signed claim and the claim's
/// input values, and the parties' unit key in lowercase hexadecimal.
///
/// The protocol's six checks run in order. See the module documentation for
/// what a passing check does not establish.
///
/// # Errors
///
/// The first check that fails.
pub fn check_registered_unit(
    agreement: &[u8],
    claim: &[u8],
    inputs: &[u8],
    unit_key_hex: &str,
) -> Result<(), UnitRefusal> {
    use UnitCheckCode as Code;

    // Step 1.
    let (agreement, claim, inputs) = (
        canonical(agreement, "agreement")?,
        canonical(claim, "claim")?,
        canonical(inputs, "inputs")?,
    );
    let malformed = |shape: verified_protocol::ShapeError| UnitRefusal {
        code: Code::Malformed,
        detail: shape.to_string(),
    };
    let agreement = SignedAgreement::from_value(&agreement).map_err(malformed)?;
    let claim = SignedClaim::from_value(&claim).map_err(malformed)?;
    let are_strings = inputs
        .as_object()
        .is_some_and(|o| o.iter().all(|(_, value)| value.as_str().is_some()));
    if !are_strings {
        return refuse(Code::Malformed, "the inputs are not an object of strings");
    }
    let Some(key) = key(unit_key_hex) else {
        return refuse(
            Code::Malformed,
            "the unit key is not 32 bytes in lowercase hexadecimal",
        );
    };

    // Step 2.
    if !claim.agreement.states(&agreement.agreement.digest()) {
        return refuse(
            Code::AgreementMismatch,
            "the claim is made under another agreement",
        );
    }
    // Step 3.
    if !agreement.unit_key.states(&key.commitment()) {
        return refuse(
            Code::UnitKeyMismatch,
            "the key is not the one the agreement pins",
        );
    }
    // Step 4.
    if !claim.inputs.states(&inputs.digest()) {
        return refuse(
            Code::InputsMismatch,
            "the inputs are not those the claim committed to",
        );
    }
    // Step 5.
    let scope = Scope {
        scope: agreement.scope.to_owned(),
        operation: agreement.operation.to_owned(),
        identity: agreement.identity.iter().map(|&s| s.to_owned()).collect(),
    };
    let identity = match Identity::of_claim(agreement.tenant, &scope, &inputs) {
        Ok(identity) => identity,
        Err(Error::MissingInput(name)) => {
            return refuse(
                Code::MissingInput,
                format!("the inputs have no {name:?}, which the scope names"),
            );
        }
        // The inputs are an object of strings, so nothing else can fail.
        Err(other) => return refuse(Code::Malformed, other.to_string()),
    };
    // Step 6.
    let unit = key.nullifier(&identity);
    if claim.unit.algorithm != NULLIFIER_ALGORITHM || claim.unit.hex != unit.to_hex() {
        return refuse(
            Code::UnitMismatch,
            "the claim's unit is not the nullifier of its identifying inputs",
        );
    }
    Ok(())
}
