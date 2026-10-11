// SPDX-License-Identifier: Apache-2.0

//! Producing a statement: laying it out and giving a signer its bytes.
//!
//! A source states what it observed. The layout is here, beside the reader
//! that checks it, so that the two cannot disagree: every statement this
//! module lays out is read back with `SignedStatement::from_value` before it
//! is returned. This module holds no key. A signature is made by the caller,
//! over [`statement_signing_input`], and attached with [`signed_statement`];
//! [`super::authenticate`] then shows whether a relying party would accept
//! it.

use verified_canonical::{Object, Value};
use verified_protocol::{STATEMENT_DOMAIN, STATEMENT_PROTOCOL, SignedStatement};

use super::{EvidenceCode, EvidenceRefusal, refuse};
use crate::json::{digest, object, text};

/// The members of a statement its source states, as they appear in it.
const STATED: [&str; 7] = [
    "id",
    "issuer",
    "kind",
    "observedAt",
    "source",
    "subject",
    "tenant",
];

/// Where a statement stands in its issuer's stream.
#[derive(Clone, Copy, Debug)]
pub enum Step<'a> {
    /// Not chained.
    Unchained,
    /// The first step of a new stream.
    First {
        /// The stream's name.
        stream: &'a str,
    },
    /// The step after a statement of the stream, signed before.
    After(&'a Value),
}

/// What a statement is made from.
#[derive(Clone, Copy, Debug)]
pub struct StatementDraft<'a> {
    /// The members the source states, as the statement carries them:
    /// exactly `id`, `issuer`, `kind`, `observedAt`, `source`, `subject` and
    /// `tenant`.
    pub stated: &'a Value,
    /// The evidence body. The statement commits to it by its digest.
    pub body: &'a Value,
    /// Its place in a stream.
    pub step: Step<'a>,
}

/// The unsigned statement a draft describes: the stated members, the
/// protocol, the commitment to the body, and the chain link.
///
/// # Errors
///
/// `MALFORMED` for a draft that does not give a statement of the protocol's
/// structure, or a previous step that is not a chained statement.
pub fn prepare_statement(draft: &StatementDraft<'_>) -> Result<Value, EvidenceRefusal> {
    let Some(stated) = draft.stated.as_object().filter(|o| o.has_exactly(&STATED)) else {
        return refuse(
            EvidenceCode::Malformed,
            format!("a statement's stated members are exactly {STATED:?}"),
        );
    };
    let chain = match draft.step {
        Step::Unchained => Value::Null,
        Step::First { stream } => object([
            ("previous", Value::Null),
            ("sequence", Value::Integer(0.into())),
            ("stream", text(stream)),
        ]),
        Step::After(previous) => {
            let read = SignedStatement::from_value(previous).or_else(|shape| {
                refuse(
                    EvidenceCode::Malformed,
                    format!("the previous step: {shape}"),
                )
            })?;
            let Some(link) = read.chain else {
                return refuse(EvidenceCode::Malformed, "the previous step is not chained");
            };
            let Some(sequence) = link.sequence.checked_add(1) else {
                return refuse(
                    EvidenceCode::Malformed,
                    "the stream has no step after this one",
                );
            };
            object([
                ("previous", digest(&read.digest())),
                ("sequence", Value::Integer(sequence.into())),
                ("stream", text(link.stream)),
            ])
        }
    };
    let mut statement: Object = stated
        .iter()
        .map(|(k, v)| (k.to_owned(), v.clone()))
        .collect();
    statement.insert("chain", chain);
    statement.insert("payload", digest(&draft.body.digest()));
    statement.insert("protocol", text(STATEMENT_PROTOCOL));
    let statement = Value::Object(statement);

    // Read back as a verifier reads it, with a placeholder signature.
    let probe = signed_statement(&statement, "", "");
    SignedStatement::from_value(&probe)
        .or_else(|shape| refuse(EvidenceCode::Malformed, shape.to_string()))?;
    Ok(statement)
}

/// The bytes a statement's signature is made over: its domain, then the
/// statement's canonical text.
#[must_use]
pub fn statement_signing_input(statement: &Value) -> Vec<u8> {
    STATEMENT_DOMAIN.signing_input(statement)
}

/// A statement with its signature: `{ statement, signature }`, where
/// `encoded` is the standard base64 of an Ed25519 signature over
/// [`statement_signing_input`]. Nothing is checked here; authenticate the
/// result.
#[must_use]
pub fn signed_statement(statement: &Value, key_id: &str, encoded: &str) -> Value {
    object([
        (
            "signature",
            object([
                ("encoded", text(encoded)),
                ("keyId", text(key_id)),
                ("scheme", text("Ed25519")),
            ]),
        ),
        ("statement", statement.clone()),
    ])
}
