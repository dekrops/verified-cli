// SPDX-License-Identifier: Apache-2.0

//! The components of a `wvp-0.2` package (draft).
//!
//! In this version the contract is data in Work Contract Language 1. Reading
//! here checks the shape of everything except the contract itself, which the
//! language's own reader checks; both belong to step 7 of the verification
//! procedure.

use verified_canonical::Value;

use crate::container::WireDigest;
use crate::decision::{self, RecordedDecision};
use crate::evidence::{self, Evidence};
use crate::inputs::Inputs;
use crate::shape::{self, At, Shape};
use crate::time::Instant;

/// A claim made against a contract, named by digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim<'a> {
    /// The component, whole.
    pub value: &'a Value,
    /// The claim's identifier (a UUID).
    pub id: &'a str,
    /// The tenant the claim says it belongs to.
    pub tenant: &'a str,
    /// The stated digest of the contract the claim was made against.
    pub contract: WireDigest<'a>,
    /// The contract's declared inputs, as the claim supplies them. Whether
    /// they fit the contract is the language's check.
    pub inputs: &'a Value,
    /// The identifiers of the evidence the claim relies on, as listed.
    pub evidence: Vec<&'a str>,
    /// When the claim was submitted.
    pub submitted_at: Instant,
}

/// What a statement's payload commits to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Body<'a> {
    /// One record a source reported.
    Record {
        /// The kind of record.
        kind: &'a str,
        /// The record's fields. Whether they fit the kind is the language's
        /// check.
        fields: &'a Value,
    },
    /// A source's statement that its records of a kind are complete as of a
    /// time.
    Complete {
        /// The kind declared complete.
        kind: &'a str,
        /// The time, as stated: seconds since the epoch, in the language's
        /// number spelling. Unchecked.
        as_of: &'a str,
    },
}

/// The components of a `wvp-0.2` package other than the contract, well
/// formed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Components<'a> {
    /// `claim.json`.
    pub claim: Claim<'a>,
    /// `contract.json`, unread: a Work Contract Language 1 contract.
    pub contract: &'a Value,
    /// `decision.json`, as stated.
    pub decision: RecordedDecision<'a>,
    /// `evidence/statements.json` with `evidence/bodies.json`.
    pub evidence: Vec<Evidence<'a, Body<'a>>>,
    /// `inputs.json`.
    pub inputs: Inputs<'a>,
}

impl<'a> Components<'a> {
    /// Reads the six component contents, given in protocol order. The
    /// contract is handed back unread.
    pub fn read(files: [&'a Value; 6]) -> Result<Self, crate::ShapeError> {
        let [claim, contract, decision, bodies, statements, inputs] = files;
        Ok(Self {
            claim: read_claim(claim, &At::root("claim.json"))?,
            contract,
            decision: read_decision(decision, &At::root("decision.json"))?,
            inputs: Inputs::read(inputs, &At::root("inputs.json"))?,
            evidence: evidence::read(bodies, statements, read_body)?,
        })
    }
}

fn read_claim<'a>(value: &'a Value, at: &At<'_>) -> Shape<Claim<'a>> {
    let o = shape::object(
        value,
        at,
        &[
            "claimant",
            "contract",
            "evidence",
            "id",
            "inputs",
            "submittedAt",
            "tenant",
        ],
    )?;
    let member = |name| shape::get(o, name);
    shape::uuid(member("claimant"), &at.member("claimant"))?;
    if member("inputs").as_object().is_none() {
        return at.member("inputs").fail(crate::ShapeProblem::NotAnObject);
    }
    Ok(Claim {
        value,
        id: shape::uuid(member("id"), &at.member("id"))?,
        tenant: shape::wrapped(member("tenant"), &at.member("tenant"))?,
        contract: shape::digest(member("contract"), &at.member("contract"))?,
        inputs: member("inputs"),
        evidence: shape::each(member("evidence"), &at.member("evidence"), shape::uuid)?,
        submitted_at: shape::instant(member("submittedAt"), &at.member("submittedAt"))?,
    })
}

fn read_decision<'a>(value: &'a Value, at: &At<'_>) -> Shape<RecordedDecision<'a>> {
    let o = shape::object(
        value,
        at,
        &[
            "commitments",
            "conflicts",
            "decision",
            "evaluator",
            "ignored",
            "protocol",
            "requirements",
        ],
    )?;
    shape::each(
        shape::get(o, "requirements"),
        &at.member("requirements"),
        |requirement, at| {
            let o = shape::object(requirement, at, &["id", "value"])?;
            shape::text(shape::get(o, "id"), &at.member("id"))?;
            shape::text(shape::get(o, "value"), &at.member("value"))
        },
    )?;
    shape::each(shape::get(o, "ignored"), &at.member("ignored"), shape::text)?;
    shape::each(
        shape::get(o, "conflicts"),
        &at.member("conflicts"),
        |conflict, at| {
            // An unresolved conflict has no `resolvedTo` member; `null` is not a
            // spelling of that.
            let resolved = conflict
                .as_object()
                .is_some_and(|o| o.get("resolvedTo").is_some());
            let o = if resolved {
                let o = shape::object(conflict, at, &["facts", "kind", "resolvedTo"])?;
                shape::text(shape::get(o, "resolvedTo"), &at.member("resolvedTo"))?;
                o
            } else {
                shape::object(conflict, at, &["facts", "kind"])?
            };
            shape::text(shape::get(o, "kind"), &at.member("kind"))?;
            shape::each(shape::get(o, "facts"), &at.member("facts"), shape::text)
        },
    )?;
    decision::common(value, o, at)
}

/// A body is exactly one of the two forms.
fn read_body<'a>(value: &'a Value, at: &At<'_>) -> Shape<Body<'a>> {
    if value.as_object().is_some_and(|o| o.get("record").is_some()) {
        let o = shape::object(value, at, &["record"])?;
        let at = at.member("record");
        let record = shape::object(shape::get(o, "record"), &at, &["fields", "kind"])?;
        let fields = shape::get(record, "fields");
        if fields.as_object().is_none() {
            return at.member("fields").fail(crate::ShapeProblem::NotAnObject);
        }
        Ok(Body::Record {
            kind: shape::text(shape::get(record, "kind"), &at.member("kind"))?,
            fields,
        })
    } else {
        let o = shape::object(value, at, &["complete"])?;
        let at = at.member("complete");
        let complete = shape::object(shape::get(o, "complete"), &at, &["asOf", "kind"])?;
        Ok(Body::Complete {
            kind: shape::text(shape::get(complete, "kind"), &at.member("kind"))?,
            as_of: shape::text(shape::get(complete, "asOf"), &at.member("asOf"))?,
        })
    }
}
