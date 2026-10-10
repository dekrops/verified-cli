// SPDX-License-Identifier: Apache-2.0

//! The components of a `wvp-0.1` package (draft).
//!
//! In this version a contract names a transition rule that one evaluator,
//! `order-transition`, applies. Reading here checks shape only (step 7 of the
//! verification procedure): every object closed at every depth, every body a
//! listed case, bodies and statements aligned.

use verified_canonical::Value;

use crate::container::ShapeProblem;
use crate::decision::{self, RecordedDecision};
use crate::evidence::{self, Evidence};
use crate::inputs::Inputs;
use crate::shape::{self, At, Shape};
use crate::statement::EVIDENCE_KINDS;
use crate::time::Instant;

const STATES: [&str; 4] = ["Created", "Approved", "Shipped", "Cancelled"];
const WORK_TYPES: [&str; 2] = ["OrderFulfillment", "OrderCapture"];
const TRUST: [&str; 4] = [
    "Unauthenticated",
    "SourceAuthenticated",
    "Signed",
    "HumanAttested",
];

/// An actor's assertion that work with a given outcome occurred.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim<'a> {
    /// The component, whole.
    pub value: &'a Value,
    /// The contract the claim was made against (a UUID).
    pub contract_id: &'a str,
    /// What the work was about.
    pub subject: &'a Value,
    /// The outcome the claim asserts.
    pub outcome: &'a Value,
    /// The identifiers of the evidence the claim relies on, as listed.
    pub evidence: Vec<&'a str>,
    /// When the work is said to have occurred.
    pub occurred_at: Instant,
    /// When the claim was submitted.
    pub submitted_at: Instant,
}

/// The period in which a contract applies: from `from`, and before `until`
/// if there is one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Validity {
    /// The first instant the contract applies at.
    pub from: Instant,
    /// The first instant it no longer applies at, if any.
    pub until: Option<Instant>,
}

impl Validity {
    /// Whether the contract applies at `at`.
    #[must_use]
    pub fn contains(&self, at: Instant) -> bool {
        self.from <= at && self.until.is_none_or(|until| at < until)
    }
}

/// What counts as the work: subject, expected outcome and a transition rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contract<'a> {
    /// The component, whole.
    pub value: &'a Value,
    /// The contract's identifier (a UUID).
    pub id: &'a str,
    /// What the work is about.
    pub subject: &'a Value,
    /// The outcome that counts as the work.
    pub expected_outcome: &'a Value,
    /// When the contract applies.
    pub validity: Validity,
    /// The states the rule allows a transition from.
    pub allowed_from: Vec<&'a str>,
    /// The state the rule's transition leads to.
    pub target: &'a str,
    /// The evidence kinds the policy requires.
    pub required_evidence: Vec<&'a str>,
}

/// What a statement's payload commits to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Body<'a> {
    /// A subject moved from one state to another at a time.
    StateTransition {
        /// The subject that moved.
        subject: &'a Value,
        /// The state it left.
        from: &'a str,
        /// The state it reached.
        to: &'a str,
        /// When.
        at: Instant,
    },
    /// Another listed case. The one evaluator of this version reads only
    /// state transitions, so the content is checked and not kept.
    Other,
}

/// The six components of a `wvp-0.1` package, well formed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Components<'a> {
    /// `claim.json`.
    pub claim: Claim<'a>,
    /// `contract.json`.
    pub contract: Contract<'a>,
    /// `decision.json`, as stated.
    pub decision: RecordedDecision<'a>,
    /// `evidence/statements.json` with `evidence/bodies.json`.
    pub evidence: Vec<Evidence<'a, Body<'a>>>,
    /// `inputs.json`.
    pub inputs: Inputs<'a>,
}

impl<'a> Components<'a> {
    /// Reads the six component contents, given in protocol order.
    pub fn read(files: [&'a Value; 6]) -> Result<Self, crate::ShapeError> {
        let [claim, contract, decision, bodies, statements, inputs] = files;
        Ok(Self {
            claim: read_claim(claim, &At::root("claim.json"))?,
            contract: read_contract(contract, &At::root("contract.json"))?,
            decision: read_decision(decision, &At::root("decision.json"))?,
            inputs: Inputs::read(inputs, &At::root("inputs.json"))?,
            evidence: evidence::read(bodies, statements, read_body)?,
        })
    }
}

fn state<'a>(value: &'a Value, at: &At<'_>) -> Shape<&'a str> {
    shape::unit(value, at, &STATES)
}

fn kind<'a>(value: &'a Value, at: &At<'_>) -> Shape<&'a str> {
    shape::unit(value, at, &EVIDENCE_KINDS)
}

fn outcome(value: &Value, at: &At<'_>) -> Shape<()> {
    let (case, content) = shape::variant(value, at)?;
    let at = at.member(case);
    match case {
        "OrderRecorded" => {
            shape::object(content, &at, &[])?;
        }
        "OrderReached" => {
            let o = shape::object(content, &at, &["state"])?;
            state(shape::get(o, "state"), &at.member("state"))?;
        }
        "GoodsIssued" => {
            let o = shape::object(content, &at, &["orderItem", "quantity", "unit"])?;
            shape::text(shape::get(o, "orderItem"), &at.member("orderItem"))?;
            shape::int32(shape::get(o, "quantity"), &at.member("quantity"))?;
            shape::text(shape::get(o, "unit"), &at.member("unit"))?;
        }
        _ => {
            return at.fail(ShapeProblem::Case(&[
                "OrderRecorded",
                "OrderReached",
                "GoodsIssued",
            ]));
        }
    }
    Ok(())
}

fn provenance(value: &Value, at: &At<'_>) -> Shape<()> {
    let o = shape::object(
        value,
        at,
        &[
            "causedBy",
            "ingestedAt",
            "observedAt",
            "source",
            "transformations",
            "trust",
            "witness",
        ],
    )?;
    let member = |name| shape::get(o, name);
    shape::source(member("source"), &at.member("source"))?;
    shape::uuid(member("witness"), &at.member("witness"))?;
    shape::unit(member("trust"), &at.member("trust"), &TRUST)?;
    shape::instant(member("observedAt"), &at.member("observedAt"))?;
    shape::instant(member("ingestedAt"), &at.member("ingestedAt"))?;
    shape::each(
        member("transformations"),
        &at.member("transformations"),
        |step, at| {
            let o = shape::object(step, at, &["inputHashes", "name", "version"])?;
            shape::text(shape::get(o, "name"), &at.member("name"))?;
            shape::version(shape::get(o, "version"), &at.member("version"))?;
            shape::each(
                shape::get(o, "inputHashes"),
                &at.member("inputHashes"),
                shape::digest,
            )
        },
    )?;
    shape::each(member("causedBy"), &at.member("causedBy"), shape::uuid)?;
    Ok(())
}

fn read_claim<'a>(value: &'a Value, at: &At<'_>) -> Shape<Claim<'a>> {
    // `contractSnapshotHash` is optional and, when present, part of what the
    // claim commits to.
    let with_snapshot = value
        .as_object()
        .is_some_and(|o| o.get("contractSnapshotHash").is_some());
    let o = if with_snapshot {
        let o = shape::object(
            value,
            at,
            &[
                "claimant",
                "contractId",
                "contractSnapshotHash",
                "evidence",
                "id",
                "occurredAt",
                "outcome",
                "provenance",
                "subject",
                "submittedAt",
                "supersedes",
            ],
        )?;
        shape::digest(
            shape::get(o, "contractSnapshotHash"),
            &at.member("contractSnapshotHash"),
        )?;
        o
    } else {
        shape::object(
            value,
            at,
            &[
                "claimant",
                "contractId",
                "evidence",
                "id",
                "occurredAt",
                "outcome",
                "provenance",
                "subject",
                "submittedAt",
                "supersedes",
            ],
        )?
    };
    let member = |name| shape::get(o, name);
    shape::uuid(member("id"), &at.member("id"))?;
    shape::uuid(member("claimant"), &at.member("claimant"))?;
    shape::subject(member("subject"), &at.member("subject"))?;
    outcome(member("outcome"), &at.member("outcome"))?;
    provenance(member("provenance"), &at.member("provenance"))?;
    shape::nullable(member("supersedes"), &at.member("supersedes"), shape::uuid)?;
    Ok(Claim {
        value,
        contract_id: shape::uuid(member("contractId"), &at.member("contractId"))?,
        subject: member("subject"),
        outcome: member("outcome"),
        evidence: shape::each(member("evidence"), &at.member("evidence"), shape::uuid)?,
        occurred_at: shape::instant(member("occurredAt"), &at.member("occurredAt"))?,
        submitted_at: shape::instant(member("submittedAt"), &at.member("submittedAt"))?,
    })
}

fn read_contract<'a>(value: &'a Value, at: &At<'_>) -> Shape<Contract<'a>> {
    let o = shape::object(
        value,
        at,
        &[
            "expectedOutcome",
            "id",
            "parties",
            "policy",
            "subject",
            "validity",
            "version",
            "workType",
        ],
    )?;
    let member = |name| shape::get(o, name);
    shape::version(member("version"), &at.member("version"))?;
    shape::unit(member("workType"), &at.member("workType"), &WORK_TYPES)?;
    shape::subject(member("subject"), &at.member("subject"))?;
    outcome(member("expectedOutcome"), &at.member("expectedOutcome"))?;
    shape::each(member("parties"), &at.member("parties"), shape::uuid)?;

    let policy_at = at.member("policy");
    let policy = shape::object(
        member("policy"),
        &policy_at,
        &["id", "requiredEvidence", "rule", "version"],
    )?;
    shape::uuid(shape::get(policy, "id"), &policy_at.member("id"))?;
    shape::version(shape::get(policy, "version"), &policy_at.member("version"))?;
    let rule_at = policy_at.member("rule");
    let rule = shape::object(shape::get(policy, "rule"), &rule_at, &["allowedFrom", "to"])?;

    let validity_at = at.member("validity");
    let validity = shape::object(member("validity"), &validity_at, &["from", "until"])?;

    Ok(Contract {
        value,
        id: shape::uuid(member("id"), &at.member("id"))?,
        subject: member("subject"),
        expected_outcome: member("expectedOutcome"),
        validity: Validity {
            from: shape::instant(shape::get(validity, "from"), &validity_at.member("from"))?,
            until: shape::nullable(
                shape::get(validity, "until"),
                &validity_at.member("until"),
                shape::instant,
            )?,
        },
        allowed_from: shape::each(
            shape::get(rule, "allowedFrom"),
            &rule_at.member("allowedFrom"),
            state,
        )?,
        target: state(shape::get(rule, "to"), &rule_at.member("to"))?,
        required_evidence: shape::each(
            shape::get(policy, "requiredEvidence"),
            &policy_at.member("requiredEvidence"),
            kind,
        )?,
    })
}

fn read_decision<'a>(value: &'a Value, at: &At<'_>) -> Shape<RecordedDecision<'a>> {
    let o = shape::object(
        value,
        at,
        &[
            "commitments",
            "conditions",
            "decision",
            "evaluator",
            "protocol",
        ],
    )?;
    shape::each(
        shape::get(o, "conditions"),
        &at.member("conditions"),
        |condition, at| {
            let o = shape::object(condition, at, &["evidence", "holds", "id"])?;
            shape::text(shape::get(o, "id"), &at.member("id"))?;
            shape::boolean(shape::get(o, "holds"), &at.member("holds"))?;
            shape::each(
                shape::get(o, "evidence"),
                &at.member("evidence"),
                shape::uuid,
            )
        },
    )?;
    decision::common(value, o, at)
}

fn read_body<'a>(value: &'a Value, at: &At<'_>) -> Shape<Body<'a>> {
    let (case, content) = shape::variant(value, at)?;
    let at = at.member(case);
    match case {
        "StateTransition" => {
            let o = shape::object(content, &at, &["at", "from", "subject", "to"])?;
            shape::subject(shape::get(o, "subject"), &at.member("subject"))?;
            Ok(Body::StateTransition {
                subject: shape::get(o, "subject"),
                from: state(shape::get(o, "from"), &at.member("from"))?,
                to: state(shape::get(o, "to"), &at.member("to"))?,
                at: shape::instant(shape::get(o, "at"), &at.member("at"))?,
            })
        }
        "ExternalArtifact" => {
            let o = shape::object(content, &at, &["digest", "location", "mediaType"])?;
            shape::digest(shape::get(o, "digest"), &at.member("digest"))?;
            shape::text(shape::get(o, "location"), &at.member("location"))?;
            shape::text(shape::get(o, "mediaType"), &at.member("mediaType"))?;
            Ok(Body::Other)
        }
        "HumanAttestation" => {
            let o = shape::object(content, &at, &["at", "statement", "subject", "witness"])?;
            shape::subject(shape::get(o, "subject"), &at.member("subject"))?;
            shape::text(shape::get(o, "statement"), &at.member("statement"))?;
            shape::uuid(shape::get(o, "witness"), &at.member("witness"))?;
            shape::instant(shape::get(o, "at"), &at.member("at"))?;
            Ok(Body::Other)
        }
        "Redacted" => {
            let o = shape::object(content, &at, &["disclosedFact", "originalCommitment"])?;
            shape::text(shape::get(o, "disclosedFact"), &at.member("disclosedFact"))?;
            shape::digest(
                shape::get(o, "originalCommitment"),
                &at.member("originalCommitment"),
            )?;
            Ok(Body::Other)
        }
        "RetainedMetadata" => {
            let o = shape::object(content, &at, &["originalKind", "subject"])?;
            kind(shape::get(o, "originalKind"), &at.member("originalKind"))?;
            shape::subject(shape::get(o, "subject"), &at.member("subject"))?;
            Ok(Body::Other)
        }
        _ => at.fail(ShapeProblem::Case(&[
            "StateTransition",
            "ExternalArtifact",
            "HumanAttestation",
            "Redacted",
            "RetainedMetadata",
        ])),
    }
}
