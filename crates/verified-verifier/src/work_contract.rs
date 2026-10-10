// SPDX-License-Identifier: Apache-2.0

//! `wvp-0.2`: steps 7 to 13, with a Work Contract Language 1 contract.

use std::collections::BTreeMap;

use verified_canonical::{Value, cmp_keys};
use verified_contract::Contract;
use verified_protocol::v02::{Body, Claim, Components};
use verified_protocol::{Decision, Evidence, Inputs, ProtocolVersion, RefusalCode};

use crate::container::{Checked, Refusal, refusal};
use crate::json::{digest, object, text};
use crate::report::{ContractSummary, DecisionFinding, Evaluation, Reproduced};
use crate::statement::{admit, authenticate};
use crate::trust::Trust;
use crate::verify::{Parts, decision_document, issuer_signatures, without_registry};

const PROTOCOL: ProtocolVersion = ProtocolVersion::V0_2;

/// A completeness statement's time: a non-negative number in the language's
/// spelling.
fn as_of(spelling: &str) -> Option<u64> {
    let spelled = !spelling.is_empty()
        && spelling.len() <= 19
        && spelling.bytes().all(|b| b.is_ascii_digit())
        && (spelling == "0" || !spelling.starts_with('0'));
    spelled.then(|| spelling.parse().ok()).flatten()
}

/// The environment the contract is evaluated against, built from the
/// authenticated statements in ascending order of identifier.
fn environment(claim: &Claim<'_>, evidence: &[Evidence<'_, Body<'_>>]) -> Result<Value, Refusal> {
    // One entry per (kind, source): of several completeness statements, the
    // one with the greatest time.
    let mut complete: BTreeMap<(&str, &str), (u64, &str)> = BTreeMap::new();
    for item in evidence {
        let Body::Complete {
            kind,
            as_of: spelling,
        } = item.body
        else {
            continue;
        };
        // Completeness as of a time later than the statement itself was
        // observed is not something its source could have known.
        let observed = item.statement.observed_at.epoch_seconds();
        let Some(at) = as_of(spelling).filter(|at| i128::from(*at) <= i128::from(observed)) else {
            return Err(refusal(
                RefusalCode::InputMismatch,
                "a completeness statement vouches for a time after its statement was observed",
            ));
        };
        let latest = complete
            .entry((kind, item.statement.source_system))
            .or_insert((at, spelling));
        if latest.0 < at {
            *latest = (at, spelling);
        }
    }
    let mut complete: Vec<_> = complete.into_iter().collect();
    complete.sort_by(|((k1, s1), _), ((k2, s2), _)| cmp_keys(k1, k2).then(cmp_keys(s1, s2)));

    // A fact's source is the system named in its signed statement, for
    // which step 9 showed the signing key is authorized. A body has no say
    // in where it came from.
    let facts = evidence.iter().filter_map(|item| match item.body {
        Body::Record { kind, fields } => Some(object([
            ("id", text(&format!("e-{}", item.statement.id))),
            ("kind", text(kind)),
            ("source", text(item.statement.source_system)),
            ("fields", fields.clone()),
        ])),
        Body::Complete { .. } => None,
    });
    let complete = complete.into_iter().map(|((kind, source), (_, spelling))| {
        object([
            ("kind", text(kind)),
            ("source", text(source)),
            ("asOf", text(spelling)),
        ])
    });
    Ok(object([
        ("inputs", claim.inputs.clone()),
        ("facts", Value::Array(facts.collect())),
        ("complete", Value::Array(complete.collect())),
    ]))
}

/// `submittedAt` ≤ `evaluatedAt`, `ingestedAt` ≤ `assembledAt` ≤
/// `evaluatedAt`, and every statement observed no later than ingestion.
fn times_in_order(
    claim: &Claim<'_>,
    inputs: &Inputs<'_>,
    evidence: &[Evidence<'_, Body<'_>>],
) -> bool {
    claim.submitted_at <= inputs.evaluated_at
        && inputs.ingested_at <= inputs.assembled_at
        && inputs.assembled_at <= inputs.evaluated_at
        && evidence
            .iter()
            .all(|e| e.statement.observed_at <= inputs.ingested_at)
}

pub(crate) fn verify(checked: &Checked<'_>, trust: Option<&Trust>) -> Result<Parts, Refusal> {
    // Step 7. The contract must be a well-formed contract; its text is
    // canonical because the package's is.
    let components = Components::read(checked.files)
        .map_err(|error| refusal(RefusalCode::MalformedComponent, error.to_string()))?;
    let contract = Contract::read(components.contract).map_err(|error| {
        refusal(
            RefusalCode::MalformedComponent,
            format!("contract.json is not a well-formed work-contract-1 contract ({error})"),
        )
    })?;
    let contract_digest = components.contract.digest();
    let mut parts = without_registry(
        checked,
        components.inputs.tenant,
        components.claim.id,
        components.evidence.len(),
    );
    parts.contract = Some(ContractSummary {
        id: contract.id().to_owned(),
        version: contract.version().to_owned(),
        digest: contract_digest,
    });
    let Some(trust) = trust else {
        return Ok(parts);
    };

    // Step 8.
    let recorded = &components.decision;
    if recorded.protocol != PROTOCOL.identifier() || recorded.evaluator != PROTOCOL.evaluator() {
        return Err(refusal(
            RefusalCode::UnsupportedEvaluator,
            "the decision does not name wvp-0.2 and the work-contract evaluator, specification 1",
        ));
    }

    // Step 9.
    for item in &components.evidence {
        authenticate(&item.statement, trust)?;
    }

    // Step 10.
    let Components {
        claim,
        inputs,
        evidence,
        ..
    } = &components;
    admit(inputs.tenant, &claim.evidence, evidence)?;

    // Step 11.
    let mismatch = |what: &str| refusal(RefusalCode::InputMismatch, what.to_owned());
    if claim.tenant != inputs.tenant {
        return Err(mismatch(
            "the claim's tenant is not the evaluation's tenant",
        ));
    }
    if !claim.contract.states(&contract_digest) {
        return Err(mismatch(
            "the claim names another contract than the one in the package",
        ));
    }
    if !times_in_order(claim, inputs, evidence) {
        return Err(mismatch(
            "the observation, ingestion, assembly, submission and evaluation times are out of order",
        ));
    }
    let environment = environment(claim, evidence)?;
    let outcome = contract.evaluate(&environment).map_err(|error| {
        refusal(
            RefusalCode::InputMismatch,
            format!("the contract cannot be evaluated against this evidence ({error})"),
        )
    })?;

    // Step 12.
    let statement_digests = evidence.iter().map(|e| digest(&e.statement.digest()));
    let evidence_commitment = Value::Array(statement_digests.collect()).digest();
    let reproduced = decision_document(PROTOCOL, outcome.to_value(), checked, &evidence_commitment);
    if reproduced != *recorded.value {
        return Err(refusal(
            RefusalCode::DecisionMismatch,
            format!(
                "the decision recomputed from the package is {}, with values or commitments that differ from decision.json",
                outcome.decision
            ),
        ));
    }

    // Step 13.
    parts.issuer_signature = issuer_signatures(checked, PROTOCOL, recorded.value, inputs, trust)?;
    parts.authenticated();
    parts.decision = DecisionFinding::Reproduced(Reproduced {
        decision: match outcome.decision {
            verified_contract::Decision::Supported => Decision::Supported,
            verified_contract::Decision::Contradicted => Decision::Contradicted,
            verified_contract::Decision::Undetermined => Decision::Undetermined,
        },
        evaluation: Evaluation::WorkContract {
            requirements: outcome.requirements,
            ignored: outcome.ignored,
            conflicts: outcome.conflicts,
        },
    });
    Ok(parts)
}
