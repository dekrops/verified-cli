//! `wvp-0.1`: steps 7 to 13, with the `order-transition` evaluator.

use verified_canonical::Value;
use verified_protocol::v01::{Body, Claim, Components, Contract};
use verified_protocol::{
    Decision, Evidence, Inputs, ProtocolVersion, RefusalCode, SignedStatement,
};

use crate::container::{Checked, Refusal, refusal};
use crate::json::{digest, object, text, wrapped};
use crate::report::{Condition, DecisionFinding, Evaluation, Reproduced};
use crate::statement::{admit, authenticate};
use crate::trust::Trust;
use crate::verify::{Parts, decision_document, issuer_signatures, without_registry};

const PROTOCOL: ProtocolVersion = ProtocolVersion::V0_1;

pub(crate) fn verify(checked: &Checked<'_>, trust: Option<&Trust>) -> Result<Parts, Refusal> {
    // Step 7.
    let components = Components::read(checked.files)
        .map_err(|error| refusal(RefusalCode::MalformedComponent, error.to_string()))?;
    let claim_id = components.claim.value.as_object().and_then(|o| o.get("id"));
    let mut parts = without_registry(
        checked,
        components.inputs.tenant,
        claim_id
            .and_then(|id| id.as_object()?.get("value")?.as_str())
            .unwrap_or_default(),
        components.evidence.len(),
    );
    let Some(trust) = trust else {
        return Ok(parts);
    };

    // Step 8.
    let recorded = &components.decision;
    if recorded.protocol != PROTOCOL.identifier() || recorded.evaluator != PROTOCOL.evaluator() {
        return Err(refusal(
            RefusalCode::UnsupportedEvaluator,
            "the decision does not name wvp-0.1 and the order-transition evaluator, specification 1",
        ));
    }

    // Step 9.
    for item in &components.evidence {
        authenticate(&item.statement, trust)?;
    }

    // Step 10.
    admit(
        components.inputs.tenant,
        &components.claim.evidence,
        &components.evidence,
    )?;
    let evidence = evidence_manifest(&components).digest();

    // Step 11.
    let Components {
        claim,
        contract,
        inputs,
        ..
    } = &components;
    let inputs_belong_together = !components.evidence.is_empty()
        && claim.contract_id == contract.id
        && claim.subject == contract.subject
        && claim.outcome == contract.expected_outcome
        && contract.validity.contains(claim.occurred_at)
        && inputs.evaluated_at >= claim.submitted_at
        && inputs.evaluated_at >= inputs.assembled_at;
    if !inputs_belong_together {
        return Err(refusal(
            RefusalCode::InputMismatch,
            "the claim, contract, evidence and evaluation times do not belong together",
        ));
    }

    // Step 12.
    let (decision, conditions) = evaluate(claim, contract, inputs, &components.evidence);
    let outcome = object([
        ("decision", text(decision.as_str())),
        (
            "conditions",
            Value::Array(
                conditions
                    .iter()
                    .map(|c| {
                        object([
                            ("id", text(c.id)),
                            ("holds", Value::Bool(c.holds)),
                            (
                                "evidence",
                                Value::Array(c.evidence.iter().map(|id| wrapped(id)).collect()),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
    ]);
    let reproduced = decision_document(PROTOCOL, outcome, checked, &evidence);
    if reproduced != *recorded.value {
        return Err(refusal(
            RefusalCode::DecisionMismatch,
            format!(
                "the decision recomputed from the package is {decision}, with conditions or commitments that differ from decision.json"
            ),
        ));
    }

    // Step 13.
    parts.issuer_signature = issuer_signatures(checked, PROTOCOL, recorded.value, inputs, trust)?;
    parts.authenticated();
    parts.decision = DecisionFinding::Reproduced(Reproduced {
        decision,
        evaluation: Evaluation::OrderTransition { conditions },
    });
    Ok(parts)
}

/// The evidence manifest that admission produces. Its digest is the
/// decision's commitment to the evidence.
fn evidence_manifest(components: &Components<'_>) -> Value {
    let inputs = &components.inputs;
    let item = |statement: &SignedStatement<'_>| {
        let transformation = object([
            ("name", text("verified-evidence-statement")),
            (
                "version",
                object([
                    ("major", Value::Integer(1.into())),
                    ("minor", Value::Integer(0.into())),
                    ("patch", Value::Integer(0.into())),
                ]),
            ),
            (
                "inputHashes",
                Value::Array(vec![digest(&statement.digest())]),
            ),
        ]);
        object([
            ("id", statement.member("id").clone()),
            ("kind", statement.member("kind").clone()),
            ("subject", statement.member("subject").clone()),
            ("payloadHash", statement.member("payload").clone()),
            (
                "provenance",
                object([
                    ("source", statement.member("source").clone()),
                    ("witness", statement.member("issuer").clone()),
                    ("trust", object([("Signed", object([]))])),
                    ("observedAt", statement.member("observedAt").clone()),
                    ("ingestedAt", inputs.member("ingestedAt").clone()),
                    ("transformations", Value::Array(vec![transformation])),
                    ("causedBy", Value::Array(Vec::new())),
                ]),
            ),
        ])
    };
    // Statements are in ascending order of identifier (step 7) and distinct
    // (step 10), which is the order the manifest lists them in.
    let items = components
        .evidence
        .iter()
        .map(|e| item(&e.statement))
        .collect();
    let claim_id = components.claim.value.as_object().and_then(|o| o.get("id"));
    object([
        ("version", text("verified-evidence-manifest-v1")),
        ("id", inputs.member("packageId").clone()),
        ("claimId", claim_id.cloned().unwrap_or(Value::Null)),
        ("items", Value::Array(items)),
        ("assembledAt", inputs.member("assembledAt").clone()),
    ])
}

/// The evaluator: qualifying transitions, the four conditions, the decision.
fn evaluate(
    claim: &Claim<'_>,
    contract: &Contract<'_>,
    inputs: &Inputs<'_>,
    evidence: &[Evidence<'_, Body<'_>>],
) -> (Decision, Vec<Condition>) {
    let claimed_system = claim
        .subject
        .as_object()
        .and_then(|subject| subject.get("system"))
        .and_then(Value::as_str);
    // Only qualifying transitions count, for or against the claim. A
    // correctly signed statement that does not qualify changes nothing.
    let qualifying = evidence.iter().filter_map(|item| {
        let statement = &item.statement;
        let Body::StateTransition {
            subject,
            from,
            to,
            at,
        } = item.body
        else {
            return None;
        };
        let qualifies = statement.kind == "StateTransition"
            && subject == statement.member("subject")
            && subject == claim.subject
            && Some(statement.source_system) == claimed_system
            && at == statement.observed_at
            && at == claim.occurred_at
            && contract.validity.contains(at)
            && inputs.ingested_at >= at
            && inputs.evaluated_at >= inputs.ingested_at;
        qualifies.then_some((statement.id, from, to))
    });
    let mut contradicting = Vec::new();
    let mut supporting = Vec::new();
    for (id, from, to) in qualifying {
        if to != contract.target {
            contradicting.push(id.to_owned());
        } else if contract.allowed_from.contains(&from) {
            supporting.push(id.to_owned());
        }
    }
    contradicting.sort();
    supporting.sort();

    let reached_target = object([(
        "OrderReached",
        object([("state", object([(contract.target, object([]))]))]),
    )]);
    let outcome_is_target = *contract.expected_outcome == reached_target;
    let required_evidence = contract
        .required_evidence
        .iter()
        .all(|kind| evidence.iter().any(|item| item.statement.kind == *kind));

    // Contradiction is tested first: it wins over any support.
    let decision = if !contradicting.is_empty() {
        Decision::Contradicted
    } else if outcome_is_target && required_evidence && !supporting.is_empty() {
        Decision::Supported
    } else {
        Decision::Undetermined
    };
    let condition = |id, holds, evidence| Condition {
        id,
        holds,
        evidence,
    };
    let conditions = vec![
        condition(
            "CONTRADICTING_TRANSITION",
            !contradicting.is_empty(),
            contradicting,
        ),
        condition("OUTCOME_IS_TARGET", outcome_is_target, Vec::new()),
        condition("REQUIRED_EVIDENCE", required_evidence, Vec::new()),
        condition("SUPPORTING_TRANSITION", !supporting.is_empty(), supporting),
    ];
    (decision, conditions)
}
