// SPDX-License-Identifier: Apache-2.0

//! The verification procedure: the container checks, then the checks of the
//! package's protocol version, then the relying party's expectations.

use verified_canonical::{Sha256Digest, Value};
use verified_protocol::{ComponentPath, DECISION_SOURCE, Inputs, ProtocolVersion, RefusalCode};

use crate::container::{self, Checked, Options, Refusal, Rejection, refusal};
use crate::json::{digest, object, text};
use crate::report::{
    ContractSummary, DecisionFinding, Expectations, Finding, IssuerSignature, NotChecked, Report,
};
use crate::trust::{ED25519, Trust, verifies};
use crate::{order_transition, work_contract};

/// What the version-specific checks contribute to a report.
pub(crate) struct Parts {
    pub(crate) tenant: String,
    pub(crate) claim: String,
    pub(crate) contract: Option<ContractSummary>,
    pub(crate) statements: usize,
    pub(crate) evidence_signatures: Finding,
    pub(crate) signer_authority: Finding,
    pub(crate) decision: DecisionFinding,
    pub(crate) issuer_signature: IssuerSignature,
    pub(crate) work_record: Option<Value>,
}

impl Parts {
    /// Records that every statement verified under the registry.
    pub(crate) const fn authenticated(&mut self) {
        self.evidence_signatures = Finding::Established;
        self.signer_authority = Finding::Established;
    }
}

/// What can be said once integrity is established and nothing else: no
/// signature was checked and no decision reproduced.
pub(crate) fn without_registry(
    checked: &Checked<'_>,
    tenant: &str,
    claim: &str,
    statements: usize,
) -> Parts {
    let reason = NotChecked::NoTrustRegistry;
    Parts {
        tenant: tenant.to_owned(),
        claim: claim.to_owned(),
        contract: None,
        statements,
        evidence_signatures: Finding::NotChecked(reason),
        signer_authority: Finding::NotChecked(reason),
        decision: DecisionFinding::NotChecked(reason),
        issuer_signature: IssuerSignature::NotChecked {
            carried: checked.signatures.len(),
            reason,
        },
        work_record: None,
    }
}

fn component(checked: &Checked<'_>, path: ComponentPath) -> Sha256Digest {
    checked
        .components
        .iter()
        .find(|c| c.path == path)
        .map_or_else(|| Sha256Digest::of(&[]), |c| c.digest)
}

/// The decision document a verifier computes: the protocol, its evaluator,
/// the evaluator's outcome and the commitments to what was evaluated.
pub(crate) fn decision_document(
    protocol: ProtocolVersion,
    outcome: Value,
    checked: &Checked<'_>,
    evidence: &Sha256Digest,
) -> Value {
    let evaluator = protocol.evaluator();
    let mut document = match outcome {
        Value::Object(members) => members,
        _ => verified_canonical::Object::new(),
    };
    document.insert("protocol", text(protocol.identifier()));
    document.insert(
        "evaluator",
        object([
            ("name", text(evaluator.name)),
            ("specification", text(evaluator.specification)),
        ]),
    );
    document.insert(
        "commitments",
        object([
            ("claim", digest(&component(checked, ComponentPath::Claim))),
            (
                "contract",
                digest(&component(checked, ComponentPath::Contract)),
            ),
            ("evidence", digest(evidence)),
            ("inputs", digest(&component(checked, ComponentPath::Inputs))),
        ]),
    );
    Value::Object(document)
}

/// Step 13: every issuer signature counts. A signature counts only if the
/// registry holds its key, for the evaluation's tenant, with the decision
/// source among the key's sources, valid at the evaluation time, and the
/// signature verifies over the decision under this version's domain.
pub(crate) fn issuer_signatures(
    checked: &Checked<'_>,
    protocol: ProtocolVersion,
    decision: &Value,
    inputs: &Inputs<'_>,
    trust: &Trust,
) -> Result<IssuerSignature, Refusal> {
    if checked.signatures.is_empty() {
        return Ok(IssuerSignature::Absent);
    }
    let message = protocol.decision_domain().signing_input(decision);
    for signature in &checked.signatures {
        let counts = trust.find(signature.key_id).is_some_and(|(key, material)| {
            key.algorithm == ED25519
                && signature.scheme == ED25519
                && key.tenant == inputs.tenant
                && key.speaks_for(DECISION_SOURCE)
                && key.valid_at(inputs.evaluated_at)
                && material.is_some_and(|key| verifies(key, &message, signature.encoded))
        });
        if !counts {
            return Err(refusal(
                RefusalCode::IssuerSignatureInvalid,
                format!(
                    "the issuer signature by key {:?} does not count under the registry",
                    signature.key_id
                ),
            ));
        }
    }
    Ok(IssuerSignature::Established {
        count: checked.signatures.len(),
    })
}

/// Relying-party expectations, checked after every other check has passed,
/// in the protocol's order: tenant, contract, claim.
fn expect(expected: &Expectations, parts: &Parts, checked: &Checked<'_>) -> Result<(), Refusal> {
    if expected
        .tenant
        .as_ref()
        .is_some_and(|tenant| *tenant != parts.tenant)
    {
        return Err(refusal(
            RefusalCode::TenantNotExpected,
            format!("the evaluation is for tenant {:?}", parts.tenant),
        ));
    }
    let contract = component(checked, ComponentPath::Contract);
    if expected.contract.is_some_and(|digest| digest != contract) {
        return Err(refusal(
            RefusalCode::ContractNotExpected,
            format!("the package's contract is sha-256:{contract}"),
        ));
    }
    if expected
        .claim
        .as_ref()
        .is_some_and(|claim| *claim != parts.claim)
    {
        return Err(refusal(
            RefusalCode::ClaimNotExpected,
            format!("the package carries claim {}", parts.claim),
        ));
    }
    Ok(())
}

/// The members in which a supplied work record and the record computed from
/// the package disagree, in ascending order; a member either lacks counts.
fn record_differences(computed: &Value, supplied: &Value) -> Vec<String> {
    let members = |value: &'_ Value| value.as_object().cloned().unwrap_or_default();
    let (computed, supplied) = (members(computed), members(supplied));
    let mut names: Vec<&str> = computed.keys().chain(supplied.keys()).collect();
    names.sort_by(|a, b| verified_canonical::cmp_keys(a, b));
    names.dedup();
    names
        .into_iter()
        .filter(|name| computed.get(name) != supplied.get(name))
        .map(str::to_owned)
        .collect()
}

/// A supplied work record must be about this package, member for member.
fn compare_record(supplied: &Value, parts: &Parts) -> Result<(), Refusal> {
    let computed = parts.work_record.as_ref().unwrap_or(&Value::Null);
    let differing = record_differences(computed, supplied);
    if differing.is_empty() {
        Ok(())
    } else {
        Err(refusal(
            RefusalCode::RecordMismatch,
            format!(
                "the record is not about this package; it differs in: {}",
                differing.join(", ")
            ),
        ))
    }
}

/// Verifies a package.
///
/// Checks run in protocol order and stop at the first failure, which is the
/// result. A package that fails none of the checks that ran yields a
/// [`Report`] stating, property by property, what was established; read
/// [`Report::is_complete`] before relying on one.
///
/// This function reads no file, opens no socket and consults no clock.
pub fn verify(package: &[u8], options: &Options<'_>) -> Result<Report, Rejection> {
    let value = container::read(package, &options.limits)?;
    let checked = container::check(&value, options.protocol)?;
    let parts = match checked.protocol {
        ProtocolVersion::V0_1 => {
            // Expectations are defined for wvp-0.2 only. Ignoring them would
            // let a caller believe they were checked.
            if !options.expectations.is_empty() {
                return Err(Rejection::ExpectationsUndefined(checked.protocol));
            }
            if options.record.is_some() {
                return Err(Rejection::RecordUndefined(checked.protocol));
            }
            order_transition::verify(&checked, options.trust)?
        }
        ProtocolVersion::V0_2 => {
            let parts = work_contract::verify(&checked, options.trust)?;
            expect(&options.expectations, &parts, &checked)?;
            // The record is compared last: with a package that verified and
            // is the one the relying party expected.
            if let Some(record) = options.record {
                compare_record(record, &parts)?;
            }
            parts
        }
    };
    Ok(Report {
        protocol: checked.protocol,
        package_id: checked.package_id,
        components: checked.components,
        tenant: parts.tenant,
        claim: parts.claim,
        contract: parts.contract,
        statements: parts.statements,
        integrity: Finding::Established,
        evidence_signatures: parts.evidence_signatures,
        signer_authority: parts.signer_authority,
        decision: parts.decision,
        issuer_signature: parts.issuer_signature,
        work_record: parts.work_record,
        record_matched: options.record.is_some(),
        expectations_met: options.expectations.clone(),
    })
}
