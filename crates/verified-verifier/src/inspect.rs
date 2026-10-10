// SPDX-License-Identifier: Apache-2.0

//! Looking at what a package says, as distinct from what was established.

use verified_canonical::Value;
use verified_protocol::{Evidence, ProtocolVersion, RefusalCode, v01, v02};

use crate::container::{self, Options, Rejection, refusal};
use crate::report::{IssuerSignature, Report};
use crate::verify::verify;

/// One evidence statement, as the package states it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementSummary {
    /// The evidence identifier.
    pub id: String,
    /// The evidence kind.
    pub kind: String,
    /// The system the statement says was observed.
    pub source: String,
    /// The actor the statement says asserted it.
    pub issuer: String,
    /// The identifier of the key said to have signed it.
    pub key_id: String,
    /// The asserted observation time, in the protocol's spelling.
    pub observed_at: String,
    /// What the carried body is, in a few words: its case, and for a
    /// `wvp-0.2` body the kind of record it concerns.
    pub body: String,
    /// Whether the claim lists this statement as evidence it relies on.
    pub claimed: bool,
}

/// The claim, as the package states it.
///
/// Nothing here is authenticated by itself. The claim is covered by the
/// package's commitment, so these are the values of exactly the package the
/// accompanying report is about; whether anyone stands behind them is what
/// the report's findings say, and what the claimant is entitled to is not
/// something this library decides.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatedClaim {
    /// The claim's identifier.
    pub id: String,
    /// The actor the claim says made it (a UUID). Both protocol versions.
    pub claimant: String,
    /// `wvp-0.2`: the values the claim supplies for the contract's declared
    /// inputs, as the JSON object the package carries, with every value in
    /// its protocol type (numbers are strings in the contract language's
    /// spelling; nothing is converted). A complete report means they fit the
    /// contract's declarations.
    ///
    /// `None` for `wvp-0.1`, whose claims have no inputs. It is never an
    /// empty object standing in for "not available".
    pub inputs: Option<Value>,
}

/// What a well-formed package says about itself.
///
/// Everything outside `report` is **stated by the package**: written by
/// whoever produced it and, unless `report` says otherwise, checked by
/// nobody. It is for inspection. In particular `recorded_decision` is the
/// issuer's claim; only `report.decision` can say it was reproduced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inspection {
    /// What verification under the given options established.
    pub report: Report,
    /// The claim.
    pub claim: StatedClaim,
    /// The decision `decision.json` carries, as text.
    pub recorded_decision: String,
    /// The evidence statements, in package order.
    pub statements: Vec<StatementSummary>,
    /// The identifiers of the keys said to have signed the decision, as the
    /// package states them. Use [`Inspection::verified_issuer_keys`] for keys
    /// whose signatures were actually verified.
    pub issuer_signature_keys: Vec<String>,
    /// How the claim names its contract: a contract identifier in `wvp-0.1`,
    /// `sha-256:<hex>` (as stated) in `wvp-0.2`.
    pub contract_reference: String,
    /// Evidence the claim lists that the package does not carry.
    pub claimed_but_absent: Vec<String>,
}

impl Inspection {
    /// The keys that signed the decision, if every carried signature was
    /// verified under the relying party's registry.
    ///
    /// `Some` only when the report establishes the issuer signature. Then it
    /// is every key the package lists: verification refuses a package in
    /// which any one signature does not count, so there is never a mix of
    /// verified and unverified keys. `None` when no signature was checked
    /// (no registry) and when the package carries none.
    #[must_use]
    pub fn verified_issuer_keys(&self) -> Option<&[String]> {
        matches!(
            self.report.issuer_signature,
            IssuerSignature::Established { .. }
        )
        .then_some(self.issuer_signature_keys.as_slice())
    }
}

fn member_text(value: &Value, path: &[&str]) -> String {
    path.iter()
        .try_fold(value, |value, name| value.as_object()?.get(name))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn summaries<B>(
    evidence: &[Evidence<'_, B>],
    claimed: &[&str],
    describe: impl Fn(&Evidence<'_, B>) -> String,
) -> Vec<StatementSummary> {
    evidence
        .iter()
        .map(|item| {
            let statement = &item.statement;
            StatementSummary {
                id: statement.id.to_owned(),
                kind: statement.kind.to_owned(),
                source: statement.source_system.to_owned(),
                issuer: statement.issuer.to_owned(),
                key_id: statement.signature.key_id.to_owned(),
                observed_at: member_text(statement.statement, &["observedAt", "value"]),
                body: describe(item),
                claimed: claimed.contains(&statement.id),
            }
        })
        .collect()
}

fn absent<B>(claimed: &[&str], evidence: &[Evidence<'_, B>]) -> Vec<String> {
    claimed
        .iter()
        .filter(|id| !evidence.iter().any(|item| item.statement.id == **id))
        .map(|id| (*id).to_owned())
        .collect()
}

/// Verifies a package under `options` and also returns what it states.
///
/// A package that [`verify`] refuses is refused here too: there is no
/// inspection of a package whose contents are not the ones it commits to.
pub fn inspect(package: &[u8], options: &Options<'_>) -> Result<Inspection, Rejection> {
    let report = verify(package, options)?;
    let value = container::read(package, &options.limits)?;
    let checked = container::check(&value, options.protocol)?;
    let malformed = |error: verified_protocol::ShapeError| {
        Rejection::Refused(refusal(RefusalCode::MalformedComponent, error.to_string()))
    };
    let (decision, statements, contract_reference, claimed_but_absent, inputs, claim_value) =
        match checked.protocol {
            ProtocolVersion::V0_1 => {
                let components = v01::Components::read(checked.files).map_err(malformed)?;
                let claim = &components.claim;
                // The body's case is its one member's name.
                let case = |item: &Evidence<'_, v01::Body<'_>>| {
                    let mut names = item
                        .body_value
                        .as_object()
                        .into_iter()
                        .flat_map(verified_canonical::Object::keys);
                    names.next().unwrap_or_default().to_owned()
                };
                (
                    components.decision.value,
                    summaries(&components.evidence, &claim.evidence, case),
                    claim.contract_id.to_owned(),
                    absent(&claim.evidence, &components.evidence),
                    None,
                    claim.value,
                )
            }
            ProtocolVersion::V0_2 => {
                let components = v02::Components::read(checked.files).map_err(malformed)?;
                let claim = &components.claim;
                let describe = |item: &Evidence<'_, v02::Body<'_>>| match item.body {
                    v02::Body::Record { kind, .. } => format!("record of kind {kind}"),
                    v02::Body::Complete { kind, as_of } => {
                        format!("completeness of kind {kind} as of {as_of}")
                    }
                };
                (
                    components.decision.value,
                    summaries(&components.evidence, &claim.evidence, describe),
                    format!("{}:{}", claim.contract.algorithm, claim.contract.hex),
                    absent(&claim.evidence, &components.evidence),
                    Some(claim.inputs.clone()),
                    claim.value,
                )
            }
        };
    let claim = StatedClaim {
        id: member_text(claim_value, &["id", "value"]),
        claimant: member_text(claim_value, &["claimant", "value"]),
        inputs,
    };
    Ok(Inspection {
        report,
        claim,
        recorded_decision: member_text(decision, &["decision"]),
        statements,
        issuer_signature_keys: checked
            .signatures
            .iter()
            .map(|signature| signature.key_id.to_owned())
            .collect(),
        contract_reference,
        claimed_but_absent,
    })
}
