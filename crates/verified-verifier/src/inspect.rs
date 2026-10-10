// SPDX-License-Identifier: Apache-2.0

//! Looking at what a package says, as distinct from what was established.

use verified_canonical::Value;
use verified_protocol::{Evidence, ProtocolVersion, RefusalCode, v01, v02};

use crate::container::{self, Options, Rejection, refusal};
use crate::report::Report;
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
    /// The decision `decision.json` carries, as text.
    pub recorded_decision: String,
    /// The evidence statements, in package order.
    pub statements: Vec<StatementSummary>,
    /// The identifiers of the keys said to have signed the decision.
    pub issuer_signature_keys: Vec<String>,
}

fn member_text(value: &Value, path: &[&str]) -> String {
    path.iter()
        .try_fold(value, |value, name| value.as_object()?.get(name))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn summaries<B>(evidence: &[Evidence<'_, B>]) -> Vec<StatementSummary> {
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
            }
        })
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
    let (decision, statements) = match checked.protocol {
        ProtocolVersion::V0_1 => {
            let components = v01::Components::read(checked.files).map_err(malformed)?;
            (components.decision.value, summaries(&components.evidence))
        }
        ProtocolVersion::V0_2 => {
            let components = v02::Components::read(checked.files).map_err(malformed)?;
            (components.decision.value, summaries(&components.evidence))
        }
    };
    Ok(Inspection {
        report,
        recorded_decision: member_text(decision, &["decision"]),
        statements,
        issuer_signature_keys: checked
            .signatures
            .iter()
            .map(|signature| signature.key_id.to_owned())
            .collect(),
    })
}
