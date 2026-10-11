// SPDX-License-Identifier: Apache-2.0

//! A report as JSON: the `verify` contract of `docs/sdk/json-output.md`.
//!
//! One definition, so that the command line and every binding print the
//! same members for the same report. Every value is read off the report;
//! nothing here decides anything.

use verified_canonical::{Integer, Object, Value};

use crate::json::{digest, object, text};
use crate::report::{
    DecisionFinding, Evaluation, Finding, IssuerSignature, NotChecked, Report, Reproduced,
};

fn count(n: usize) -> Value {
    // A count of things in a package that was read under a byte limit.
    Value::Integer(Integer::from(i64::try_from(n).unwrap_or(i64::MAX)))
}

fn texts<S: AsRef<str>>(items: &[S]) -> Value {
    Value::Array(items.iter().map(|s| text(s.as_ref())).collect())
}

fn optional(value: Option<&str>) -> Value {
    value.map_or(Value::Null, text)
}

fn not_checked(reason: NotChecked) -> Object {
    let mut members = Object::new();
    members.insert("status", text("not_checked"));
    members.insert("reason", text(reason.as_str()));
    members
}

impl NotChecked {
    /// The reason as the JSON output names it. Stable.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoTrustRegistry => "no_trust_registry",
        }
    }
}

impl Finding {
    /// `{ "status": "established" }`, or `not_checked` with its `reason`.
    #[must_use]
    pub fn to_value(self) -> Value {
        match self {
            Self::Established => object([("status", text("established"))]),
            Self::NotChecked(reason) => Value::Object(not_checked(reason)),
        }
    }
}

impl DecisionFinding {
    /// `established` with the reproduced `decision` and how it was reached,
    /// or `not_checked` with its `reason`. When not checked there is no
    /// `decision`: the decision a package carries is never echoed.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let (decision, evaluation) = match self {
            Self::NotChecked(reason) => return Value::Object(not_checked(*reason)),
            Self::Reproduced(Reproduced {
                decision,
                evaluation,
            }) => (decision, evaluation),
        };
        let mut members = Object::new();
        members.insert("status", text("established"));
        members.insert("decision", text(decision.as_str()));
        match evaluation {
            Evaluation::OrderTransition { conditions } => {
                let conditions = conditions.iter().map(|c| {
                    object([
                        ("evidence", texts(&c.evidence)),
                        ("holds", Value::Bool(c.holds)),
                        ("id", text(c.id)),
                    ])
                });
                members.insert("conditions", Value::Array(conditions.collect()));
            }
            Evaluation::WorkContract {
                requirements,
                ignored,
                conflicts,
            } => {
                let requirements = requirements
                    .iter()
                    .map(|r| object([("id", text(&r.id)), ("value", text(r.value.as_str()))]));
                let conflicts = conflicts.iter().map(|c| {
                    object([
                        ("facts", texts(&c.facts)),
                        ("kind", text(&c.kind)),
                        ("resolvedTo", optional(c.resolved_to.as_deref())),
                    ])
                });
                members.insert("requirements", Value::Array(requirements.collect()));
                members.insert("ignored", texts(ignored));
                members.insert("conflicts", Value::Array(conflicts.collect()));
            }
        }
        Value::Object(members)
    }
}

impl IssuerSignature {
    /// `established` with `count`, `absent`, or `not_checked` with its
    /// `reason` and how many signatures the package `carried`.
    #[must_use]
    pub fn to_value(self) -> Value {
        match self {
            Self::Established { count: n } => {
                object([("count", count(n)), ("status", text("established"))])
            }
            Self::Absent => object([("status", text("absent"))]),
            Self::NotChecked { carried, reason } => {
                let mut members = not_checked(reason);
                members.insert("carried", count(carried));
                Value::Object(members)
            }
        }
    }
}

impl Report {
    /// The report as the `verify` command's JSON output states it
    /// (`docs/sdk/json-output.md`): `outcome` (`complete` or `incomplete`),
    /// the package's identity, `components`, `properties`,
    /// `expectationsMet`, and for `wvp-0.2` `contract` and, when computed,
    /// `workRecord` and `recordMatched`.
    ///
    /// Members only the command line adds (`note`, `requiredDecision`) are
    /// not here. `properties.sourceTruthfulness` always is, and is never
    /// established.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let met = &self.expectations_met;
        let components = self.components.iter().map(|c| {
            object([
                ("digest", digest(&c.digest)),
                ("path", text(c.path.as_str())),
            ])
        });
        let mut members = Object::new();
        let outcome = if self.is_complete() {
            "complete"
        } else {
            "incomplete"
        };
        members.insert("outcome", text(outcome));
        members.insert("protocol", text(self.protocol.identifier()));
        members.insert("protocolStatus", text("draft"));
        members.insert("packageId", text(&self.package_id.to_string()));
        members.insert("tenant", text(&self.tenant));
        members.insert("claim", text(&self.claim));
        members.insert("statements", count(self.statements));
        members.insert("components", Value::Array(components.collect()));
        members.insert(
            "properties",
            object([
                ("decisionReproduced", self.decision.to_value()),
                ("evidenceSignatures", self.evidence_signatures.to_value()),
                ("issuerSignature", self.issuer_signature.to_value()),
                ("packageIntegrity", self.integrity.to_value()),
                ("signerAuthority", self.signer_authority.to_value()),
                (
                    "sourceTruthfulness",
                    object([
                        ("reason", text("no_check_can_establish_it")),
                        ("status", text("not_established")),
                    ]),
                ),
            ]),
        );
        members.insert(
            "expectationsMet",
            object([
                ("claim", optional(met.claim.as_deref())),
                (
                    "contract",
                    met.contract.as_ref().map_or(Value::Null, digest),
                ),
                ("tenant", optional(met.tenant.as_deref())),
            ]),
        );
        if let Some(contract) = &self.contract {
            members.insert(
                "contract",
                object([
                    ("digest", digest(&contract.digest)),
                    ("id", text(&contract.id)),
                    ("version", text(&contract.version)),
                ]),
            );
        }
        if let Some(record) = &self.work_record {
            members.insert("workRecord", record.clone());
            members.insert("recordMatched", Value::Bool(self.record_matched));
        }
        Value::Object(members)
    }
}
