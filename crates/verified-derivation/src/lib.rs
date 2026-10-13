// SPDX-License-Identifier: Apache-2.0

//! Experimental replay of a recomputed Cedar authorization.
//!
//! A package carries a contract, signed evidence statements, a profile, and what a first
//! verifier arrived at. This crate believes none of the last part. It authenticates every
//! statement against the caller's trust registry, prepares the authorization question from the
//! statements, asks Cedar, evaluates the contract, and only then compares its own commitments
//! with the presented ones.
//!
//! It is written from the method's description, with the `cedar-policy` crate and this
//! workspace's evidence code. It shares no code with the first implementation, which is in
//! Scala. It is **not** a protocol verifier: the package format and the
//! step of deriving a record are not part of any specification.

mod cedar;
mod prepare;

use verified_canonical::{Object, Sha256Digest, Value, cmp_keys};
use verified_contract::Contract;
use verified_verifier::{Trust, evidence};

pub use prepare::Derivation;

/// The package format this crate replays.
pub const PACKAGE: &str = "verified-recomputation-package-experimental-2";
/// The format of a derived evaluation's core.
pub const EVALUATION: &str = "verified-derived-evaluation-experimental-2";
/// The source name of derived decisions. Reserved: a signed statement that claims it is not read.
pub const DERIVED_SOURCE: &str = "authorization-recomputation";

/// Why a replay did not reproduce what was presented, and at which stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// `PACKAGE`, `EVIDENCE`, `CONTRACT`, `PROFILE`, `DERIVATION` or `EVALUATION`.
    pub stage: &'static str,
    /// What went wrong there.
    pub code: String,
    /// Where the computed and the presented values part, when that is the failure.
    pub detail: String,
}

/// The members in which two objects differ, with both values: a reproducible counterexample.
fn difference(what: &str, presented: Option<&Value>, computed: &Value) -> String {
    let (Some(Value::Object(theirs)), Value::Object(ours)) = (presented, computed) else {
        return format!("{what}: nothing comparable was presented");
    };
    let mut names: Vec<&str> = theirs
        .keys()
        .chain(ours.keys())
        .filter(|k| theirs.get(k) != ours.get(k))
        .collect();
    names.sort_unstable();
    names.dedup();
    names
        .into_iter()
        .map(|name| {
            let show = |v: Option<&Value>| {
                v.map_or_else(|| "absent".to_owned(), Value::to_canonical_string)
            };
            format!(
                "{what}.{name}: presented {} computed {}",
                show(theirs.get(name)),
                show(ours.get(name))
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn fail<T>(stage: &'static str, code: impl Into<String>) -> Result<T, Failure> {
    Err(Failure {
        stage,
        code: code.into(),
        detail: String::new(),
    })
}

/// What this crate computed from a package.
#[derive(Debug, Clone)]
pub struct Replayed {
    /// The core of the derived evaluation: what two implementations must agree on.
    pub core: Value,
    /// Its digest.
    pub commitment: Sha256Digest,
    /// The contract's decision.
    pub decision: String,
    /// One recomputed authorization per work event.
    pub derivations: Vec<Derivation>,
}

pub(crate) fn text(value: &str) -> Value {
    Value::String(value.to_owned())
}

pub(crate) fn object<const N: usize>(members: [(&str, Value); N]) -> Value {
    Value::Object(
        members
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect::<Object>(),
    )
}

pub(crate) fn digest(digest: &Sha256Digest) -> Value {
    object([
        ("algorithm", text(Sha256Digest::ALGORITHM)),
        ("hex", text(&digest.to_hex())),
    ])
}

pub(crate) fn member<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    value.as_object()?.get(name)
}

pub(crate) fn string<'a>(value: &'a Value, name: &str) -> Option<&'a str> {
    member(value, name)?.as_str()
}

/// A number as the contract language spells one: a decimal string.
pub(crate) fn number(value: Option<&Value>) -> Option<i128> {
    let spelling = value?.as_str()?;
    let digits = spelling.strip_prefix('-').unwrap_or(spelling);
    let plain = digits == "0"
        || (!digits.is_empty()
            && digits.len() <= 19
            && !digits.starts_with('0')
            && digits.bytes().all(|b| b.is_ascii_digit()));
    // The language's own bound: a magnitude below 2^63, and no negative zero.
    if plain && spelling != "-0" {
        spelling
            .parse::<i128>()
            .ok()
            .filter(|n| n.unsigned_abs() < 1 << 63)
    } else {
        None
    }
}

/// One admitted statement's body.
pub(crate) enum Body<'a> {
    Record { kind: &'a str, fields: &'a Object },
    Complete { kind: &'a str, as_of: &'a str },
}

/// One authenticated statement with its body.
pub(crate) struct Item<'a> {
    pub(crate) id: &'a str,
    pub(crate) source: &'a str,
    pub(crate) digest: Sha256Digest,
    pub(crate) body: Body<'a>,
}

impl Item<'_> {
    pub(crate) fn fact_id(&self) -> String {
        format!("e-{}", self.id)
    }
}

fn body(value: &Value) -> Option<Body<'_>> {
    let outer = value.as_object()?;
    if outer.has_exactly(&["record"]) {
        let record = outer.get("record")?.as_object()?;
        record.has_exactly(&["fields", "kind"]).then_some(())?;
        Some(Body::Record {
            kind: record.get("kind")?.as_str()?,
            fields: record.get("fields")?.as_object()?,
        })
    } else if outer.has_exactly(&["complete"]) {
        let complete = outer.get("complete")?.as_object()?;
        complete.has_exactly(&["asOf", "kind"]).then_some(())?;
        Some(Body::Complete {
            kind: complete.get("kind")?.as_str()?,
            as_of: complete.get("asOf")?.as_str()?,
        })
    } else {
        None
    }
}

fn malformed(name: &str) -> Failure {
    Failure {
        stage: "PACKAGE",
        code: format!("MALFORMED_{}", name.to_uppercase()),
        detail: String::new(),
    }
}

fn evidence_failure(code: &str) -> Failure {
    Failure {
        stage: "EVIDENCE",
        code: code.to_owned(),
        detail: String::new(),
    }
}

fn not_reproduced(stage: &'static str, detail: String) -> Failure {
    Failure {
        stage,
        code: "NOT_REPRODUCED".to_owned(),
        detail,
    }
}

/// The statements a tenant's question may be read from.
struct Admitted<'a> {
    items: Vec<Item<'a>>,
    /// Why the others are not read.
    not_read: Vec<String>,
    /// The digest of the digests of the admitted statements, in the order of their identifiers.
    commitment: Sha256Digest,
}

/// Every statement against the registry, then the conditions for reading it: this tenant's,
/// with the body that was signed, and no completeness vouched for a time after it was observed.
fn admit<'a>(listed: &'a [Value], tenant: &str, trust: &Trust) -> Result<Admitted<'a>, Failure> {
    let mut authenticated = Vec::new();
    for entry in listed {
        // The body first, then the signature: the order of the first implementation.
        let carried = member(entry, "body").ok_or_else(|| evidence_failure("MALFORMED"))?;
        let parsed = body(carried).ok_or_else(|| evidence_failure("MALFORMED"))?;
        let signed = member(entry, "statement").unwrap_or(&Value::Null);
        let authentic = evidence::authenticate(signed, trust)
            .map_err(|refusal| evidence_failure(refusal.code.as_str()))?;
        authenticated.push((authentic, carried, parsed));
    }
    authenticated.sort_by(|a, b| cmp_keys(a.0.statement().id, b.0.statement().id));
    // One statement, one identifier: two statements with the same one are not two records.
    if authenticated
        .windows(2)
        .any(|pair| pair[0].0.statement().id == pair[1].0.statement().id)
    {
        return Err(evidence_failure("DUPLICATE_EVIDENCE_ID"));
    }

    let (mut items, mut not_read, mut digests) = (Vec::new(), Vec::new(), Vec::new());
    for (authentic, carried, parsed) in authenticated {
        let statement = authentic.statement();
        let observed = i128::from(statement.observed_at.epoch_seconds());
        let reason = if statement.tenant != tenant {
            Some("FOREIGN_TENANT_EVIDENCE")
        } else if !statement.payload.states(&carried.digest()) {
            Some("PAYLOAD_MISMATCH")
        } else if let Body::Complete { as_of, .. } = &parsed
            && number(Some(&text(as_of))).is_none_or(|at| at > observed)
        {
            Some("COMPLETENESS_AFTER_OBSERVATION")
        } else {
            None
        };
        if let Some(reason) = reason {
            not_read.push(format!("{reason}: e-{} is not read", statement.id));
            continue;
        }
        digests.push(digest(&statement.digest()));
        // A signed statement that claims to be a derivation is admitted and never read.
        if statement.source_system != DERIVED_SOURCE {
            items.push(Item {
                id: statement.id,
                source: statement.source_system,
                digest: statement.digest(),
                body: parsed,
            });
        }
    }
    Ok(Admitted {
        items,
        not_read,
        commitment: Value::Array(digests).digest(),
    })
}

/// Each presented report must be the one recomputed here: its core, and the digest it claims.
fn compare_derivations(presented: &Value, computed: &[Derivation]) -> Result<Value, Failure> {
    let reports = member(presented, "derivations")
        .and_then(Value::as_array)
        .unwrap_or(&[]);
    let same = reports.len() == computed.len()
        && reports.iter().zip(computed).all(|(report, computed)| {
            member(report, "core") == Some(&computed.core)
                && member(report, "commitment") == Some(&digest(&computed.commitment))
        });
    if !same {
        let detail = computed
            .iter()
            .enumerate()
            .map(|(at, computed)| {
                difference(
                    &format!("derivation {}", computed.correlation),
                    reports.get(at).and_then(|report| member(report, "core")),
                    &computed.core,
                )
            })
            .filter(|detail| !detail.is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        return Err(not_reproduced("DERIVATION", detail));
    }
    let commitments = Value::Array(computed.iter().map(|d| digest(&d.commitment)).collect());
    let listed = member(presented, "core").and_then(|core| member(core, "derivations"));
    if listed != Some(&commitments) {
        return Err(not_reproduced("DERIVATION", String::new()));
    }
    Ok(commitments)
}

/// Whether a predicate quantifies over records of a kind.
fn quantifies_over(predicate: &Value, kind: &str) -> bool {
    match predicate {
        Value::Object(members) => {
            let quantifier = members.get("exists").is_some() || members.get("forall").is_some();
            (quantifier && members.get("in").and_then(Value::as_str) == Some(kind))
                || members
                    .iter()
                    .any(|(_, inner)| quantifies_over(inner, kind))
        }
        Value::Array(items) => items.iter().any(|inner| quantifies_over(inner, kind)),
        _ => false,
    }
}

/// Which requirements depend on which derivations, read from the contract itself.
///
/// A requirement depends on the derived records if its predicate quantifies over their kind and
/// the contract accepts the reserved source for that kind. Such a requirement depends on every
/// derivation, including one that yielded no record: the absence of a record is what the
/// quantifier then sees. This is exact about which requirements can be affected and conservative
/// about which derivation affected them; no single witness is named.
fn bindings(contract: &Value, kind: &str, derivations: &[Derivation]) -> Value {
    let accepted = member(contract, "evidence")
        .and_then(|evidence| member(evidence, "sources"))
        .and_then(|sources| member(sources, kind))
        .and_then(Value::as_array)
        .is_some_and(|sources| sources.iter().any(|s| s.as_str() == Some(DERIVED_SOURCE)));
    let depended: Vec<Value> = derivations
        .iter()
        .map(|d| {
            object([
                ("correlation", text(&d.correlation)),
                ("commitment", digest(&d.commitment)),
                ("record", d.record().map_or(Value::Null, text)),
            ])
        })
        .collect();
    let mut requirements: Vec<&str> = member(contract, "requires")
        .and_then(Value::as_array)
        .unwrap_or(&[])
        .iter()
        .filter(|requirement| {
            accepted && member(requirement, "predicate").is_some_and(|p| quantifies_over(p, kind))
        })
        .filter_map(|requirement| string(requirement, "id"))
        .collect();
    requirements.sort_by(|a, b| cmp_keys(a, b));
    Value::Array(
        requirements
            .into_iter()
            .map(|id| {
                object([
                    ("requirement", text(id)),
                    (
                        "method",
                        object([
                            ("name", text(prepare::METHOD)),
                            ("version", text(prepare::METHOD_VERSION)),
                        ]),
                    ),
                    ("derivations", Value::Array(depended.clone())),
                ])
            })
            .collect(),
    )
}

/// Replay a package against the caller's trust registry.
///
/// Stages, in order: the package's shape; every statement against the registry; the contract and
/// the profile against what the presented result commits to; every derivation, recomputed; the
/// contract, evaluated again. Whatever cannot be done is a failure, never a pass.
///
/// # Errors
///
/// The first stage that does not hold, with a code.
pub fn replay(package: &Value, trust: &Trust) -> Result<Replayed, Failure> {
    if string(package, "package") != Some(PACKAGE) {
        return fail("PACKAGE", "UNSUPPORTED_PACKAGE");
    }
    let field = |name: &str| member(package, name).ok_or_else(|| malformed(name));
    let tenant = field("tenant")?
        .as_str()
        .ok_or_else(|| malformed("tenant"))?;
    let inputs = field("inputs")?;
    let decision_kind = field("decisionKind")?
        .as_str()
        .ok_or_else(|| malformed("decisionKind"))?;
    let profile_value = field("profile")?;
    let profile = prepare::Profile::read(profile_value).ok_or_else(|| malformed("profile"))?;
    let listed = field("statements")?
        .as_array()
        .ok_or_else(|| malformed("statements"))?;
    let presented = field("presented")?;
    let presented_core = member(presented, "core").unwrap_or(&Value::Null);

    let admitted = admit(listed, tenant, trust)?;

    // The contract and the profile, and what the presented result says they were.
    let contract_value = field("contract")?;
    let Ok(contract) = Contract::read(contract_value) else {
        return fail("CONTRACT", "CONTRACT_ILL_FORMED");
    };
    let contract_digest = contract_value.digest();
    let presented_contract = member(presented_core, "contract").and_then(|c| member(c, "digest"));
    if presented_contract != Some(&digest(&contract_digest)) {
        return fail("CONTRACT", "CONTRACT_MISMATCH");
    }
    if member(presented_core, "profile") != Some(&digest(&profile_value.digest())) {
        return fail("PROFILE", "PROFILE_MISMATCH");
    }

    let evaluated = prepare::evaluate(
        &contract,
        contract_value,
        inputs,
        decision_kind,
        &profile,
        &admitted.items,
        &admitted.not_read,
    )
    .map_err(|code| Failure {
        stage: "EVALUATION",
        code,
        detail: String::new(),
    })?;
    let commitments = compare_derivations(presented, &evaluated.derivations)?;

    let core = object([
        ("format", text(EVALUATION)),
        (
            "contract",
            object([
                ("id", text(contract.id())),
                ("version", text(contract.version())),
                ("digest", digest(&contract_digest)),
                ("language", text(contract.language())),
                ("semantics", text(contract.semantics())),
            ]),
        ),
        ("decisionKind", text(decision_kind)),
        ("derivedSource", text(DERIVED_SOURCE)),
        ("profile", digest(&profile_value.digest())),
        ("inputs", digest(&inputs.digest())),
        ("evidence", digest(&admitted.commitment)),
        ("derivations", commitments),
        (
            "bindings",
            bindings(contract_value, decision_kind, &evaluated.derivations),
        ),
        ("result", evaluated.result.clone()),
    ]);
    let commitment = core.digest();
    if presented_core != &core || member(presented, "commitment") != Some(&digest(&commitment)) {
        let detail = difference("evaluation", Some(presented_core), &core);
        return Err(not_reproduced("EVALUATION", detail));
    }
    Ok(Replayed {
        core,
        commitment,
        decision: evaluated.decision,
        derivations: evaluated.derivations,
    })
}

#[cfg(test)]
mod tests {
    use super::{number, text};

    #[test]
    fn a_number_is_bounded_as_the_contract_language_bounds_it() {
        let read = |spelling: &str| number(Some(&text(spelling)));
        assert_eq!(read("9223372036854775807"), Some(i128::from(i64::MAX)));
        assert_eq!(read("9223372036854775808"), None);
        assert_eq!(read("-9223372036854775808"), None);
        assert_eq!(read("01"), None);
        assert_eq!(read("0"), Some(0));
        assert_eq!(read("-0"), None);
        assert_eq!(read("-7"), Some(-7));
    }
}
