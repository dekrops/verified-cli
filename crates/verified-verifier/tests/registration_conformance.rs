// SPDX-License-Identifier: Apache-2.0

//! The claim registration v1 conformance corpus: registrations.
//!
//! The corpus is published in `dekrops/wvp` and is not copied here; see
//! `conformance/README.md`. Point `VERIFIED_CONFORMANCE_DIR` at a directory
//! holding `claim-registration/v1` to run this test. With
//! `VERIFIED_CONFORMANCE_REQUIRED=1` its absence is a failure.
//!
//! Expected outcomes are read from the vectors and never adjusted here.
//! Each case's whole expectation is compared: the refusal code, or every
//! fact of the registration.
//!
//! `vectors.json` (registrations), `log.json` (log segments and held
//! entries) and the three files of audits (`audit.json`, `notice.json`,
//! `dispute.json`) are run here. `unit.json` is run by `verified-work-unit`.

#![allow(clippy::print_stderr)] // progress notes for whoever runs the corpus

use std::path::PathBuf;

use verified_canonical::{Limits, Object, Sha256Digest, Value, parse};
use verified_verifier::registration::audit::{AuditedClaim, audit};
use verified_verifier::registration::log::{Inclusion, LogCheck, check_log};
use verified_verifier::registration::{Registration, RegistrationTrust, verify_registration};

fn corpus() -> Option<PathBuf> {
    let Some(dir) = std::env::var_os("VERIFIED_CONFORMANCE_DIR") else {
        assert!(
            std::env::var_os("VERIFIED_CONFORMANCE_REQUIRED").is_none(),
            "VERIFIED_CONFORMANCE_REQUIRED is set but VERIFIED_CONFORMANCE_DIR is not"
        );
        eprintln!("skipped: VERIFIED_CONFORMANCE_DIR is not set");
        return None;
    };
    Some(PathBuf::from(dir).join("claim-registration").join("v1"))
}

fn member<'a>(value: &'a Value, name: &str, at: &str) -> &'a Value {
    value
        .as_object()
        .and_then(|o| o.get(name))
        .unwrap_or_else(|| panic!("{at}: no {name}"))
}

fn text<'a>(value: &'a Value, name: &str, at: &str) -> &'a str {
    member(value, name, at)
        .as_str()
        .unwrap_or_else(|| panic!("{at}: {name} is not text"))
}

fn string(s: &str) -> Value {
    Value::String(s.to_owned())
}

fn object<const N: usize>(members: [(&str, Value); N]) -> Value {
    Value::Object(
        members
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect::<Object>(),
    )
}

fn wrapped(s: &str) -> Value {
    object([("value", string(s))])
}

fn digest(digest: &Sha256Digest) -> Value {
    object([
        ("algorithm", string(Sha256Digest::ALGORITHM)),
        ("hex", string(&digest.to_hex())),
    ])
}

fn facts(registration: &Registration) -> Value {
    object([
        ("accept", Value::Bool(true)),
        ("agreement", digest(&registration.agreement)),
        ("claim", wrapped(&registration.claim_id)),
        ("claimDigest", digest(&registration.claim)),
        ("receiptDigest", digest(&registration.receipt)),
        ("receivedAt", wrapped(&registration.received_at)),
        ("registry", string(&registration.registry)),
        ("respondBy", wrapped(&registration.respond_by)),
        ("respondent", wrapped(&registration.respondent)),
        ("sequence", Value::Integer(registration.sequence.into())),
    ])
}

#[test]
fn every_registration_case_is_reproduced() {
    let Some(corpus) = corpus() else { return };
    let path = corpus.join("vectors.json");
    let at = path.display().to_string();
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{at}: {e}"));
    let vectors = parse(&bytes, &Limits::DEFAULT).unwrap_or_else(|e| panic!("{at}: {e}"));
    let trust = RegistrationTrust::from_value(member(&vectors, "trust", &at))
        .unwrap_or_else(|e| panic!("{at}: {e}"));

    let cases = member(&vectors, "cases", &at)
        .as_array()
        .unwrap_or_else(|| panic!("{at}: cases is not a list"));
    assert!(!cases.is_empty(), "{at}: no cases");
    let (mut accepted, mut refused) = (0, 0);
    for case in cases {
        let at = format!("{at}: {}", text(case, "name", &at));
        let outcome = verify_registration(
            text(case, "agreementJson", &at).as_bytes(),
            text(case, "claimJson", &at).as_bytes(),
            text(case, "receiptJson", &at).as_bytes(),
            &trust,
        );
        let actual = match &outcome {
            Ok(registration) => {
                accepted += 1;
                facts(registration)
            }
            Err(refusal) => {
                refused += 1;
                object([
                    ("accept", Value::Bool(false)),
                    ("error", string(refusal.code.as_str())),
                ])
            }
        };
        assert_eq!(&actual, member(case, "expected", &at), "{at}: {outcome:?}");
    }
    eprintln!(
        "claim-registration-1: {} registration cases reproduced ({accepted} accepted, {refused} refused)",
        cases.len()
    );
}

fn optional_text<'a>(case: &'a Value, name: &str, at: &str) -> Option<&'a [u8]> {
    match member(case, name, at) {
        Value::Null => None,
        text => Some(
            text.as_str()
                .unwrap_or_else(|| panic!("{at}: {name} is not text"))
                .as_bytes(),
        ),
    }
}

fn log_facts(check: &LogCheck) -> Value {
    match check.inclusion {
        None => object([
            ("accept", Value::Bool(true)),
            ("first", Value::Integer(check.segment.first.into())),
            ("head", digest(&check.segment.head)),
            ("last", Value::Integer(check.segment.last.into())),
            ("registry", string(&check.segment.registry)),
        ]),
        Some(Inclusion::Included) => object([
            ("accept", Value::Bool(true)),
            ("inclusion", string("INCLUDED")),
        ]),
        Some(Inclusion::NotCovered) => object([
            ("accept", Value::Bool(true)),
            ("inclusion", string("NOT_COVERED")),
        ]),
        Some(Inclusion::Equivocation { held, logged }) => object([
            ("accept", Value::Bool(true)),
            ("held", digest(&held)),
            ("inclusion", string("EQUIVOCATION")),
            ("logged", digest(&logged)),
        ]),
    }
}

#[test]
fn every_log_case_is_reproduced() {
    let Some(corpus) = corpus() else { return };
    let read = |name: &str| {
        let path = corpus.join(name);
        let at = path.display().to_string();
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{at}: {e}"));
        (
            parse(&bytes, &Limits::DEFAULT).unwrap_or_else(|e| panic!("{at}: {e}")),
            at,
        )
    };
    // The log cases are stated under the keys of the registration vectors.
    let (vectors, at) = read("vectors.json");
    let trust = RegistrationTrust::from_value(member(&vectors, "trust", &at))
        .unwrap_or_else(|e| panic!("{at}: {e}"));

    let (log, at) = read("log.json");
    let cases = member(&log, "cases", &at)
        .as_array()
        .unwrap_or_else(|| panic!("{at}: cases is not a list"));
    assert!(!cases.is_empty(), "{at}: no cases");
    for case in cases {
        let at = format!("{at}: {}", text(case, "name", &at));
        let entries: Vec<&[u8]> = member(case, "receiptsJson", &at)
            .as_array()
            .unwrap_or_else(|| panic!("{at}: receiptsJson is not a list"))
            .iter()
            .map(|entry| {
                entry
                    .as_str()
                    .unwrap_or_else(|| panic!("{at}: an entry is not text"))
                    .as_bytes()
            })
            .collect();
        let outcome = check_log(
            &entries,
            optional_text(case, "anchorJson", &at),
            optional_text(case, "heldJson", &at),
            &trust,
        );
        let actual = match &outcome {
            Ok(check) => log_facts(check),
            Err(refusal) => object([
                ("accept", Value::Bool(false)),
                ("error", string(refusal.code.as_str())),
            ]),
        };
        assert_eq!(&actual, member(case, "expected", &at), "{at}: {outcome:?}");
    }
    eprintln!("claim-registration-1: {} log cases reproduced", cases.len());
}

fn audited(claims: &[AuditedClaim]) -> Value {
    let claims = claims
        .iter()
        .map(|claim| {
            let mut members = vec![
                ("claim", digest(&claim.claim)),
                ("id", wrapped(&claim.id)),
                ("position", Value::Integer(claim.position.into())),
                ("respondBy", wrapped(&claim.respond_by)),
                ("state", string(claim.state.as_str())),
            ];
            if let Some(dispute) = claim.dispute {
                members.push(("dispute", string(dispute.as_str())));
            }
            Value::Object(
                members
                    .into_iter()
                    .map(|(k, v)| (k.to_owned(), v))
                    .collect::<Object>(),
            )
        })
        .collect();
    object([
        ("accept", Value::Bool(true)),
        ("claims", Value::Array(claims)),
    ])
}

#[test]
fn every_audit_case_is_reproduced() {
    let Some(corpus) = corpus() else { return };
    let read = |name: &str| {
        let path = corpus.join(name);
        let at = path.display().to_string();
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{at}: {e}"));
        (
            parse(&bytes, &Limits::DEFAULT).unwrap_or_else(|e| panic!("{at}: {e}")),
            at,
        )
    };
    let (vectors, vectors_at) = read("vectors.json");
    let lists = [
        "agreementsJson",
        "claimsJson",
        "responsesJson",
        "noticesJson",
        "documentsJson",
    ];
    for name in ["audit.json", "notice.json", "dispute.json"] {
        let (file, at) = read(name);
        // A file states its own trust configuration, or uses the
        // registration vectors'.
        let own = file.as_object().and_then(|o| o.get("trust"));
        let trust = RegistrationTrust::from_value(
            own.unwrap_or_else(|| member(&vectors, "trust", &vectors_at)),
        )
        .unwrap_or_else(|e| panic!("{at}: {e}"));
        let texts = |from: &Value, list: &str| -> Vec<Vec<u8>> {
            from.as_object()
                .and_then(|o| o.get(list))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|text| {
                    text.as_str()
                        .unwrap_or_else(|| panic!("{at}: {list} holds a non-text"))
                        .as_bytes()
                        .to_vec()
                })
                .collect()
        };
        let cases = member(&file, "cases", &at)
            .as_array()
            .unwrap_or_else(|| panic!("{at}: cases is not a list"));
        assert!(!cases.is_empty(), "{at}: no cases");
        for case in cases {
            let case_at = format!("{at}: {}", text(case, "name", &at));
            let entries = texts(case, "entriesJson");
            let entries: Vec<&[u8]> = entries.iter().map(Vec::as_slice).collect();
            // Documents of a case, then those the file states for all cases.
            let documents: Vec<Vec<u8>> = lists
                .iter()
                .flat_map(|list| texts(case, list).into_iter().chain(texts(&file, list)))
                .collect();
            let documents: Vec<&[u8]> = documents.iter().map(Vec::as_slice).collect();
            let outcome = audit(&entries, &documents, &trust);
            let actual = match &outcome {
                Ok(claims) => audited(claims),
                Err(refusal) => object([
                    ("accept", Value::Bool(false)),
                    ("error", string(refusal.code.as_str())),
                ]),
            };
            assert_eq!(
                &actual,
                member(case, "expected", &case_at),
                "{case_at}: {:?}",
                outcome.as_ref().err()
            );
        }
        eprintln!(
            "claim-registration-1: {} audit cases of {name} reproduced",
            cases.len()
        );
    }
}
