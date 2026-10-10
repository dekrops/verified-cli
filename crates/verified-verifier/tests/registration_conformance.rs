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
//! Only `vectors.json` is run. The corpus's other files (log segments,
//! audits, notices, disputes and unit checks) are for parts of the protocol
//! this project does not implement yet.

#![allow(clippy::print_stderr)] // progress notes for whoever runs the corpus

use std::path::PathBuf;

use verified_canonical::{Limits, Object, Sha256Digest, Value, parse};
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
