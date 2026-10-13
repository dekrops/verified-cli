// SPDX-License-Identifier: Apache-2.0

//! The example packages of `examples/derivation-replay`: each was produced by the first
//! implementation of the method, in Scala, and says what a second verifier must arrive at.
//! This is the differential test between the two. Expectations are read from the files and
//! never adjusted here.

use std::path::PathBuf;

use verified_canonical::{Limits, Value, parse};
use verified_derivation::replay;
use verified_verifier::Trust;

fn directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/derivation-replay")
}

fn read(name: &str) -> Value {
    let bytes = std::fs::read(directory().join(name)).expect("the corpus file is readable");
    parse(&bytes, &Limits::DEFAULT).expect("the corpus file is JSON")
}

fn member<'a>(value: &'a Value, name: &str) -> &'a Value {
    value
        .as_object()
        .and_then(|o| o.get(name))
        .unwrap_or(&Value::Null)
}

fn cases() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(directory())
        .expect("the examples directory exists")
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        // Every case starts with its number; the registry and the README do not.
        .filter(|name| name.starts_with(|first: char| first.is_ascii_digit()))
        .collect();
    names.sort();
    names
}

#[test]
fn every_case_replays_as_the_first_implementation_says() {
    let trust = Trust::from_value(&read("trust.json")).expect("the registry is usable");
    let names = cases();
    assert_eq!(names.len(), 21, "the corpus has 21 cases");
    let mut disagreements = Vec::new();
    for name in &names {
        let case = read(name);
        let expect = member(&case, "expect");
        let replayed = replay(member(&case, "package"), &trust);
        let agrees = match (member(expect, "replay").as_str(), &replayed) {
            (Some("REPRODUCED"), Ok(found)) => {
                member(member(expect, "commitment"), "hex").as_str()
                    == Some(found.commitment.to_hex().as_str())
                    && member(expect, "decision").as_str() == Some(found.decision.as_str())
                    && member(expect, "authorization")
                        .as_array()
                        .is_some_and(|expected| {
                            expected.len() == found.derivations.len()
                                && expected.iter().zip(&found.derivations).all(|(e, d)| {
                                    member(e, "outcome").as_str() == Some(d.outcome)
                                        && member(e, "correlation").as_str()
                                            == Some(d.correlation.as_str())
                                })
                        })
            }
            (Some("FAILED"), Err(failure)) => {
                member(expect, "stage").as_str() == Some(failure.stage)
                    && member(expect, "code").as_str() == Some(failure.code.as_str())
            }
            _ => false,
        };
        if !agrees {
            // A reproducible counterexample: the case, and where the two part.
            disagreements.push(format!(
                "{name}: {:?}",
                replayed.map(|r| r.commitment.to_hex())
            ));
        }
    }
    assert!(disagreements.is_empty(), "{}", disagreements.join("\n"));
}

#[test]
fn a_registry_that_does_not_know_a_signer_reproduces_nothing() {
    let registry = read("trust.json");
    let keys: Vec<Value> = member(&registry, "keys")
        .as_array()
        .expect("keys")
        .iter()
        .filter(|key| {
            !member(key, "sources")
                .to_canonical_string()
                .contains("policy-store")
        })
        .cloned()
        .collect();
    let without = Value::Object(
        [("keys".to_owned(), Value::Array(keys))]
            .into_iter()
            .collect(),
    );
    let trust = Trust::from_value(&without).expect("the registry is usable");
    let failure =
        replay(member(&read("01-allowed.json"), "package"), &trust).expect_err("an unknown signer");
    assert_eq!(
        (failure.stage, failure.code.as_str()),
        ("EVIDENCE", "UNKNOWN_KEY")
    );
}

#[test]
fn a_presented_digest_alone_is_never_believed() {
    // The package says ALLOW and SUPPORTED, with digests that match what it says. The evidence
    // says the approver's limit is too low.
    let trust = Trust::from_value(&read("trust.json")).expect("the registry is usable");
    let failure = replay(member(&read("25-outcome-altered.json"), "package"), &trust)
        .expect_err("not reproduced");
    assert_eq!(failure.stage, "DERIVATION");
    assert!(
        failure
            .detail
            .contains("outcome: presented \"ALLOW\" computed \"DENY\""),
        "{}",
        failure.detail
    );
}
