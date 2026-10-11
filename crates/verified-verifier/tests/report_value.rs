// SPDX-License-Identifier: Apache-2.0

//! A report as JSON (`Report::to_value`): the `verify` contract of
//! `docs/sdk/json-output.md`, which the command line and the bindings print.

use std::path::PathBuf;

use verified_canonical::{Limits, Value, parse};
use verified_verifier::{Options, Trust, verify};

fn read(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/invoice-posting")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn trust() -> Trust {
    let registry = parse(&read("trust.json"), &Limits::DEFAULT).expect("JSON");
    Trust::from_value(&registry).expect("a registry")
}

fn at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter()
        .try_fold(value, |value, name| value.as_object()?.get(name))
}

fn text<'a>(value: &'a Value, path: &[&str]) -> &'a str {
    at(value, path)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no text at {path:?} in {}", value.to_canonical_string()))
}

#[test]
fn a_complete_report_states_each_property_and_the_reproduced_decision() {
    let trust = trust();
    let options = Options {
        trust: Some(&trust),
        ..Options::default()
    };
    let report = verify(&read("supported.json"), &options).expect("verified");
    let value = report.to_value();

    assert_eq!(text(&value, &["outcome"]), "complete");
    assert_eq!(text(&value, &["protocolStatus"]), "draft");
    assert_eq!(text(&value, &["packageId"]), report.package_id.to_string());
    for property in ["packageIntegrity", "evidenceSignatures", "signerAuthority"] {
        assert_eq!(
            text(&value, &["properties", property, "status"]),
            "established"
        );
    }
    let decision = ["properties", "decisionReproduced"];
    assert_eq!(
        text(&value, &[&decision[..], &["decision"]].concat()),
        "SUPPORTED"
    );
    assert!(at(&value, &[&decision[..], &["requirements"]].concat()).is_some());
    assert_eq!(
        text(&value, &["properties", "sourceTruthfulness", "status"]),
        "not_established"
    );
    assert!(at(&value, &["workRecord"]).is_some());
    // What only the command line adds is not here.
    assert!(at(&value, &["note"]).is_none());
    assert!(at(&value, &["requiredDecision"]).is_none());
}

#[test]
fn without_a_registry_no_decision_is_stated_not_even_the_package_s() {
    let report = verify(&read("supported.json"), &Options::default()).expect("verified");
    let value = report.to_value();

    assert_eq!(text(&value, &["outcome"]), "incomplete");
    assert_eq!(
        text(&value, &["properties", "packageIntegrity", "status"]),
        "established"
    );
    for property in [
        "evidenceSignatures",
        "signerAuthority",
        "decisionReproduced",
    ] {
        assert_eq!(
            text(&value, &["properties", property, "status"]),
            "not_checked"
        );
        assert_eq!(
            text(&value, &["properties", property, "reason"]),
            "no_trust_registry"
        );
    }
    assert!(at(&value, &["properties", "decisionReproduced", "decision"]).is_none());
    assert_eq!(
        text(&value, &["properties", "issuerSignature", "status"]),
        "not_checked"
    );
}

#[test]
fn the_same_report_gives_the_same_text() {
    let trust = trust();
    let options = Options {
        trust: Some(&trust),
        ..Options::default()
    };
    for name in ["supported.json", "contradicted.json", "undetermined.json"] {
        let a = verify(&read(name), &options).expect("verified").to_value();
        let b = verify(&read(name), &options).expect("verified").to_value();
        assert_eq!(a.to_canonical_string(), b.to_canonical_string(), "{name}");
    }
}
