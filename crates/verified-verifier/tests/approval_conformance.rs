// SPDX-License-Identifier: Apache-2.0

//! The contract approval v1 conformance corpus.
//!
//! The corpus is published in `dekrops/wvp` and is not copied here; see
//! `conformance/README.md`. Point `VERIFIED_CONFORMANCE_DIR` at a directory
//! holding `contract-approval/v1` to run this test. With
//! `VERIFIED_CONFORMANCE_REQUIRED=1` its absence is a failure.
//!
//! Expected outcomes are read from the vectors and never adjusted here: for
//! a valid case the statement and its challenge, for an invalid one the code
//! of the one check it fails.

#![allow(clippy::print_stderr)] // progress notes for whoever runs the corpus

use std::collections::BTreeMap;
use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use verified_canonical::{Limits, Value, parse};
use verified_verifier::approval::verify_approval;

/// An object whose members are kept as the text the file holds.
type Raw = BTreeMap<String, Box<serde_json::value::RawValue>>;

fn corpus() -> Option<PathBuf> {
    let Some(dir) = std::env::var_os("VERIFIED_CONFORMANCE_DIR") else {
        assert!(
            std::env::var_os("VERIFIED_CONFORMANCE_REQUIRED").is_none(),
            "VERIFIED_CONFORMANCE_REQUIRED is set but VERIFIED_CONFORMANCE_DIR is not"
        );
        eprintln!("skipped: VERIFIED_CONFORMANCE_DIR is not set");
        return None;
    };
    Some(PathBuf::from(dir).join("contract-approval").join("v1"))
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

#[test]
fn every_approval_gives_its_expected_outcome() {
    let Some(dir) = corpus() else { return };
    let path = dir.join("vectors.json");
    let file = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    // Each approval is handed over as the text the vectors hold, never
    // re-encoded: some are written in a non-canonical spelling on purpose,
    // and one has a snapshot with no canonical form. The rest of each case
    // is read with the canonical reader.
    let vectors: Raw = serde_json::from_str(&file).expect("the vectors are JSON");
    let protocol = parse(vectors["protocol"].get().as_bytes(), &Limits::DEFAULT).expect("protocol");
    assert_eq!(protocol.as_str(), Some("verified.contract-approval/1"));
    let cases: Vec<Raw> = serde_json::from_str(vectors["cases"].get()).expect("cases is a list");
    let (mut valid, mut invalid) = (0, 0);
    for raw in &cases {
        let read = |name: &str| {
            parse(raw[name].get().as_bytes(), &Limits::DEFAULT)
                .unwrap_or_else(|e| panic!("{name}: {e}"))
        };
        let mut object = verified_canonical::Object::new();
        for name in ["name", "rpId", "origins", "expected"] {
            object.insert(name, read(name));
        }
        let case = &Value::Object(object);
        let name = text(case, "name", "a case");
        let rp_id = text(case, "rpId", name);
        let origins: Vec<String> = member(case, "origins", name)
            .as_array()
            .unwrap_or_else(|| panic!("{name}: origins is not a list"))
            .iter()
            .map(|o| {
                o.as_str()
                    .unwrap_or_else(|| panic!("{name}: an origin is not text"))
                    .to_owned()
            })
            .collect();
        let approval = raw["approval"].get();
        let expected = member(case, "expected", name);
        let outcome = verify_approval(approval.as_bytes(), rp_id, &origins);
        if member(expected, "valid", name) == &Value::Bool(true) {
            let approved = outcome.unwrap_or_else(|r| panic!("{name}: refused, {r}"));
            assert_eq!(
                approved.statement.value(),
                member(expected, "statement", name),
                "{name}: statement"
            );
            assert_eq!(
                URL_SAFE_NO_PAD.encode(approved.statement.challenge().as_bytes()),
                text(expected, "challenge", name),
                "{name}: challenge"
            );
            valid += 1;
        } else {
            let refusal = outcome
                .err()
                .unwrap_or_else(|| panic!("{name}: valid, expected a refusal"));
            assert_eq!(
                refusal.code.as_str(),
                text(expected, "refusal", name),
                "{name}: {refusal}"
            );
            invalid += 1;
        }
    }
    eprintln!("contract-approval-1: {valid} valid, {invalid} invalid");
}
