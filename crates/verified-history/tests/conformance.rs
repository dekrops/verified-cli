// SPDX-License-Identifier: Apache-2.0

//! The work relation v1 conformance corpus.
//!
//! The corpus is published in `dekrops/wvp` and is not copied here; see
//! `conformance/README.md`. Point `VERIFIED_CONFORMANCE_DIR` at a directory
//! holding `work-relation/v1` to run this test. With
//! `VERIFIED_CONFORMANCE_REQUIRED=1` its absence is a failure.
//!
//! Expected readings are read from the vectors and never adjusted here.
//! Each case's whole reading is compared: every record, every relation's
//! standing, every derived relation and every stream.

#![allow(clippy::print_stderr)] // progress notes for whoever runs the corpus

use std::path::PathBuf;

use verified_canonical::{Limits, Value, parse};
use verified_history::{Carried, Offered, read};
use verified_verifier::Trust;

fn corpus() -> Option<PathBuf> {
    let Some(dir) = std::env::var_os("VERIFIED_CONFORMANCE_DIR") else {
        assert!(
            std::env::var_os("VERIFIED_CONFORMANCE_REQUIRED").is_none(),
            "VERIFIED_CONFORMANCE_REQUIRED is set but VERIFIED_CONFORMANCE_DIR is not"
        );
        eprintln!("skipped: VERIFIED_CONFORMANCE_DIR is not set");
        return None;
    };
    Some(PathBuf::from(dir).join("work-relation").join("v1"))
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

fn list<'a>(value: &'a Value, name: &str, at: &str) -> &'a [Value] {
    member(value, name, at)
        .as_array()
        .unwrap_or_else(|| panic!("{at}: {name} is not a list"))
}

#[test]
fn every_case_yields_its_expected_reading() {
    let Some(dir) = corpus() else { return };
    let path = dir.join("vectors.json");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let vectors = parse(&bytes, &Limits::DEFAULT).expect("the vectors parse");
    assert_eq!(
        text(&vectors, "protocol", "vectors"),
        "verified-work-relation-v1"
    );
    let cases = list(&vectors, "cases", "vectors");
    assert!(
        cases.len() >= 41,
        "the corpus has at least the cases measured so far"
    );

    let mut wrong = Vec::new();
    for case in cases {
        let name = text(case, "name", "case");
        let trust = Trust::from_value(member(case, "trust", name))
            .unwrap_or_else(|e| panic!("{name}: trust: {e}"));
        let relations: Vec<Carried<'_>> = list(case, "relations", name)
            .iter()
            .map(|carried| Carried {
                statement: member(carried, "statement", name),
                body: member(carried, "body", name),
            })
            .collect();
        let records: Vec<Offered<'_>> = list(case, "records", name)
            .iter()
            .map(|offered| Offered {
                kind: text(offered, "kind", name),
                text: text(offered, "text", name),
            })
            .collect();
        let reading = read(&relations, &records, &trust).to_value();
        let expected = member(case, "expected", name);
        if &reading != expected {
            wrong.push(format!(
                "{name}:\n  computed {}\n  expected {}",
                reading.to_canonical_string(),
                expected.to_canonical_string()
            ));
        }
    }
    eprintln!("work relation v1: {} cases", cases.len());
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
