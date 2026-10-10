//! The Work Contract Language 1 conformance corpus.
//!
//! The corpus is not part of this repository until its publication is
//! approved; see `conformance/README.md`. Point `VERIFIED_CONFORMANCE_DIR`
//! at a directory holding `work-contract/v1` to run this test. With
//! `VERIFIED_CONFORMANCE_REQUIRED=1` its absence is a failure.
//!
//! Expected outcomes are read from the corpus and never adjusted here.
#![allow(clippy::print_stderr)] // progress notes for whoever runs the corpus

use std::path::{Path, PathBuf};

use verified_canonical::{Limits, Object, ParseError, Value, parse};
use verified_contract::Contract;

fn corpus() -> Option<PathBuf> {
    let Some(dir) = std::env::var_os("VERIFIED_CONFORMANCE_DIR") else {
        assert!(
            std::env::var_os("VERIFIED_CONFORMANCE_REQUIRED").is_none(),
            "VERIFIED_CONFORMANCE_REQUIRED is set but VERIFIED_CONFORMANCE_DIR is not"
        );
        eprintln!("skipped: VERIFIED_CONFORMANCE_DIR is not set");
        return None;
    };
    Some(PathBuf::from(dir).join("work-contract").join("v1"))
}

fn files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();
    files
}

fn member<'a>(object: &'a Object, name: &str, label: &str) -> &'a Value {
    object
        .get(name)
        .unwrap_or_else(|| panic!("{label}: no {name}"))
}

/// What the implementation says, in the corpus's own result form.
fn run(contract: &Value, environment: &Value) -> Value {
    let refused = |refusal: verified_contract::Refusal| {
        let mut o = Object::new();
        o.insert("refused", Value::String(refusal.as_str().to_owned()));
        Value::Object(o)
    };
    match Contract::read(contract).and_then(|c| c.evaluate(environment)) {
        Ok(outcome) => outcome.to_value(),
        Err(refusal) => refused(refusal),
    }
}

#[test]
fn every_case_in_the_corpus_is_reproduced() {
    let Some(root) = corpus() else { return };
    let mut cases = 0usize;
    let mut unreadable = Vec::new();
    for dir in ["cases", "differential"] {
        for path in files(&root.join(dir)) {
            let label = path.display().to_string();
            let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{label}: {e}"));
            let json = match parse(&bytes, &Limits::DEFAULT) {
                Ok(json) => json,
                // `verified-json-v1` has no fractions, so a case built around
                // one cannot reach this implementation as a value. Inside a
                // package such text is refused before the contract is read.
                Err(ParseError::FractionalNumber { .. }) => {
                    unreadable.push(label);
                    continue;
                }
                Err(e) => panic!("{label}: {e}"),
            };
            let file = json
                .as_object()
                .unwrap_or_else(|| panic!("{label}: not an object"));
            let contract = member(file, "contract", &label);
            if let Some(batch) = file.get("cases").and_then(Value::as_array) {
                for (i, case) in batch.iter().enumerate() {
                    let label = format!("{label}#{i}");
                    let case = case
                        .as_object()
                        .unwrap_or_else(|| panic!("{label}: not an object"));
                    let got = run(contract, member(case, "environment", &label));
                    assert_eq!(&got, member(case, "expected", &label), "{label}");
                    cases += 1;
                }
            } else {
                let got = run(contract, member(file, "environment", &label));
                assert_eq!(&got, member(file, "expected", &label), "{label}");
                cases += 1;
            }
        }
    }
    eprintln!(
        "work-contract-1: {cases} cases reproduced; {} not representable in verified-json-v1: {unreadable:?}",
        unreadable.len()
    );
    assert!(cases > 0, "the corpus holds no cases");
    // Exactly one published case turns on a fractional JSON number.
    assert!(
        unreadable.len() <= 1,
        "unexpected unreadable cases: {unreadable:?}"
    );
}
