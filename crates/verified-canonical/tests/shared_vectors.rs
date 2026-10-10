//! The shared `verified-json-v1` corpus, when it is available.
//!
//! The corpus (`canonical-hash-v1.json`) is not part of this repository until
//! its publication is approved; see `conformance/README.md`. Point
//! `VERIFIED_CONFORMANCE_DIR` at a directory holding it to run this test.
//! With `VERIFIED_CONFORMANCE_REQUIRED=1` its absence is a failure.
#![allow(clippy::print_stderr)] // progress notes for whoever runs the corpus

use std::path::PathBuf;

use verified_canonical::{Limits, Object, Value, parse};

fn corpus() -> Option<PathBuf> {
    let Some(dir) = std::env::var_os("VERIFIED_CONFORMANCE_DIR") else {
        assert!(
            std::env::var_os("VERIFIED_CONFORMANCE_REQUIRED").is_none(),
            "VERIFIED_CONFORMANCE_REQUIRED is set but VERIFIED_CONFORMANCE_DIR is not"
        );
        eprintln!("skipped: VERIFIED_CONFORMANCE_DIR is not set");
        return None;
    };
    Some(PathBuf::from(dir).join("canonical-hash-v1.json"))
}

fn text<'a>(case: &'a Object, member: &str) -> &'a str {
    case.get(member)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("case without {member}"))
}

fn cases<'a>(corpus: &'a Value, member: &str) -> impl Iterator<Item = &'a Object> {
    corpus
        .as_object()
        .and_then(|o| o.get(member))
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("corpus without {member}"))
        .iter()
        .map(|case| case.as_object().expect("a case is an object"))
}

#[test]
fn shared_vectors() {
    let Some(path) = corpus() else { return };
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let corpus = parse(&bytes, &Limits::DEFAULT).expect("the corpus file is JSON");
    assert_eq!(
        corpus
            .as_object()
            .and_then(|o| o.get("canonicalizationVersion"))
            .and_then(Value::as_str),
        Some(verified_canonical::CANONICAL_VERSION)
    );

    let mut valid = 0;
    for case in cases(&corpus, "valid") {
        let name = text(case, "name");
        let value = parse(text(case, "inputJson").as_bytes(), &Limits::DEFAULT)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            value.to_canonical_string(),
            text(case, "canonicalUtf8"),
            "{name}"
        );
        assert_eq!(value.digest().to_hex(), text(case, "sha256"), "{name}");
        valid += 1;
    }
    let mut invalid = 0;
    for case in cases(&corpus, "invalid") {
        let name = text(case, "name");
        assert!(
            parse(text(case, "inputJson").as_bytes(), &Limits::DEFAULT).is_err(),
            "{name}"
        );
        invalid += 1;
    }
    assert!(valid > 0 && invalid > 0, "an empty corpus proves nothing");
    eprintln!("shared vectors: {valid} valid, {invalid} invalid");
}
