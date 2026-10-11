// SPDX-License-Identifier: Apache-2.0

//! The Evidence Statement v1 conformance corpus.
//!
//! The corpus is published in `dekrops/wvp` and is not copied here; see
//! `conformance/README.md`. Point `VERIFIED_CONFORMANCE_DIR` at a directory
//! holding `evidence-statement/v1` to run this test. With
//! `VERIFIED_CONFORMANCE_REQUIRED=1` its absence is a failure.
//!
//! Expected outcomes are read from the vectors and never adjusted here. A
//! refusal is compared by its code. An accepted statement is compared by its
//! key, canonical text, digest and signing input; an accepted chain by its
//! whole summary; an accepted admission by its evidence manifest.
//!
//! Two members of an accepted admission are **not** compared, because they
//! are the platform's verification result, which this project does not
//! compute: `verificationResultSha256` and `verificationStatus`.

#![allow(clippy::print_stderr)] // progress notes for whoever runs the corpus

use std::path::{Path, PathBuf};

use verified_canonical::{Limits, Object, Sha256Digest, Value, parse};
use verified_protocol::STATEMENT_DOMAIN;
use verified_verifier::Trust;
use verified_verifier::evidence::{
    Anchor, Authenticated, EvidenceRefusal, admit, authenticate, verify_chain,
};

fn corpus() -> Option<PathBuf> {
    let Some(dir) = std::env::var_os("VERIFIED_CONFORMANCE_DIR") else {
        assert!(
            std::env::var_os("VERIFIED_CONFORMANCE_REQUIRED").is_none(),
            "VERIFIED_CONFORMANCE_REQUIRED is set but VERIFIED_CONFORMANCE_DIR is not"
        );
        eprintln!("skipped: VERIFIED_CONFORMANCE_DIR is not set");
        return None;
    };
    Some(PathBuf::from(dir).join("evidence-statement").join("v1"))
}

fn json(text: &str, at: &str) -> Value {
    parse(text.as_bytes(), &Limits::DEFAULT).unwrap_or_else(|e| panic!("{at}: {e}"))
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

/// The text of `{ "value": … }`.
fn wrapped<'a>(value: &'a Value, name: &str, at: &str) -> &'a str {
    text(member(value, name, at), "value", at)
}

fn texts<'a>(value: &'a Value, name: &str, at: &str) -> Vec<&'a str> {
    member(value, name, at)
        .as_array()
        .unwrap_or_else(|| panic!("{at}: {name} is not a list"))
        .iter()
        .map(|v| {
            v.as_str()
                .unwrap_or_else(|| panic!("{at}: {name} holds a non-text"))
        })
        .collect()
}

fn string(s: impl Into<String>) -> Value {
    Value::String(s.into())
}

fn object<const N: usize>(members: [(&str, Value); N]) -> Value {
    Value::Object(
        members
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect::<Object>(),
    )
}

fn refused(refusal: &EvidenceRefusal) -> Value {
    object([
        ("accept", Value::Bool(false)),
        ("error", string(refusal.code.as_str())),
    ])
}

fn authenticated<'a>(
    statements: &'a [Value],
    trust: &Trust,
) -> Result<Vec<Authenticated<'a>>, EvidenceRefusal> {
    statements.iter().map(|s| authenticate(s, trust)).collect()
}

fn statement_outcome(input: &Value, trust: &Trust, at: &str) -> Value {
    let signed = json(text(input, "signedStatementJson", at), at);
    match authenticate(&signed, trust) {
        Err(refusal) => refused(&refusal),
        Ok(authentic) => {
            let statement = authentic.statement();
            let canonical = statement.statement.to_canonical_string();
            object([
                ("accept", Value::Bool(true)),
                ("keyId", string(statement.signature.key_id)),
                (
                    "signingInputSha256",
                    string(Sha256Digest::of(&statement.signing_input()).to_hex()),
                ),
                ("statementCanonicalUtf8", string(canonical)),
                ("statementSha256", string(statement.digest().to_hex())),
            ])
        }
    }
}

fn chain_outcome(input: &Value, trust: &Trust, at: &str) -> Value {
    let statements: Vec<Value> = texts(input, "statements", at)
        .into_iter()
        .map(|s| json(s, at))
        .collect();
    let anchor = match member(input, "anchor", at) {
        Value::Null => None,
        anchor => {
            Some(Anchor::from_value(anchor).unwrap_or_else(|e| panic!("{at}: the anchor: {e}")))
        }
    };
    let segment = authenticated(&statements, trust)
        .and_then(|authentic| verify_chain(&authentic, anchor.as_ref()));
    match segment {
        Err(refusal) => refused(&refusal),
        Ok(segment) => object([
            ("accept", Value::Bool(true)),
            ("first", Value::Integer(segment.first.into())),
            ("fromGenesis", Value::Bool(segment.from_genesis)),
            ("headSha256", string(segment.head.digest.to_hex())),
            ("last", Value::Integer(segment.head.sequence.into())),
        ]),
    }
}

/// The outcome of an admission vector, and whether the expectation's
/// verification result was left out of the comparison.
fn admission_outcome(input: &Value, expected: &Value, trust: &Trust, at: &str) -> Value {
    let statements: Vec<Value> = texts(input, "statements", at)
        .into_iter()
        .map(|s| json(s, at))
        .collect();
    let bodies: Vec<Value> = texts(input, "bodies", at)
        .into_iter()
        .map(|s| json(s, at))
        .collect();
    assert_eq!(
        statements.len(),
        bodies.len(),
        "{at}: one body per statement"
    );
    let claim = member(input, "claim", at);
    let claimed: Vec<&str> = member(claim, "evidence", at)
        .as_array()
        .unwrap_or_else(|| panic!("{at}: claim.evidence is not a list"))
        .iter()
        .map(|id| text(id, "value", at))
        .collect();
    let admitted = authenticated(&statements, trust).and_then(|authentic| {
        let evidence: Vec<_> = authentic.into_iter().zip(&bodies).collect();
        admit(wrapped(input, "tenant", at), &claimed, &evidence)
    });
    match admitted {
        Err(refusal) => refused(&refusal),
        Ok(admitted) => {
            let manifest = admitted.manifest(
                member(input, "packageId", at),
                member(claim, "id", at),
                member(input, "ingestedAt", at),
                member(input, "assembledAt", at),
            );
            // The verification result is the platform's; see the module
            // documentation. It is carried over so that the rest compares.
            object([
                ("accept", Value::Bool(true)),
                ("packageManifestSha256", string(manifest.digest().to_hex())),
                (
                    "verificationResultSha256",
                    member(expected, "verificationResultSha256", at).clone(),
                ),
                (
                    "verificationStatus",
                    member(expected, "verificationStatus", at).clone(),
                ),
            ])
        }
    }
}

fn run_vector(path: &Path, class: &str) -> &'static str {
    let at = path.display().to_string();
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{at}: {e}"));
    let vector = parse(&bytes, &Limits::DEFAULT).unwrap_or_else(|e| panic!("{at}: {e}"));
    let expected = member(&vector, "expected", &at);
    let input = member(&vector, "input", &at);
    let trust =
        Trust::from_value(member(&vector, "registry", &at)).unwrap_or_else(|e| panic!("{at}: {e}"));

    let accepted = member(expected, "accept", &at) == &Value::Bool(true);
    assert_eq!(accepted, class == "valid", "{at}: is in {class}/");

    let kind = text(&vector, "kind", &at);
    let (kind, actual) = match kind {
        "statement" => ("statement", statement_outcome(input, &trust, &at)),
        "chain" => ("chain", chain_outcome(input, &trust, &at)),
        "admission" => ("admission", admission_outcome(input, expected, &trust, &at)),
        other => panic!("{at}: unknown vector kind {other:?}"),
    };
    assert_eq!(&actual, expected, "{at}");
    kind
}

#[test]
fn every_evidence_statement_vector_is_reproduced() {
    let Some(corpus) = corpus() else { return };
    assert_eq!(
        STATEMENT_DOMAIN.as_str(),
        "verified:evidence-statement:v1\n"
    );
    let mut counts = std::collections::BTreeMap::new();
    for class in ["valid", "invalid", "must-reject"] {
        let dir = corpus.join(class);
        let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
            .map(|entry| entry.expect("a directory entry").path())
            .filter(|path| path.extension().is_some_and(|x| x == "json"))
            .collect();
        paths.sort();
        assert!(!paths.is_empty(), "{}: no vectors", dir.display());
        for path in paths {
            *counts.entry(run_vector(&path, class)).or_insert(0u32) += 1;
        }
    }
    eprintln!(
        "evidence-statement-1: {} statement, {} chain and {} admission vectors reproduced \
         (the platform's verification result of an accepted admission is not compared)",
        counts.get("statement").copied().unwrap_or(0),
        counts.get("chain").copied().unwrap_or(0),
        counts.get("admission").copied().unwrap_or(0),
    );
}
