// SPDX-License-Identifier: Apache-2.0

//! Producing statements: what `prepare_statement` lays out is what a
//! verifier reads, signed by its source.

mod support;

use std::path::PathBuf;

use support::{evidence_key, registry};
use verified_canonical::{Limits, Object, Value, parse};
use verified_verifier::Trust;
use verified_verifier::evidence::{
    StatementDraft, Step, authenticate, prepare_statement, signed_statement,
    statement_signing_input, verify_chain,
};

fn example() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/invoice-posting/supported.json");
    parse(&std::fs::read(path).expect("example"), &Limits::DEFAULT).expect("JSON")
}

fn at<'a>(value: &'a Value, path: &[&str]) -> &'a Value {
    path.iter().fold(value, |value, name| {
        value
            .as_object()
            .and_then(|o| o.get(name))
            .unwrap_or_else(|| panic!("no member {name}"))
    })
}

fn component(package: &Value, index: usize) -> &Value {
    at(
        &at(package, &["files"]).as_array().expect("files")[index],
        &["content"],
    )
}

/// A statement's stated members: all but those `prepare_statement` writes.
fn stated(statement: &Value) -> Value {
    let o = statement.as_object().expect("a statement");
    Value::Object(
        o.iter()
            .filter(|(name, _)| !matches!(*name, "chain" | "payload" | "protocol"))
            .map(|(name, value)| (name.to_owned(), value.clone()))
            .collect::<Object>(),
    )
}

fn signed(statement: &Value) -> Value {
    let signature = evidence_key().sign("verified:evidence-statement:v1\n", statement);
    let field = |name| at(&signature, &[name]).as_str().expect("text").to_owned();
    signed_statement(statement, &field("keyId"), &field("encoded"))
}

#[test]
fn an_example_statement_laid_out_and_signed_again_is_the_same_bytes() {
    let package = example();
    let original = &component(&package, 4).as_array().expect("statements")[0];
    let body = at(
        &component(&package, 3).as_array().expect("bodies")[0],
        &["body"],
    );
    let statement = at(original, &["statement"]);

    let stated = stated(statement);
    let draft = StatementDraft {
        stated: &stated,
        body,
        step: Step::Unchained,
    };
    let prepared = prepare_statement(&draft).expect("a statement");
    assert_eq!(&prepared, statement);
    assert_eq!(
        statement_signing_input(&prepared),
        [
            b"verified:evidence-statement:v1\n".as_slice(),
            prepared.to_canonical_string().as_bytes()
        ]
        .concat()
    );
    assert_eq!(&signed(&prepared), original);
}

#[test]
fn a_stream_started_and_continued_is_one_unbroken_run() {
    let package = example();
    let statement = at(
        &component(&package, 4).as_array().expect("statements")[0],
        &["statement"],
    );
    let body = at(
        &component(&package, 3).as_array().expect("bodies")[0],
        &["body"],
    );
    let trust = Trust::from_value(&registry(&[&evidence_key()])).expect("a registry");

    let stated = stated(statement);
    let first = signed(
        &prepare_statement(&StatementDraft {
            stated: &stated,
            body,
            step: Step::First {
                stream: "erp/postings",
            },
        })
        .expect("the first step"),
    );
    let second = signed(
        &prepare_statement(&StatementDraft {
            stated: &stated,
            body,
            step: Step::After(&first),
        })
        .expect("the second step"),
    );
    let run = [&first, &second].map(|s| authenticate(s, &trust).expect("authentic"));
    let segment = verify_chain(&run, None).expect("one run");
    assert!(segment.from_genesis);
    assert_eq!((segment.first, segment.head.sequence), (0, 1));
}

#[test]
fn what_is_not_a_statement_is_not_laid_out() {
    let package = example();
    let statement = at(
        &component(&package, 4).as_array().expect("statements")[0],
        &["statement"],
    );
    let body = Value::Null;

    // A member the source does not state, or one too many.
    let with_payload = statement.clone();
    let draft = StatementDraft {
        stated: &with_payload,
        body: &body,
        step: Step::Unchained,
    };
    assert_eq!(
        prepare_statement(&draft)
            .expect_err("refused")
            .code
            .as_str(),
        "MALFORMED"
    );

    // A stated member of the wrong shape: an unknown evidence kind.
    let stated = stated(statement);
    let text = stated
        .to_canonical_string()
        .replace("\"Event\"", "\"Rumour\"");
    let wrong = parse(text.as_bytes(), &Limits::DEFAULT).expect("JSON");
    let draft = StatementDraft {
        stated: &wrong,
        body: &body,
        step: Step::Unchained,
    };
    assert_eq!(
        prepare_statement(&draft)
            .expect_err("refused")
            .code
            .as_str(),
        "MALFORMED"
    );

    // A previous step that is not chained.
    let unchained = signed(statement);
    let draft = StatementDraft {
        stated: &stated,
        body: &body,
        step: Step::After(&unchained),
    };
    assert_eq!(
        prepare_statement(&draft)
            .expect_err("refused")
            .code
            .as_str(),
        "MALFORMED"
    );
}
