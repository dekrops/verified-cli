// SPDX-License-Identifier: Apache-2.0

//! The synthetic example packages under `examples/`.
//!
//! The files are generated from the scenarios below and checked in, so that
//! a consumer can use them without this repository's test code. This test
//! fails if a file is not exactly what its scenario generates, or does not
//! verify to the outcome its README states. To write the files after a
//! deliberate change: `VERIFIED_WRITE_EXAMPLES=1 cargo test --test examples`.
//! Review the diff; never regenerate to make a failure go away.

mod support;

use std::path::PathBuf;

use support::{
    Item, Scenario, evidence_key, hash, issuer_key, json, list, registry, replaced, string, uuid,
    wrapped,
};
use verified_canonical::{Limits, parse};
use verified_protocol::{Decision, RefusalCode};
use verified_verifier::{DecisionFinding, IssuerSignature, Options, Rejection, Trust, verify};

/// What verifying an example under `trust.json` must conclude.
enum Expected {
    Reproduced(Decision, IssuerSignature),
    Refused(RefusalCode),
}

fn directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/invoice-posting")
}

fn examples() -> Vec<(&'static str, String, Expected)> {
    let signed = || {
        let mut scenario = Scenario::posted();
        scenario.issuers = vec![issuer_key()];
        scenario
    };

    // No record of the invoice, and no statement that the listing is
    // complete: its absence settles nothing.
    let mut undetermined = signed();
    undetermined.items[0].body = json(
        r#"{"record": {"kind": "posting", "fields": {"document": "D-2", "invoice": "INV-2"}}}"#,
    );
    undetermined.outcome = json(
        r#"{"decision": "UNDETERMINED", "requirements": [{"id": "POSTED", "value": "UNKNOWN"}],
            "ignored": [], "conflicts": []}"#,
    );

    // The same, with the source declaring its postings complete.
    let mut contradicted = undetermined.clone();
    let complete = json(r#"{"complete": {"kind": "posting", "asOf": "1772359200"}}"#);
    contradicted
        .items
        .push(Item::new(2, &evidence_key(), "erp", complete));
    contradicted.claim = replaced(
        &contradicted.claim,
        &["evidence"],
        Some(list([wrapped(uuid(1)), wrapped(uuid(2))])),
    );
    contradicted.outcome = json(
        r#"{"decision": "CONTRADICTED", "requirements": [{"id": "POSTED", "value": "FALSE"}],
            "ignored": [], "conflicts": []}"#,
    );

    // A recorded decision that does not follow from the evidence, signed by
    // its issuer all the same.
    let mut overstated = undetermined.clone();
    overstated.outcome = json(
        r#"{"decision": "SUPPORTED", "requirements": [{"id": "POSTED", "value": "TRUE"}],
            "ignored": [], "conflicts": []}"#,
    );

    // A record changed after the package was assembled.
    let mut tampered = signed().draft();
    tampered.manifest_files = Some(
        tampered
            .files
            .iter()
            .map(|(path, content)| (path.clone(), hash(content)))
            .collect(),
    );
    tampered.files[3].1 = replaced(
        &tampered.files[3].1,
        &["0", "body", "record", "fields", "invoice"],
        Some(string("INV-9")),
    );

    let absent = IssuerSignature::Absent;
    let one = IssuerSignature::Established { count: 1 };
    vec![
        (
            "supported.json",
            Scenario::posted().text(),
            Expected::Reproduced(Decision::Supported, absent),
        ),
        (
            "supported-issuer-signed.json",
            signed().text(),
            Expected::Reproduced(Decision::Supported, one),
        ),
        (
            "undetermined.json",
            undetermined.text(),
            Expected::Reproduced(Decision::Undetermined, one),
        ),
        (
            "contradicted.json",
            contradicted.text(),
            Expected::Reproduced(Decision::Contradicted, one),
        ),
        (
            "refused-decision-mismatch.json",
            overstated.text(),
            Expected::Refused(RefusalCode::DecisionMismatch),
        ),
        (
            "refused-component-digest.json",
            tampered.text(),
            Expected::Refused(RefusalCode::ComponentDigest),
        ),
    ]
}

#[test]
fn the_checked_in_examples_are_current_and_verify_as_documented() {
    let dir = directory();
    let write = std::env::var_os("VERIFIED_WRITE_EXAMPLES").is_some();
    let registry_text = registry(&[&evidence_key(), &issuer_key()]).to_canonical_string();
    let mut files = vec![("trust.json", registry_text.clone())];
    files.extend(examples().into_iter().map(|(name, text, _)| (name, text)));
    for (name, text) in &files {
        let path = dir.join(name);
        if write {
            std::fs::write(&path, text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        }
        let on_disk =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(&on_disk, text, "{name} is not what its scenario generates");
    }

    // Verified from the files, as a consumer would: the registry is read
    // from its own file and is never taken from a package.
    let registry_bytes = std::fs::read(dir.join("trust.json")).expect("trust.json");
    let trust = Trust::from_value(&parse(&registry_bytes, &Limits::DEFAULT).expect("JSON"))
        .expect("a registry");
    let options = Options {
        trust: Some(&trust),
        ..Options::default()
    };
    for (name, _, expected) in examples() {
        let bytes = std::fs::read(dir.join(name)).expect("an example");
        match (verify(&bytes, &options), expected) {
            (Ok(report), Expected::Reproduced(decision, issuer)) => {
                assert!(report.is_complete(), "{name}");
                assert_eq!(report.issuer_signature, issuer, "{name}");
                let DecisionFinding::Reproduced(reproduced) = &report.decision else {
                    panic!("{name}: not reproduced");
                };
                assert_eq!(reproduced.decision, decision, "{name}");
            }
            (Err(Rejection::Refused(refusal)), Expected::Refused(code)) => {
                assert_eq!(refusal.code, code, "{name}");
            }
            (other, _) => panic!("{name}: {other:?}"),
        }
        // Without a registry no example yields a decision, whatever it carries.
        if let Ok(report) = verify(&bytes, &Options::default()) {
            assert!(!report.is_complete(), "{name}");
            assert!(
                matches!(report.decision, DecisionFinding::NotChecked(_)),
                "{name}"
            );
        }
    }
}
