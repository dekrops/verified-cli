// SPDX-License-Identifier: Apache-2.0

//! Issuing packages.
//!
//! The strongest check available without a second producer: the checked-in
//! example packages were written by this repository's test builder, by hand.
//! Taking each apart and issuing it again from its parts must give the same
//! bytes.

use std::path::PathBuf;

use verified_canonical::{Limits, Value, parse};
use verified_protocol::{Decision, RefusalCode};
use verified_verifier::issue::{
    Countersignature, Draft, IssueError, countersign, decision_signing_input, issue,
};
use verified_verifier::{DecisionFinding, IssuerSignature, Rejection, Trust};

fn read(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/invoice-posting")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn json(text: &str) -> Value {
    parse(text.as_bytes(), &Limits::DEFAULT).expect("JSON")
}

fn trust() -> Trust {
    Trust::from_value(&json(&read("trust.json"))).expect("a registry")
}

fn at<'a>(value: &'a Value, path: &[&str]) -> &'a Value {
    path.iter().fold(value, |value, name| {
        value
            .as_object()
            .and_then(|o| o.get(name))
            .unwrap_or_else(|| panic!("no member {name}"))
    })
}

fn text<'a>(value: &'a Value, path: &[&str]) -> &'a str {
    at(value, path).as_str().expect("text")
}

/// The parts of a package, as an issuer would have held them.
struct Parts {
    package: Value,
}

impl Parts {
    fn of(name: &str) -> Self {
        Self {
            package: json(&read(name)),
        }
    }

    fn file(&self, index: usize) -> &Value {
        let files = at(&self.package, &["files"]).as_array().expect("files");
        at(&files[index], &["content"])
    }

    fn evidence(&self) -> Vec<(&Value, &Value)> {
        let bodies = self.file(3).as_array().expect("bodies");
        let statements = self.file(4).as_array().expect("statements");
        // In reverse, to show that the order given does not matter.
        statements
            .iter()
            .zip(bodies)
            .map(|(statement, body)| (statement, at(body, &["body"])))
            .rev()
            .collect()
    }

    fn draft<'a>(&'a self, evidence: &'a [(&'a Value, &'a Value)]) -> Draft<'a> {
        let (claim, inputs) = (self.file(0), self.file(5));
        Draft {
            tenant: text(claim, &["tenant", "value"]),
            contract: self.file(1),
            claim: text(claim, &["id", "value"]),
            claimant: text(claim, &["claimant", "value"]),
            inputs: at(claim, &["inputs"]),
            submitted_at: text(claim, &["submittedAt", "value"]),
            evidence,
            evidence_set: text(inputs, &["packageId", "value"]),
            ingested_at: text(inputs, &["ingestedAt", "value"]),
            assembled_at: text(inputs, &["assembledAt", "value"]),
            evaluated_at: text(inputs, &["evaluatedAt", "value"]),
        }
    }
}

fn refused(result: Result<verified_verifier::issue::Issued, IssueError>) -> RefusalCode {
    match result {
        Err(IssueError::Refused(refusal)) => refusal.code,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn issuing_an_example_from_its_parts_gives_the_same_bytes() {
    let parts = Parts::of("supported.json");
    let evidence = parts.evidence();
    let issued = issue(&parts.draft(&evidence), &trust()).expect("issued");
    assert_eq!(issued.package, read("supported.json"));
    assert!(issued.report.is_complete());
    assert_eq!(issued.report.issuer_signature, IssuerSignature::Absent);
    let DecisionFinding::Reproduced(reproduced) = &issued.report.decision else {
        panic!("the issuer's check reproduces the decision");
    };
    assert_eq!(reproduced.decision, Decision::Supported);
}

#[test]
fn a_contradicted_or_undetermined_claim_is_issued_not_refused() {
    for (name, decision) in [
        ("undetermined.json", Decision::Undetermined),
        ("contradicted.json", Decision::Contradicted),
    ] {
        let parts = Parts::of(name);
        let evidence = parts.evidence();
        let issued = issue(&parts.draft(&evidence), &trust()).expect("issued");
        let DecisionFinding::Reproduced(reproduced) = &issued.report.decision else {
            panic!("{name}: the issuer's check reproduces the decision");
        };
        assert_eq!(reproduced.decision, decision, "{name}");

        // The examples carry an issuer signature; the same signature over
        // the same decision gives the same file.
        let signatures = at(&parts.package, &["signatures"])
            .as_array()
            .expect("signatures");
        let signature = Countersignature {
            key_id: text(&signatures[0], &["keyId"]),
            encoded: text(&signatures[0], &["encoded"]),
        };
        let signed = countersign(issued.package.as_bytes(), &[signature], &trust())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(signed.package, read(name), "{name}");
        assert_eq!(signed.report.package_id, issued.report.package_id);
        assert_eq!(
            signed.report.issuer_signature,
            IssuerSignature::Established { count: 1 }
        );
    }
}

#[test]
fn a_decision_is_never_supplied_by_the_caller() {
    // The draft of a package whose recorded decision was overstated has
    // nowhere to put that decision: issuing it gives what the evidence yields.
    let parts = Parts::of("refused-decision-mismatch.json");
    let evidence = parts.evidence();
    let issued = issue(&parts.draft(&evidence), &trust()).expect("issued");
    let DecisionFinding::Reproduced(reproduced) = &issued.report.decision else {
        panic!("reproduced");
    };
    assert_ne!(reproduced.decision, Decision::Supported);
}

#[test]
fn what_a_verifier_would_refuse_is_not_issued() {
    let parts = Parts::of("supported.json");
    let evidence = parts.evidence();
    let draft = parts.draft(&evidence);

    // A registry that does not hold the evidence key.
    let strangers = Trust::from_value(&json(r#"{"keys": []}"#)).expect("a registry");
    assert_eq!(refused(issue(&draft, &strangers)), RefusalCode::UnknownKey);

    // Evaluated before the evidence was observed.
    let early = Draft {
        evaluated_at: "2026-03-01T09:00:00Z",
        ..draft
    };
    assert_eq!(refused(issue(&early, &trust())), RefusalCode::InputMismatch);

    // A claim for another tenant than the statements'.
    let foreign = Draft {
        tenant: "another-tenant",
        ..draft
    };
    assert_eq!(
        refused(issue(&foreign, &trust())),
        RefusalCode::ForeignTenantEvidence
    );

    // Inputs the contract does not declare.
    let inputs = json(r#"{"order": "SO-1"}"#);
    let undeclared = Draft {
        inputs: &inputs,
        ..draft
    };
    assert_eq!(
        refused(issue(&undeclared, &trust())),
        RefusalCode::InputMismatch
    );

    // Not a contract.
    let nothing = json("{}");
    let no_contract = Draft {
        contract: &nothing,
        ..draft
    };
    assert_eq!(
        refused(issue(&no_contract, &trust())),
        RefusalCode::MalformedComponent
    );

    // A body other than the one the statement commits to.
    let body = json(
        r#"{"record": {"kind": "posting", "fields": {"document": "D-9", "invoice": "INV-1"}}}"#,
    );
    let swapped = [(evidence[0].0, &body)];
    let altered = Draft {
        evidence: &swapped,
        ..draft
    };
    assert_eq!(
        refused(issue(&altered, &trust())),
        RefusalCode::PayloadMismatch
    );
}

#[test]
fn a_draft_that_is_not_components_is_an_error_of_the_draft() {
    let parts = Parts::of("supported.json");
    let evidence = parts.evidence();
    let draft = parts.draft(&evidence);
    for broken in [
        Draft {
            claim: "not-a-uuid",
            ..draft
        },
        Draft {
            submitted_at: "yesterday",
            ..draft
        },
    ] {
        assert!(matches!(
            issue(&broken, &trust()),
            Err(IssueError::Draft(_))
        ));
    }
    let not_a_statement = json("{}");
    let bad = [(&not_a_statement, evidence[0].1)];
    let draft = Draft {
        evidence: &bad,
        ..draft
    };
    assert!(matches!(issue(&draft, &trust()), Err(IssueError::Draft(_))));
}

#[test]
fn a_countersignature_must_count() {
    let unsigned = read("supported.json");
    let signed = json(&read("supported-issuer-signed.json"));
    let signatures = at(&signed, &["signatures"]).as_array().expect("signatures");
    let good = Countersignature {
        key_id: text(&signatures[0], &["keyId"]),
        encoded: text(&signatures[0], &["encoded"]),
    };
    let issued = countersign(unsigned.as_bytes(), &[good], &trust()).expect("signed");
    assert_eq!(issued.package, read("supported-issuer-signed.json"));

    // The evidence key may not sign decisions.
    let by_evidence_key = Countersignature {
        key_id: "test-erp-gateway",
        ..good
    };
    assert_eq!(
        refused(countersign(
            unsigned.as_bytes(),
            &[by_evidence_key],
            &trust()
        )),
        RefusalCode::IssuerSignatureInvalid
    );
    // A signature over another decision.
    let other = json(&read("contradicted.json"));
    let other = at(&other, &["signatures"]).as_array().expect("signatures");
    let wrong = Countersignature {
        encoded: text(&other[0], &["encoded"]),
        ..good
    };
    assert_eq!(
        refused(countersign(unsigned.as_bytes(), &[wrong], &trust())),
        RefusalCode::IssuerSignatureInvalid
    );
    // No signature at all is not a countersigned package.
    assert!(matches!(
        countersign(unsigned.as_bytes(), &[], &trust()),
        Err(IssueError::Draft(_))
    ));
}

#[test]
fn the_signing_input_is_the_decision_under_its_domain() {
    let package = read("supported.json");
    let input = decision_signing_input(package.as_bytes()).expect("a signing input");
    let decision = Parts::of("supported.json").file(2).to_canonical_string();
    assert_eq!(
        input,
        format!("verified:wvp-decision:v0.2\n{decision}").into_bytes()
    );
    assert!(matches!(
        decision_signing_input(b"{}"),
        Err(Rejection::Refused(_))
    ));
    let altered = read("refused-component-digest.json");
    assert!(matches!(
        decision_signing_input(altered.as_bytes()),
        Err(Rejection::Refused(refusal)) if refusal.code == RefusalCode::ComponentDigest
    ));
}
