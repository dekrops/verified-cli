// SPDX-License-Identifier: Apache-2.0

//! What `inspect` reports a package as stating, and how that is kept apart
//! from what verification established.

mod support;

use support::{Scenario, evidence_key, issuer_key, json, registry, replaced, string, uuid};
use verified_canonical::Value;
use verified_protocol::{Decision, RefusalCode};
use verified_verifier::{
    DecisionFinding, Inspection, IssuerSignature, Options, Rejection, Trust, inspect,
};

fn trust() -> Trust {
    Trust::from_value(&registry(&[&evidence_key(), &issuer_key()])).expect("a usable registry")
}

fn inspected(scenario: &Scenario, trust: Option<&Trust>) -> Result<Inspection, Rejection> {
    let options = Options {
        trust,
        ..Options::default()
    };
    inspect(scenario.text().as_bytes(), &options)
}

#[test]
fn the_claim_is_reported_as_stated_for_both_protocol_versions() {
    let posted = inspected(&Scenario::posted(), None).expect("not refused");
    assert_eq!(posted.claim.id, uuid(0x500));
    assert_eq!(posted.claim.claimant, uuid(0x600));
    assert_eq!(posted.claim.inputs, Some(json(r#"{"invoice": "INV-1"}"#)));

    // A wvp-0.1 claim has a claimant and no inputs. That is said, not
    // papered over with an empty object.
    let shipped = inspected(&Scenario::shipped(), None).expect("not refused");
    assert_eq!(shipped.claim.id, uuid(0x500));
    assert_eq!(shipped.claim.claimant, uuid(0x600));
    assert_eq!(shipped.claim.inputs, None);
}

#[test]
fn claim_inputs_keep_their_protocol_types() {
    // A contract with one input of each kind of JSON value the language has.
    let mut scenario = Scenario::posted();
    scenario.contract = replaced(
        &scenario.contract,
        &["inputs"],
        Some(json(
            r#"{"invoice": {"type": "text"}, "urgent": {"type": "bool"},
                "amount": {"type": "money", "currency": "EUR", "scale": 2},
                "cutoff": {"type": "time"}}"#,
        )),
    );
    let inputs =
        json(r#"{"invoice": "INV-1", "urgent": true, "amount": "125000", "cutoff": "1767225600"}"#);
    scenario.claim = replaced(&scenario.claim, &["inputs"], Some(inputs.clone()));
    scenario.claim = replaced(
        &scenario.claim,
        &["contract"],
        Some(support::hash(&scenario.contract)),
    );

    let inspection = inspected(&scenario, Some(&trust())).expect("not refused");
    assert!(inspection.report.is_complete());
    // Exactly the object the package carries: the amount is still the
    // language's number string, the flag still a boolean.
    assert_eq!(inspection.claim.inputs, Some(inputs));
    let stated = inspection
        .claim
        .inputs
        .as_ref()
        .and_then(Value::as_object)
        .expect("an object");
    assert_eq!(stated.get("amount"), Some(&string("125000")));
    assert_eq!(stated.get("urgent"), Some(&Value::Bool(true)));
}

#[test]
fn without_a_registry_everything_is_only_stated() {
    let mut scenario = Scenario::posted();
    scenario.issuers = vec![issuer_key()];
    let inspection = inspected(&scenario, None).expect("not refused");
    assert!(!inspection.report.is_complete());
    assert!(matches!(
        inspection.report.decision,
        DecisionFinding::NotChecked(_)
    ));
    // The package says who signed its decision and what the decision is.
    // Neither is a finding.
    assert_eq!(inspection.recorded_decision, "SUPPORTED");
    assert_eq!(inspection.issuer_signature_keys, ["test-decision-issuer"]);
    assert_eq!(inspection.verified_issuer_keys(), None);
}

#[test]
fn issuer_keys_count_as_verified_only_when_every_signature_was() {
    let mut scenario = Scenario::posted();
    assert_eq!(
        inspected(&scenario, Some(&trust()))
            .expect("not refused")
            .verified_issuer_keys(),
        None
    );

    scenario.issuers = vec![issuer_key()];
    let inspection = inspected(&scenario, Some(&trust())).expect("not refused");
    assert_eq!(
        inspection.report.issuer_signature,
        IssuerSignature::Established { count: 1 }
    );
    assert_eq!(
        inspection.verified_issuer_keys(),
        Some(&["test-decision-issuer".to_owned()][..])
    );

    // One good signature beside one that does not count: no inspection at
    // all, so no key can be read as verified.
    let mut draft = scenario.draft();
    let Value::Array(signatures) = &mut draft.signatures else {
        panic!("an array");
    };
    signatures.push(json(
        r#"{"scheme": "Ed25519", "keyId": "someone-else", "encoded": "AAAA"}"#,
    ));
    let registry = trust();
    let options = Options {
        trust: Some(&registry),
        ..Options::default()
    };
    let result = inspect(draft.text().as_bytes(), &options);
    assert!(
        matches!(&result, Err(Rejection::Refused(r)) if r.code == RefusalCode::IssuerSignatureInvalid),
        "{result:?}"
    );
}

#[test]
fn a_changed_claimant_or_input_is_a_different_package_or_no_package() {
    let original = Scenario::posted();
    let verified = inspected(&original, Some(&trust())).expect("not refused");

    // Changed in a package that is then made consistent again: it verifies,
    // as a different package with a different identifier.
    let mut reissued = original.clone();
    reissued.claim = replaced(
        &reissued.claim,
        &["claimant"],
        Some(support::wrapped(uuid(0x666))),
    );
    let other = inspected(&reissued, Some(&trust())).expect("not refused");
    assert_eq!(other.claim.claimant, uuid(0x666));
    assert_ne!(other.report.package_id, verified.report.package_id);

    // Changed under the original commitments: refused, at the first check
    // that covers the claim.
    for path in [&["claimant", "value"][..], &["inputs", "invoice"]] {
        let mut draft = original.draft();
        draft.manifest_files = Some(
            draft
                .files
                .iter()
                .map(|(path, content)| (path.clone(), support::hash(content)))
                .collect(),
        );
        let new = if path[0] == "claimant" {
            string(uuid(0x666))
        } else {
            string("INV-9")
        };
        draft.files[0].1 = replaced(&draft.files[0].1, path, Some(new));
        let registry = trust();
        let options = Options {
            trust: Some(&registry),
            ..Options::default()
        };
        let result = inspect(draft.text().as_bytes(), &options);
        assert!(
            matches!(&result, Err(Rejection::Refused(r)) if r.code == RefusalCode::ComponentDigest),
            "{path:?}: {result:?}"
        );
    }
}

#[test]
fn a_reproduced_decision_that_is_not_supported_stays_distinct() {
    let mut scenario = Scenario::posted();
    scenario.items[0].body = json(
        r#"{"record": {"kind": "posting", "fields": {"document": "D-1", "invoice": "INV-2"}}}"#,
    );
    scenario.outcome = json(
        r#"{"decision": "UNDETERMINED", "requirements": [{"id": "POSTED", "value": "UNKNOWN"}],
            "ignored": [], "conflicts": []}"#,
    );
    let inspection = inspected(&scenario, Some(&trust())).expect("not refused");
    // Complete, with a claim and a claimant, and not supported.
    assert!(inspection.report.is_complete());
    assert_eq!(inspection.claim.claimant, uuid(0x600));
    let DecisionFinding::Reproduced(reproduced) = &inspection.report.decision else {
        panic!("reproduced");
    };
    assert_eq!(reproduced.decision, Decision::Undetermined);
}
