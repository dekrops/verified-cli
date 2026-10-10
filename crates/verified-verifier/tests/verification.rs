// SPDX-License-Identifier: Apache-2.0

//! Steps 7 to 13 and the relying party's expectations, on synthetic signed
//! packages built in-process. Every expected decision is stated by hand in
//! the scenario or the test, never computed by the code under test.

mod support;

use proptest::prelude::*;
use support::{
    Item, Key, STATEMENT_DOMAIN, Scenario, TENANT, condition, evidence_key, hash, issuer_key, json,
    list, object, registry, replaced, string, unit, uuid, wrapped,
};
use verified_canonical::Value;
use verified_protocol::{Decision, ProtocolVersion, RefusalCode};
use verified_verifier::{
    DecisionFinding, Evaluation, Expectations, Finding, IssuerSignature, Options, Rejection,
    Report, Trust, TrustError, Truth, verify,
};

fn trust(keys: &[&Key]) -> Trust {
    Trust::from_value(&registry(keys)).expect("a usable test registry")
}

fn run(text: &str, trust: &Trust) -> Result<Report, Rejection> {
    let options = Options {
        trust: Some(trust),
        ..Options::default()
    };
    verify(text.as_bytes(), &options)
}

fn code(result: Result<Report, Rejection>) -> RefusalCode {
    match result {
        Err(Rejection::Refused(refusal)) => refusal.code,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// The refusal for a scenario under the registry holding its evidence key.
fn refused(scenario: &Scenario) -> RefusalCode {
    code(run(
        &scenario.text(),
        &trust(&[&evidence_key(), &issuer_key()]),
    ))
}

fn reproduced(report: &Report) -> (Decision, &Evaluation) {
    match &report.decision {
        DecisionFinding::Reproduced(r) => (r.decision, &r.evaluation),
        other => panic!("the decision was not reproduced: {other:?}"),
    }
}

/// One change to a scenario before it is assembled.
type Change = Box<dyn Fn(&mut Scenario)>;

fn both() -> [Scenario; 2] {
    [Scenario::shipped(), Scenario::posted()]
}

/// The file at `index`, changed in place after assembly: the manifest and
/// commitment follow, signatures and recorded commitments do not.
fn with_file(scenario: &Scenario, index: usize, path: &[&str], new: Option<Value>) -> String {
    let mut draft = scenario.draft();
    draft.files[index].1 = replaced(&draft.files[index].1, path, new);
    draft.text()
}

const CLAIM: usize = 0;
const DECISION: usize = 2;
const BODIES: usize = 3;
const STATEMENTS: usize = 4;

// ---- complete verification -------------------------------------------------

#[test]
fn a_supported_package_verifies_completely_under_the_relying_partys_registry() {
    for scenario in both() {
        let report = run(&scenario.text(), &trust(&[&evidence_key()])).expect("not refused");
        assert!(report.is_complete(), "{}", scenario.protocol);
        assert_eq!(report.integrity, Finding::Established);
        assert_eq!(report.evidence_signatures, Finding::Established);
        assert_eq!(report.signer_authority, Finding::Established);
        assert_eq!(report.issuer_signature, IssuerSignature::Absent);
        assert_eq!(report.statements, 1);
        assert_eq!(report.tenant, TENANT);
        assert_eq!(report.claim, uuid(0x500));
        assert_eq!(reproduced(&report).0, Decision::Supported);
    }
}

#[test]
fn the_report_names_the_contract_a_v02_decision_is_about() {
    let scenario = Scenario::posted();
    let report = run(&scenario.text(), &trust(&[&evidence_key()])).expect("not refused");
    let contract = report
        .contract
        .as_ref()
        .expect("a wvp-0.2 report names its contract");
    assert_eq!(contract.id, "posting-test");
    assert_eq!(contract.version, "1.0.0");
    assert_eq!(contract.digest, scenario.contract.digest());
    let (
        _,
        Evaluation::WorkContract {
            requirements,
            ignored,
            conflicts,
        },
    ) = reproduced(&report)
    else {
        panic!("a wvp-0.2 evaluation");
    };
    assert_eq!(requirements.len(), 1);
    assert_eq!(
        (requirements[0].id.as_str(), requirements[0].value),
        ("POSTED", Truth::True)
    );
    assert!(ignored.is_empty() && conflicts.is_empty());

    let shipped =
        run(&Scenario::shipped().text(), &trust(&[&evidence_key()])).expect("not refused");
    assert_eq!(shipped.contract, None);
    let (_, Evaluation::OrderTransition { conditions }) = reproduced(&shipped) else {
        panic!("a wvp-0.1 evaluation");
    };
    let holding: Vec<_> = conditions
        .iter()
        .filter(|c| c.holds)
        .map(|c| c.id)
        .collect();
    assert_eq!(
        holding,
        [
            "OUTCOME_IS_TARGET",
            "REQUIRED_EVIDENCE",
            "SUPPORTING_TRANSITION"
        ]
    );
    assert_eq!(conditions[3].evidence, [uuid(1)]);
}

#[test]
fn a_key_carried_only_by_the_package_is_never_trusted() {
    // The statement is correctly signed, but the relying party's registry
    // does not hold the key. Nothing in the package can vouch for it.
    for scenario in both() {
        assert_eq!(
            code(run(&scenario.text(), &trust(&[]))),
            RefusalCode::UnknownKey
        );
        assert_eq!(
            code(run(&scenario.text(), &trust(&[&issuer_key()]))),
            RefusalCode::UnknownKey
        );
    }
}

// ---- decisions other than SUPPORTED are reproduced, not refused ------------

#[test]
fn an_authentic_record_from_a_source_the_contract_does_not_accept_is_ignored() {
    // Two parties answer two questions: the registry lets this key speak for
    // "agent"; the contract accepts postings only from "erp".
    let agent = Key::new("test-agent-runtime", 3, &["agent"]);
    let mut scenario = Scenario::posted();
    scenario.items = vec![Item::new(
        1,
        &agent,
        "agent",
        scenario.items[0].body.clone(),
    )];
    scenario.outcome = json(&format!(
        r#"{{"decision": "UNDETERMINED", "requirements": [{{"id": "POSTED", "value": "UNKNOWN"}}],
            "ignored": ["e-{}"], "conflicts": []}}"#,
        uuid(1)
    ));
    let report = run(&scenario.text(), &trust(&[&agent])).expect("not refused");
    assert!(report.is_complete());
    let (
        decision,
        Evaluation::WorkContract {
            requirements,
            ignored,
            ..
        },
    ) = reproduced(&report)
    else {
        panic!("a wvp-0.2 evaluation");
    };
    assert_eq!(decision, Decision::Undetermined);
    assert_eq!(requirements[0].value, Truth::Unknown);
    assert_eq!(ignored, &[format!("e-{}", uuid(1))]);
}

#[test]
fn a_listing_declared_complete_without_the_record_contradicts_the_claim() {
    let mut scenario = Scenario::posted();
    let other = json(
        r#"{"record": {"kind": "posting", "fields": {"document": "D-2", "invoice": "INV-2"}}}"#,
    );
    // 2026-03-01T10:00:00Z, the second the statement was observed in.
    let complete = json(r#"{"complete": {"kind": "posting", "asOf": "1772359200"}}"#);
    scenario.items = vec![
        Item::new(1, &evidence_key(), "erp", other),
        Item::new(2, &evidence_key(), "erp", complete),
    ];
    scenario.claim = replaced(
        &scenario.claim,
        &["evidence"],
        Some(list([wrapped(uuid(1)), wrapped(uuid(2))])),
    );
    scenario.outcome = json(
        r#"{"decision": "CONTRADICTED", "requirements": [{"id": "POSTED", "value": "FALSE"}],
            "ignored": [], "conflicts": []}"#,
    );
    let report = run(&scenario.text(), &trust(&[&evidence_key()])).expect("not refused");
    assert!(report.is_complete());
    assert_eq!(reproduced(&report).0, Decision::Contradicted);

    // Without the completeness statement the same absence settles nothing.
    scenario.items.pop();
    scenario.claim = replaced(
        &scenario.claim,
        &["evidence"],
        Some(list([wrapped(uuid(1))])),
    );
    assert_eq!(refused(&scenario), RefusalCode::DecisionMismatch);
    scenario.outcome = json(
        r#"{"decision": "UNDETERMINED", "requirements": [{"id": "POSTED", "value": "UNKNOWN"}],
            "ignored": [], "conflicts": []}"#,
    );
    let report = run(&scenario.text(), &trust(&[&evidence_key()])).expect("not refused");
    assert_eq!(reproduced(&report).0, Decision::Undetermined);
}

fn transition(to: &str) -> Value {
    object([(
        "StateTransition",
        object([
            ("subject", support::subject()),
            ("from", unit("Approved")),
            ("to", unit(to)),
            ("at", wrapped("2026-03-01T10:00:00Z")),
        ]),
    )])
}

fn conditions(decision: &str, contradicting: bool, supporting: bool) -> Value {
    let evidence = |holds: bool| {
        if holds {
            vec![wrapped(uuid(1))]
        } else {
            Vec::new()
        }
    };
    object([
        ("decision", string(decision)),
        (
            "conditions",
            list([
                object([
                    ("id", string("CONTRADICTING_TRANSITION")),
                    ("holds", Value::Bool(contradicting)),
                    ("evidence", list(evidence(contradicting))),
                ]),
                condition("OUTCOME_IS_TARGET", true, []),
                condition("REQUIRED_EVIDENCE", true, []),
                object([
                    ("id", string("SUPPORTING_TRANSITION")),
                    ("holds", Value::Bool(supporting)),
                    ("evidence", list(evidence(supporting))),
                ]),
            ]),
        ),
    ])
}

#[test]
fn a_transition_to_another_state_contradicts_a_v01_claim() {
    let mut scenario = Scenario::shipped();
    scenario.items[0].body = transition("Cancelled");
    scenario.outcome = conditions("CONTRADICTED", true, false);
    let report = run(&scenario.text(), &trust(&[&evidence_key()])).expect("not refused");
    assert!(report.is_complete());
    assert_eq!(reproduced(&report).0, Decision::Contradicted);
}

#[test]
fn a_v01_statement_about_another_system_neither_supports_nor_contradicts() {
    let other = Key::new("test-other-gateway", 4, &["warehouse"]);
    let mut scenario = Scenario::shipped();
    scenario.items[0].key = other.clone();
    scenario.items[0].source = "warehouse".to_owned();
    scenario.outcome = conditions("UNDETERMINED", false, false);
    let report = run(&scenario.text(), &trust(&[&other])).expect("not refused");
    assert_eq!(reproduced(&report).0, Decision::Undetermined);
    // The same package recorded as supported is not reproduced.
    scenario.outcome = conditions("SUPPORTED", false, true);
    assert_eq!(
        code(run(&scenario.text(), &trust(&[&other]))),
        RefusalCode::DecisionMismatch
    );
}

// ---- step 7: component shapes ----------------------------------------------

#[test]
fn step_7_components_are_closed_at_every_depth() {
    let changes: [(usize, &[&str], Option<Value>); 9] = [
        (CLAIM, &["unknown"], Some(Value::Null)),
        (CLAIM, &["claimant"], None),
        (
            CLAIM,
            &["id", "value"],
            Some(string(uuid(0xabc).to_uppercase())),
        ),
        (
            CLAIM,
            &["submittedAt", "value"],
            Some(string("2026-03-01T12:30:00.000Z")),
        ),
        (
            CLAIM,
            &["submittedAt", "value"],
            Some(string("2026-02-30T12:30:00Z")),
        ),
        (
            DECISION,
            &["commitments", "claim", "extra"],
            Some(Value::Null),
        ),
        (
            STATEMENTS,
            &["0", "statement", "kind"],
            Some(unit("Rumour")),
        ),
        (
            STATEMENTS,
            &["0", "statement", "kind", "Event", "x"],
            Some(Value::Null),
        ),
        (
            STATEMENTS,
            &["0", "signature", "scheme"],
            Some(Value::Integer(1.into())),
        ),
    ];
    for scenario in both() {
        for (file, path, new) in &changes {
            // The kind differs between the scenarios; address whichever is there.
            let path: Vec<&str> = path
                .iter()
                .map(|p| {
                    if *p == "Event" {
                        scenario.items[0].kind
                    } else {
                        p
                    }
                })
                .collect();
            let text = with_file(&scenario, *file, &path, new.clone());
            for registry in [None, Some(trust(&[&evidence_key()]))] {
                let options = Options {
                    trust: registry.as_ref(),
                    ..Options::default()
                };
                let result = verify(text.as_bytes(), &options);
                assert!(
                    matches!(&result, Err(Rejection::Refused(r)) if r.code == RefusalCode::MalformedComponent),
                    "{} file {file} {path:?}: {result:?}",
                    scenario.protocol
                );
            }
        }
    }
}

#[test]
fn step_7_bodies_are_listed_cases_and_aligned_with_statements() {
    let v01 = Scenario::shipped();
    let observation = json(r#"{"SensorReading": {"celsius": 21}}"#);
    assert_eq!(
        code(run(
            &with_file(&v01, BODIES, &["0", "body"], Some(observation)),
            &trust(&[])
        )),
        RefusalCode::MalformedComponent
    );

    let v02 = Scenario::posted();
    let two_things = json(
        r#"{"record": {"kind": "posting", "fields": {}}, "complete": {"kind": "posting", "asOf": "0"}}"#,
    );
    for body in [
        two_things,
        json("{}"),
        json(r#"{"complete": {"kind": "posting", "asOf": 0}}"#),
    ] {
        assert_eq!(
            code(run(
                &with_file(&v02, BODIES, &["0", "body"], Some(body)),
                &trust(&[])
            )),
            RefusalCode::MalformedComponent
        );
    }
    // A body for another statement, and a body without a statement.
    assert_eq!(
        code(run(
            &with_file(&v02, BODIES, &["0", "id"], Some(wrapped(uuid(9)))),
            &trust(&[])
        )),
        RefusalCode::MalformedComponent
    );
    assert_eq!(
        code(run(&with_file(&v02, STATEMENTS, &["0"], None), &trust(&[]))),
        RefusalCode::MalformedComponent
    );
}

#[test]
fn step_7_statements_are_in_ascending_order_of_identifier() {
    let mut scenario = Scenario::posted();
    scenario.items.push(Item::new(
        2,
        &evidence_key(),
        "erp",
        scenario.items[0].body.clone(),
    ));
    let mut draft = scenario.draft();
    for file in [BODIES, STATEMENTS] {
        let Value::Array(items) = &mut draft.files[file].1 else {
            panic!("an array");
        };
        items.reverse();
    }
    assert_eq!(
        code(run(&draft.text(), &trust(&[]))),
        RefusalCode::MalformedComponent
    );
}

#[test]
fn step_7_a_v02_contract_must_be_a_well_formed_contract() {
    let scenario = Scenario::posted();
    let edits: [(&[&str], Option<Value>); 5] = [
        // Not a contract of the language's forms.
        (&["requires", "0", "predicate"], Some(string("return true"))),
        (&["title"], Some(string("Invoice processing"))),
        // A contract that breaks a static rule.
        (&["language"], Some(string("work-contract-2"))),
        (&["evidence", "sources", "posting"], Some(list([]))),
        (
            &["requires", "0", "predicate", "in"],
            Some(string("undeclared")),
        ),
    ];
    for (path, new) in edits {
        let mut changed = scenario.clone();
        changed.contract = replaced(&changed.contract, path, new);
        // The claim names the changed contract, so only its form is wrong.
        changed.claim = replaced(&changed.claim, &["contract"], Some(hash(&changed.contract)));
        assert_eq!(
            refused(&changed),
            RefusalCode::MalformedComponent,
            "{path:?}"
        );
    }
}

#[test]
fn step_7_an_unresolved_conflict_has_no_resolved_to_member() {
    let mut scenario = Scenario::posted();
    scenario.outcome = replaced(
        &scenario.outcome,
        &["conflicts"],
        Some(json(
            r#"[{"kind": "posting", "facts": ["e-1", "e-2"], "resolvedTo": null}]"#,
        )),
    );
    assert_eq!(refused(&scenario), RefusalCode::MalformedComponent);
}

// ---- step 8: the evaluator -------------------------------------------------

#[test]
fn step_8_the_decision_names_this_protocols_evaluator() {
    for scenario in both() {
        let mut other = scenario.clone();
        other.evaluator = json(r#"{"name": "some-other-evaluator", "specification": "1"}"#);
        assert_eq!(refused(&other), RefusalCode::UnsupportedEvaluator);

        let mut later = scenario.clone();
        later.evaluator = replaced(&later.evaluator, &["specification"], Some(string("2")));
        assert_eq!(refused(&later), RefusalCode::UnsupportedEvaluator);

        // A decision made under the other protocol version.
        let mut crossed = scenario.clone();
        crossed.decision_protocol = if scenario.protocol == "wvp-0.1" {
            "wvp-0.2"
        } else {
            "wvp-0.1"
        };
        assert_eq!(refused(&crossed), RefusalCode::UnsupportedEvaluator);

        // Without a registry the evaluator is not looked at: integrity only.
        let report = verify(other.text().as_bytes(), &Options::default()).expect("not refused");
        assert!(!report.is_complete());
    }
}

#[test]
fn the_two_versions_evaluators_are_never_interchanged() {
    // The v0.2 evaluator named in a v0.1 package, and the reverse.
    let [mut shipped, mut posted] = both();
    std::mem::swap(&mut shipped.evaluator, &mut posted.evaluator);
    assert_eq!(refused(&shipped), RefusalCode::UnsupportedEvaluator);
    assert_eq!(refused(&posted), RefusalCode::UnsupportedEvaluator);
}

// ---- step 9: statements under the registry ---------------------------------

/// A registry record for the evidence key that differs from the signer's
/// own view in one respect.
fn registered(change: impl FnOnce(&mut Key)) -> Trust {
    let mut key = evidence_key();
    change(&mut key);
    trust(&[&key])
}

#[test]
fn step_9_each_statement_check_has_its_own_code() {
    for scenario in both() {
        let text = scenario.text();
        let cases: [(Trust, RefusalCode); 9] = [
            (trust(&[&issuer_key()]), RefusalCode::UnknownKey),
            (
                registered(|k| k.algorithm = "RSA"),
                RefusalCode::UnsupportedAlgorithm,
            ),
            (
                registered(|k| k.tenant = "tenant-other"),
                RefusalCode::TenantMismatch,
            ),
            (
                registered(|k| k.issuer = uuid(0xbad)),
                RefusalCode::IssuerMismatch,
            ),
            (
                registered(|k| k.sources = vec!["agent"]),
                RefusalCode::SourceNotAuthorized,
            ),
            (
                registered(|k| k.sources = vec![]),
                RefusalCode::SourceNotAuthorized,
            ),
            (
                registered(|k| k.valid_from = "2026-03-01T10:00:00.001Z"),
                RefusalCode::KeyNotValid,
            ),
            // Validity ends before `validUntil`, and at revocation.
            (
                registered(|k| k.valid_until = Some("2026-03-01T10:00:00Z")),
                RefusalCode::KeyNotValid,
            ),
            (
                registered(|k| k.revoked_at = Some("2026-03-01T10:00:00Z")),
                RefusalCode::KeyNotValid,
            ),
        ];
        for (registry, expected) in cases {
            assert_eq!(
                code(run(&text, &registry)),
                expected,
                "{}",
                scenario.protocol
            );
        }
        // One instant earlier, the key is valid.
        let still_valid = registered(|k| k.revoked_at = Some("2026-03-01T10:00:00.001Z"));
        assert!(run(&text, &still_valid).is_ok());
    }
}

#[test]
fn step_9_protocol_and_commitments_are_checked_before_the_key() {
    for scenario in both() {
        let mut other = scenario.clone();
        other.items[0].protocol = "verified-evidence-statement-v2".to_owned();
        // Even an unknown key does not come first.
        assert_eq!(
            code(run(&other.text(), &trust(&[]))),
            RefusalCode::UnsupportedProtocol
        );

        for payload in [
            json(r#"{"algorithm": "md5", "hex": "d41d8cd98f00b204e9800998ecf8427e"}"#),
            object([
                ("algorithm", string("sha-256")),
                ("hex", string("AB".repeat(32))),
            ]),
            object([
                ("algorithm", string("sha-256")),
                ("hex", string("ab".repeat(31))),
            ]),
        ] {
            let mut malformed = scenario.clone();
            malformed.items[0].payload = Some(payload);
            assert_eq!(
                code(run(&malformed.text(), &trust(&[]))),
                RefusalCode::MalformedCommitment
            );
        }
    }
}

#[test]
fn step_9_a_signature_must_verify_over_the_domain_separated_statement() {
    for scenario in both() {
        let registry = trust(&[&evidence_key()]);
        let statement = scenario.items[0].statement();
        // Signed by another key under the registered key's identifier.
        let mut impostor = Key::new(evidence_key().id, 9, &["erp"]);
        impostor.issuer = evidence_key().issuer;
        let forgeries = [
            impostor.sign(STATEMENT_DOMAIN, &statement),
            // The right key over the statement without its domain, and under
            // the decision's domain.
            evidence_key().sign("", &statement),
            evidence_key().sign("verified:wvp-decision:v0.2\n", &statement),
            // The right key over another statement.
            evidence_key().sign(STATEMENT_DOMAIN, &Value::Null),
            json(r#"{"scheme": "Ed25519", "keyId": "test-erp-gateway", "encoded": "not base64"}"#),
            json(r#"{"scheme": "Ed25519", "keyId": "test-erp-gateway", "encoded": "AAAA"}"#),
        ];
        for signature in forgeries {
            let text = with_file(&scenario, STATEMENTS, &["0", "signature"], Some(signature));
            assert_eq!(code(run(&text, &registry)), RefusalCode::SignatureInvalid);
        }
        // A statement altered after it was signed.
        let text = with_file(
            &scenario,
            STATEMENTS,
            &["0", "statement", "source", "observationId"],
            Some(string("another-observation")),
        );
        assert_eq!(code(run(&text, &registry)), RefusalCode::SignatureInvalid);
        // A scheme the protocol does not use.
        let text = with_file(
            &scenario,
            STATEMENTS,
            &["0", "signature", "scheme"],
            Some(string("RSA")),
        );
        assert_eq!(
            code(run(&text, &registry)),
            RefusalCode::UnsupportedAlgorithm
        );
    }
}

// ---- step 10: admission ----------------------------------------------------

#[test]
fn step_10_the_statements_are_exactly_the_evidence_of_this_claim() {
    for scenario in both() {
        // A statement of another tenant, validly signed by a key trusted for
        // that tenant: authentic, and not this evaluation's evidence.
        let mut foreign_key = evidence_key();
        foreign_key.tenant = "tenant-other";
        let mut foreign = scenario.clone();
        foreign.items[0].tenant = "tenant-other".to_owned();
        assert_eq!(
            code(run(&foreign.text(), &trust(&[&foreign_key]))),
            RefusalCode::ForeignTenantEvidence
        );

        let claiming = |evidence: Vec<Value>| {
            let mut changed = scenario.clone();
            changed.claim = replaced(&changed.claim, &["evidence"], Some(list(evidence)));
            refused(&changed)
        };
        let id = || wrapped(uuid(1));
        assert_eq!(claiming(vec![id(), id()]), RefusalCode::DuplicateEvidenceId);
        assert_eq!(claiming(vec![]), RefusalCode::EvidenceNotClaimed);
        assert_eq!(
            claiming(vec![wrapped(uuid(7))]),
            RefusalCode::EvidenceNotClaimed
        );
        assert_eq!(
            claiming(vec![id(), wrapped(uuid(7))]),
            RefusalCode::MissingEvidence
        );

        // A signed commitment to another body than the one carried.
        let mut swapped = scenario.clone();
        swapped.items[0].payload = Some(hash(&Value::Null));
        assert_eq!(refused(&swapped), RefusalCode::PayloadMismatch);
    }
}

#[test]
fn step_10_duplicate_statements_are_refused() {
    let mut scenario = Scenario::posted();
    scenario.items.push(scenario.items[0].clone());
    assert_eq!(refused(&scenario), RefusalCode::DuplicateEvidenceId);
}

// ---- step 11: input conditions ---------------------------------------------

#[test]
fn step_11_v02_inputs_that_do_not_belong_together() {
    let base = Scenario::posted();
    let cases: Vec<(&str, Change)> = vec![
        (
            "claim of another tenant",
            Box::new(|s| {
                s.claim = replaced(&s.claim, &["tenant"], Some(wrapped("tenant-other")));
            }),
        ),
        (
            "claim names another contract",
            Box::new(|s| {
                s.claim = replaced(&s.claim, &["contract"], Some(hash(&Value::Null)));
            }),
        ),
        (
            "claim names the contract under another algorithm",
            Box::new(|s| {
                s.claim = replaced(
                    &s.claim,
                    &["contract", "algorithm"],
                    Some(string("sha-512")),
                );
            }),
        ),
        (
            "submitted after evaluation",
            Box::new(|s| {
                s.claim = replaced(
                    &s.claim,
                    &["submittedAt"],
                    Some(wrapped("2026-03-01T13:00:00.001Z")),
                );
            }),
        ),
        (
            "ingested after assembly",
            Box::new(|s| {
                s.inputs = replaced(
                    &s.inputs,
                    &["ingestedAt"],
                    Some(wrapped("2026-03-01T12:00:01Z")),
                );
            }),
        ),
        (
            "assembled after evaluation",
            Box::new(|s| {
                s.inputs = replaced(
                    &s.inputs,
                    &["assembledAt"],
                    Some(wrapped("2026-03-01T13:00:01Z")),
                );
            }),
        ),
        (
            "observed after ingestion",
            Box::new(|s| {
                s.items[0].observed_at = "2026-03-01T11:00:00.001Z".to_owned();
            }),
        ),
        (
            "undeclared claim input",
            Box::new(|s| {
                s.claim = replaced(&s.claim, &["inputs", "extra"], Some(string("x")));
            }),
        ),
        (
            "missing claim input",
            Box::new(|s| {
                s.claim = replaced(&s.claim, &["inputs"], Some(json("{}")));
            }),
        ),
        (
            "claim input of the wrong type",
            Box::new(|s| {
                s.claim = replaced(&s.claim, &["inputs", "invoice"], Some(Value::Bool(true)));
            }),
        ),
        (
            "record with an undeclared field",
            Box::new(|s| {
                s.items[0].body = json(
                    r#"{"record": {"kind": "posting", "fields": {"document": "D-1", "invoice": "INV-1", "x": "y"}}}"#,
                );
            }),
        ),
        (
            "record missing a required field",
            Box::new(|s| {
                s.items[0].body =
                    json(r#"{"record": {"kind": "posting", "fields": {"document": "D-1"}}}"#);
            }),
        ),
    ];
    for (what, change) in cases {
        let mut scenario = base.clone();
        change(&mut scenario);
        assert_eq!(refused(&scenario), RefusalCode::InputMismatch, "{what}");
    }
}

#[test]
fn step_11_a_source_cannot_vouch_for_a_time_after_it_spoke() {
    let complete = |as_of: &str| {
        let mut scenario = Scenario::posted();
        let body = json(&format!(
            r#"{{"complete": {{"kind": "posting", "asOf": "{as_of}"}}}}"#
        ));
        scenario
            .items
            .push(Item::new(2, &evidence_key(), "erp", body));
        scenario.claim = replaced(
            &scenario.claim,
            &["evidence"],
            Some(list([wrapped(uuid(1)), wrapped(uuid(2))])),
        );
        scenario
    };
    // Observed at 2026-03-01T10:00:00Z, which is second 1772359200.
    assert!(run(&complete("1772359200").text(), &trust(&[&evidence_key()])).is_ok());
    for bad in ["1772359201", "-1", "01", "1.0", "", "99999999999999999999"] {
        assert_eq!(
            refused(&complete(bad)),
            RefusalCode::InputMismatch,
            "{bad:?}"
        );
    }
}

#[test]
fn step_11_v01_inputs_that_do_not_belong_together() {
    let base = Scenario::shipped();
    let cases: Vec<(&str, Change)> = vec![
        (
            "claim against another contract",
            Box::new(|s| {
                s.claim = replaced(&s.claim, &["contractId"], Some(wrapped(uuid(0x7ff))));
            }),
        ),
        (
            "claim about another subject",
            Box::new(|s| {
                s.claim = replaced(&s.claim, &["subject", "key"], Some(string("SO-2")));
            }),
        ),
        (
            "claim of another outcome",
            Box::new(|s| {
                s.claim = replaced(&s.claim, &["outcome"], Some(unit("OrderRecorded")));
            }),
        ),
        (
            "work outside the contract's validity",
            Box::new(|s| {
                s.contract = replaced(
                    &s.contract,
                    &["validity", "from"],
                    Some(wrapped("2026-03-01T10:00:00.001Z")),
                );
            }),
        ),
        (
            "work at the end of the contract's validity",
            Box::new(|s| {
                s.contract = replaced(
                    &s.contract,
                    &["validity", "until"],
                    Some(wrapped("2026-03-01T10:00:00Z")),
                );
            }),
        ),
        (
            "evaluated before submission",
            Box::new(|s| {
                s.claim = replaced(
                    &s.claim,
                    &["submittedAt"],
                    Some(wrapped("2026-03-01T13:00:00.001Z")),
                );
            }),
        ),
        (
            "evaluated before assembly",
            Box::new(|s| {
                s.inputs = replaced(
                    &s.inputs,
                    &["assembledAt"],
                    Some(wrapped("2026-03-01T13:00:01Z")),
                );
            }),
        ),
        (
            "no statements",
            Box::new(|s| {
                s.items.clear();
                s.claim = replaced(&s.claim, &["evidence"], Some(list([])));
            }),
        ),
    ];
    for (what, change) in cases {
        let mut scenario = base.clone();
        change(&mut scenario);
        assert_eq!(refused(&scenario), RefusalCode::InputMismatch, "{what}");
    }
}

// ---- step 12: the decision is reproduced, not believed ---------------------

#[test]
fn step_12_a_recorded_decision_that_does_not_follow_is_refused() {
    let posted = Scenario::posted();
    let shipped = Scenario::shipped();
    let cases: [(&Scenario, &[&str], Value); 5] = [
        (&posted, &["decision"], string("CONTRADICTED")),
        (&posted, &["requirements", "0", "value"], string("UNKNOWN")),
        (&posted, &["ignored"], list([string("e-1")])),
        (&shipped, &["decision"], string("UNDETERMINED")),
        (&shipped, &["conditions", "3", "evidence"], list([])),
    ];
    for (scenario, path, new) in cases {
        let mut changed = scenario.clone();
        changed.outcome = replaced(&changed.outcome, path, Some(new));
        assert_eq!(refused(&changed), RefusalCode::DecisionMismatch, "{path:?}");
        // An issuer's signature over the wrong decision changes nothing.
        changed.issuers = vec![issuer_key()];
        assert_eq!(
            refused(&changed),
            RefusalCode::DecisionMismatch,
            "{path:?} signed"
        );
    }
}

#[test]
fn step_12_the_decision_commits_to_exactly_what_was_evaluated() {
    for scenario in both() {
        for commitment in ["claim", "contract", "evidence", "inputs"] {
            let text = with_file(
                &scenario,
                DECISION,
                &["commitments", commitment],
                Some(hash(&string("something else"))),
            );
            assert_eq!(
                code(run(&text, &trust(&[&evidence_key()]))),
                RefusalCode::DecisionMismatch,
                "{} {commitment}",
                scenario.protocol
            );
        }
    }
}

// ---- step 13: issuer signatures --------------------------------------------

#[test]
fn step_13_an_issuer_signature_counts_only_under_the_registry() {
    for scenario in both() {
        let mut signed = scenario.clone();
        signed.issuers = vec![issuer_key()];
        let text = signed.text();
        let report = run(&text, &trust(&[&evidence_key(), &issuer_key()])).expect("not refused");
        assert_eq!(
            report.issuer_signature,
            IssuerSignature::Established { count: 1 }
        );
        assert!(report.is_complete());

        let with_issuer = |change: &dyn Fn(&mut Key)| {
            let mut issuer = issuer_key();
            change(&mut issuer);
            code(run(&text, &trust(&[&evidence_key(), &issuer])))
        };
        let invalid = RefusalCode::IssuerSignatureInvalid;
        // The registry does not hold the issuer's key at all.
        assert_eq!(code(run(&text, &trust(&[&evidence_key()]))), invalid);
        assert_eq!(with_issuer(&|k| k.sources = vec!["erp"]), invalid);
        assert_eq!(with_issuer(&|k| k.tenant = "tenant-other"), invalid);
        assert_eq!(with_issuer(&|k| k.algorithm = "RSA"), invalid);
        // Validity is judged at the evaluation time.
        assert_eq!(
            with_issuer(&|k| k.valid_from = "2026-03-01T13:00:00.001Z"),
            invalid
        );
        assert_eq!(
            with_issuer(&|k| k.revoked_at = Some("2026-03-01T13:00:00Z")),
            invalid
        );

        // An evidence key may not sign decisions.
        let mut by_evidence_key = scenario.clone();
        by_evidence_key.issuers = vec![evidence_key()];
        assert_eq!(refused(&by_evidence_key), invalid);

        // One good signature does not carry a bad one.
        let mut draft = signed.draft();
        let Value::Array(signatures) = &mut draft.signatures else {
            panic!("an array");
        };
        signatures.push(json(
            r#"{"scheme": "Ed25519", "keyId": "test-decision-issuer", "encoded": "AAAA"}"#,
        ));
        assert_eq!(
            code(run(
                &draft.text(),
                &trust(&[&evidence_key(), &issuer_key()])
            )),
            invalid
        );
    }
}

#[test]
fn step_13_a_signature_over_one_versions_decision_is_not_one_over_the_others() {
    for scenario in both() {
        let other_domain = if scenario.protocol == "wvp-0.1" {
            "verified:wvp-decision:v0.2\n"
        } else {
            "verified:wvp-decision:v0.1\n"
        };
        let mut draft = scenario.draft();
        draft.signatures = list([issuer_key().sign(other_domain, &scenario.decision())]);
        assert_eq!(
            code(run(
                &draft.text(),
                &trust(&[&evidence_key(), &issuer_key()])
            )),
            RefusalCode::IssuerSignatureInvalid
        );
    }
}

// ---- expectations ----------------------------------------------------------

fn expecting(
    scenario: &Scenario,
    expectations: Expectations,
    registry: Option<&Trust>,
) -> Result<Report, Rejection> {
    let options = Options {
        trust: registry,
        expectations,
        ..Options::default()
    };
    verify(scenario.text().as_bytes(), &options)
}

#[test]
fn expectations_are_checked_after_everything_else_in_the_protocols_order() {
    let scenario = Scenario::posted();
    let registry = trust(&[&evidence_key()]);
    let met = Expectations {
        tenant: Some(TENANT.to_owned()),
        contract: Some(scenario.contract.digest()),
        claim: Some(uuid(0x500)),
    };
    let report = expecting(&scenario, met.clone(), Some(&registry)).expect("not refused");
    assert_eq!(report.expectations_met, met);
    assert!(report.is_complete());

    let unmet = Expectations {
        tenant: Some("tenant-other".to_owned()),
        contract: Some(Value::Null.digest()),
        claim: Some(uuid(0x999)),
    };
    assert_eq!(
        code(expecting(&scenario, unmet.clone(), Some(&registry))),
        RefusalCode::TenantNotExpected
    );
    let without_tenant = Expectations {
        tenant: None,
        ..unmet.clone()
    };
    assert_eq!(
        code(expecting(&scenario, without_tenant, Some(&registry))),
        RefusalCode::ContractNotExpected
    );
    let claim_only = Expectations {
        claim: unmet.claim.clone(),
        ..Expectations::default()
    };
    assert_eq!(
        code(expecting(&scenario, claim_only, Some(&registry))),
        RefusalCode::ClaimNotExpected
    );

    // A package that fails a protocol check is refused for that, not for an
    // unmet expectation.
    let mut wrong = scenario.clone();
    wrong.outcome = replaced(&wrong.outcome, &["decision"], Some(string("CONTRADICTED")));
    assert_eq!(
        code(expecting(&wrong, unmet.clone(), Some(&registry))),
        RefusalCode::DecisionMismatch
    );

    // Expectations are about the package's own content, so they are checked
    // without a registry too.
    assert_eq!(
        code(expecting(&scenario, unmet, None)),
        RefusalCode::TenantNotExpected
    );
}

#[test]
fn expectations_given_for_v01_are_not_silently_ignored() {
    let scenario = Scenario::shipped();
    let expectations = Expectations {
        tenant: Some(TENANT.to_owned()),
        ..Expectations::default()
    };
    assert_eq!(
        expecting(&scenario, expectations, Some(&trust(&[&evidence_key()]))),
        Err(Rejection::ExpectationsUndefined(ProtocolVersion::V0_1))
    );
}

// ---- registries ------------------------------------------------------------

#[test]
fn a_registry_with_unusable_key_material_is_refused_when_loaded() {
    let with_material = |material: &str| {
        let record = replaced(
            &evidence_key().record(),
            &["publicKey"],
            Some(string(material)),
        );
        Trust::from_value(&object([("keys", list([record]))]))
    };
    for material in [
        "not base64",
        "AAAA",
        // A raw 32-byte key without its SubjectPublicKeyInfo.
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        // The identity point: a small-order key, under which forged
        // signatures verify.
        "MCowBQYDK2VwAyEAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    ] {
        assert!(
            matches!(with_material(material), Err(TrustError::KeyMaterial { .. })),
            "{material}"
        );
    }
    // An unsupported algorithm is kept, undecoded.
    let mut rsa = evidence_key();
    rsa.algorithm = "RSA";
    let record = replaced(&rsa.record(), &["publicKey"], Some(string("anything")));
    assert!(Trust::from_value(&object([("keys", list([record]))])).is_ok());
}

// ---- properties ------------------------------------------------------------

/// Every position in a value, as a path `replaced` understands.
fn positions(value: &Value, here: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
    out.push(here.clone());
    let children: Vec<(String, &Value)> = match value {
        Value::Object(members) => members.iter().map(|(k, v)| (k.to_owned(), v)).collect(),
        Value::Array(items) => items
            .iter()
            .enumerate()
            .map(|(i, v)| (i.to_string(), v))
            .collect(),
        _ => Vec::new(),
    };
    for (segment, child) in children {
        here.push(segment);
        positions(child, here, out);
        here.pop();
    }
}

/// Values of every JSON type, drawn from spellings the protocol gives
/// meaning to, so that changes land near the checks rather than far from
/// them.
fn any_value() -> impl Strategy<Value = Value> {
    let text = prop::sample::select(vec![
        "",
        "0",
        "-1",
        "1772359200",
        "99999999999999999999",
        "sha-256",
        "TRUE",
        "SUPPORTED",
        "posting",
        "erp",
        "wvp-decision",
        "Ed25519",
        "2026-03-01T10:00:00Z",
        "2026-03-01T10:00:00.000Z",
        "00000000-0000-4000-8000-000000000001",
        "\u{0}",
        "é",
    ]);
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        (-3i64..3).prop_map(|n| Value::Integer(n.into())),
        Just(Value::Integer(i64::MAX.into())),
        text.clone().prop_map(string),
    ];
    leaf.prop_recursive(3, 12, 3, move |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..3).prop_map(Value::Array),
            prop::collection::vec((text.clone(), inner), 0..3).prop_map(|members| Value::Object(
                members
                    .into_iter()
                    .map(|(k, v)| (k.to_owned(), v))
                    .collect()
            )),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(192))]

    /// Every byte of a signed package is covered by a digest or a signature:
    /// no altered text verifies.
    #[test]
    fn any_single_byte_change_to_a_signed_package_is_refused(
        v02 in any::<bool>(),
        index in any::<prop::sample::Index>(),
        byte in any::<u8>(),
    ) {
        let mut scenario = if v02 { Scenario::posted() } else { Scenario::shipped() };
        scenario.issuers = vec![issuer_key()];
        let registry = trust(&[&evidence_key(), &issuer_key()]);
        let text = scenario.text();
        prop_assert!(run(&text, &registry).is_ok_and(|report| report.is_complete()));
        let mut bytes = text.into_bytes();
        let i = index.index(bytes.len());
        prop_assume!(bytes[i] != byte);
        bytes[i] = byte;
        let options = Options { trust: Some(&registry), ..Options::default() };
        prop_assert!(matches!(verify(&bytes, &options), Err(Rejection::Refused(_))));
    }

    /// A component changed anywhere, to anything, in a package whose digests,
    /// commitments and signatures were then made consistent again: the
    /// checks behind the container are reached, and none of them panics or
    /// answers differently the second time.
    #[test]
    fn a_consistently_repackaged_change_is_judged_deterministically_without_panicking(
        v02 in any::<bool>(),
        part in 0usize..5,
        position in any::<prop::sample::Index>(),
        new in prop::option::of(any_value()),
    ) {
        let mut scenario = if v02 { Scenario::posted() } else { Scenario::shipped() };
        let target = match part {
            0 => &mut scenario.claim,
            1 => &mut scenario.contract,
            2 => &mut scenario.inputs,
            3 => &mut scenario.outcome,
            _ => &mut scenario.items[0].body,
        };
        let mut all = Vec::new();
        positions(target, &mut Vec::new(), &mut all);
        let path = position.get(&all[1..]);
        let path: Vec<&str> = path.iter().map(String::as_str).collect();
        *target = replaced(target, &path, new);
        let registry = trust(&[&evidence_key()]);
        let text = scenario.text();
        let first = run(&text, &registry);
        prop_assert_eq!(&first, &run(&text, &registry));
        // Whatever the change, a complete report is never a refusal's twin:
        // without a registry the same package is at most integrity.
        if let Ok(report) = verify(text.as_bytes(), &Options::default()) {
            prop_assert!(!report.is_complete());
        }
    }
}

// ---- work records ------------------------------------------------------------

/// The record of a package, stated by hand from the scenario's own parts.
fn expected_record(scenario: &Scenario) -> Value {
    let draft = scenario.draft();
    let decision = scenario.decision();
    let commitments = decision
        .as_object()
        .and_then(|d| d.get("commitments"))
        .expect("commitments");
    let commitment = |name| {
        commitments
            .as_object()
            .and_then(|c| c.get(name))
            .expect("a commitment")
            .clone()
    };
    object([
        ("claimId", wrapped(uuid(0x500))),
        ("claim", hash(&scenario.claim)),
        ("contract", hash(&scenario.contract)),
        ("contractId", string("posting-test")),
        ("contractVersion", string("1.0.0")),
        ("evidence", commitment("evidence")),
        ("inputs", commitment("inputs")),
        ("decision", string("SUPPORTED")),
        ("decisionDigest", hash(&decision)),
        ("packageCommitment", hash(&draft.manifest())),
        ("protocol", string("wvp-0.2")),
        ("evaluator", string("work-contract")),
        ("specification", string("1")),
        ("language", string("work-contract-1")),
        ("semantics", string("kleene-1")),
    ])
}

fn with_record(
    scenario: &Scenario,
    record: &Value,
    registry: Option<&Trust>,
) -> Result<Report, Rejection> {
    let options = Options {
        trust: registry,
        record: Some(record),
        ..Options::default()
    };
    verify(scenario.text().as_bytes(), &options)
}

#[test]
fn a_work_record_is_a_function_of_the_package() {
    let scenario = Scenario::posted();
    let registry = trust(&[&evidence_key()]);
    let report = run(&scenario.text(), &registry).expect("not refused");
    assert_eq!(report.work_record, Some(expected_record(&scenario)));
    assert!(!report.record_matched);
    // The same record with or without a registry: it is computed from the
    // package, not from what was established.
    let integrity_only =
        verify(scenario.text().as_bytes(), &Options::default()).expect("not refused");
    assert_eq!(integrity_only.work_record, report.work_record);
    // wvp-0.1 defines none.
    let shipped = run(&Scenario::shipped().text(), &registry).expect("not refused");
    assert_eq!(shipped.work_record, None);
}

#[test]
fn a_record_about_this_package_is_accepted_and_any_other_is_refused_by_member() {
    let scenario = Scenario::posted();
    let registry = trust(&[&evidence_key()]);
    let record = expected_record(&scenario);
    let report = with_record(&scenario, &record, Some(&registry)).expect("not refused");
    assert!(report.record_matched && report.is_complete());

    let differing = |record: &Value| match with_record(&scenario, record, Some(&registry)) {
        Err(Rejection::Refused(refusal)) if refusal.code == RefusalCode::RecordMismatch => {
            refusal.detail
        }
        other => panic!("expected RECORD_MISMATCH, got {other:?}"),
    };
    // Each member on its own.
    let members: Vec<String> = record
        .as_object()
        .expect("an object")
        .keys()
        .map(str::to_owned)
        .collect();
    assert_eq!(members.len(), 15);
    for member in &members {
        let changed = replaced(&record, &[member.as_str()], Some(string("something else")));
        assert_eq!(
            differing(&changed),
            format!("the record is not about this package; it differs in: {member}"),
        );
        let missing = replaced(&record, &[member.as_str()], None);
        assert!(
            differing(&missing).ends_with(&format!(": {member}")),
            "{member} missing"
        );
    }
    // A record of another contract version, and one with a member the
    // protocol does not define: every difference is named, in order.
    let mut later = replaced(&record, &["contractVersion"], Some(string("1.1.0")));
    later = replaced(&later, &["contract"], Some(hash(&Value::Null)));
    later = replaced(&later, &["acceptedBy"], Some(string("someone")));
    assert!(differing(&later).ends_with(": acceptedBy, contract, contractVersion"));
    // Not a record at all.
    assert!(differing(&Value::Null).contains("claim, claimId"));
}

#[test]
fn a_record_is_compared_last_and_never_silently_dropped() {
    let scenario = Scenario::posted();
    let registry = trust(&[&evidence_key()]);
    let wrong = replaced(
        &expected_record(&scenario),
        &["decision"],
        Some(string("CONTRADICTED")),
    );

    // A package that fails a protocol check is refused for that.
    let mut changed = scenario.clone();
    changed.outcome = replaced(
        &changed.outcome,
        &["decision"],
        Some(string("CONTRADICTED")),
    );
    assert_eq!(
        code(with_record(&changed, &wrong, Some(&registry))),
        RefusalCode::DecisionMismatch
    );
    // An unmet expectation comes before the record.
    let options = Options {
        trust: Some(&registry),
        record: Some(&wrong),
        expectations: Expectations {
            tenant: Some("tenant-other".to_owned()),
            ..Expectations::default()
        },
        ..Options::default()
    };
    assert_eq!(
        code(verify(scenario.text().as_bytes(), &options)),
        RefusalCode::TenantNotExpected
    );
    // Without a registry the record is still compared with the package.
    assert_eq!(
        code(with_record(&scenario, &wrong, None)),
        RefusalCode::RecordMismatch
    );
    let report = with_record(&scenario, &expected_record(&scenario), None).expect("not refused");
    assert!(report.record_matched && !report.is_complete());
    // wvp-0.1 defines no work record; one given is an error, not ignored.
    assert_eq!(
        with_record(&Scenario::shipped(), &wrong, Some(&registry)),
        Err(Rejection::RecordUndefined(ProtocolVersion::V0_1))
    );
}
