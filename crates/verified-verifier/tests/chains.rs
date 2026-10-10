// SPDX-License-Identifier: Apache-2.0

//! Statements outside a package: authentication, chains and admission.
//!
//! Everything here is synthetic and built in process. The protocol's own
//! vectors are run by `evidence_conformance.rs`.

mod support;

use proptest::prelude::*;
use support::{
    Item, Key, STATEMENT_DOMAIN, TENANT, evidence_key, hash, object, registry, replaced, string,
};
use verified_canonical::Value;
use verified_protocol::RefusalCode;
use verified_verifier::Trust;
use verified_verifier::evidence::{
    Anchor, Authenticated, EvidenceCode, EvidenceRefusal, Segment, admit, authenticate,
    verify_chain,
};

const STREAM: &str = "erp/orders";

fn trust(keys: &[&Key]) -> Trust {
    Trust::from_value(&registry(keys)).expect("a usable test registry")
}

fn body(n: u32) -> Value {
    object([("note", string(format!("observation {n}")))])
}

/// The unsigned statement of evidence `n`, as step `sequence` of `stream`.
fn link(key: &Key, n: u32, stream: &str, sequence: i64, previous: Option<&Value>) -> Value {
    let chain = object([
        ("previous", previous.map_or(Value::Null, hash)),
        ("sequence", Value::Integer(sequence.into())),
        ("stream", string(stream)),
    ]);
    replaced(
        &Item::new(n, key, "erp", body(n)).statement(),
        &["chain"],
        Some(chain),
    )
}

fn signed(key: &Key, statement: Value) -> Value {
    object([
        ("signature", key.sign(STATEMENT_DOMAIN, &statement)),
        ("statement", statement),
    ])
}

/// `count` signed statements: steps 0, 1, … of one stream, each naming the
/// one before it.
fn run(key: &Key, count: u32) -> Vec<Value> {
    let mut statements: Vec<Value> = Vec::new();
    for n in 0..count {
        let statement = link(key, n + 1, STREAM, i64::from(n), statements.last());
        statements.push(statement);
    }
    statements.into_iter().map(|s| signed(key, s)).collect()
}

fn authentic<'a>(signed: &'a [Value], trust: &Trust) -> Vec<Authenticated<'a>> {
    signed
        .iter()
        .map(|s| authenticate(s, trust).expect("an authentic statement"))
        .collect()
}

fn chain(signed: &[Value], anchor: Option<&Anchor>) -> Result<Segment, EvidenceRefusal> {
    verify_chain(&authentic(signed, &trust(&[&evidence_key()])), anchor)
}

fn code<T: std::fmt::Debug>(result: Result<T, EvidenceRefusal>) -> &'static str {
    result.expect_err("a refusal").code.as_str()
}

fn statement_of(signed: &Value) -> &Value {
    signed
        .as_object()
        .and_then(|o| o.get("statement"))
        .expect("a signed statement")
}

#[test]
fn a_run_from_the_first_step_is_a_segment_with_its_last_step_as_head() {
    let signed = run(&evidence_key(), 3);
    let segment = chain(&signed, None).expect("a segment");
    assert!(segment.from_genesis);
    assert_eq!(segment.first, 0);
    assert_eq!(segment.head.sequence, 2);
    assert_eq!(segment.head.digest, statement_of(&signed[2]).digest());
    assert_eq!(segment.head.tenant, TENANT);
    assert_eq!(segment.head.issuer, evidence_key().issuer);
    assert_eq!(segment.head.stream, STREAM);
}

#[test]
fn a_segment_s_head_anchors_the_steps_after_it() {
    let signed = run(&evidence_key(), 5);
    let head = chain(&signed[..2], None).expect("the first two steps").head;
    let rest = chain(&signed[2..], Some(&head)).expect("the steps after them");
    assert!(!rest.from_genesis);
    assert_eq!((rest.first, rest.head.sequence), (2, 4));
    // The whole run and the run in two parts end at the same head.
    assert_eq!(rest.head, chain(&signed, None).expect("the whole run").head);
}

#[test]
fn a_missing_tail_cannot_be_noticed() {
    let signed = run(&evidence_key(), 4);
    let segment = chain(&signed[..3], None).expect("a shorter run is still a run");
    assert_eq!(segment.head.sequence, 2);
}

#[test]
fn no_statement_or_an_unchained_one_is_not_a_chain() {
    assert_eq!(code(chain(&[], None)), "CHAIN_MISSING");
    let key = evidence_key();
    let mut signed = run(&key, 2);
    signed.push(Item::new(9, &key, "erp", body(9)).signed());
    assert_eq!(code(chain(&signed, None)), "CHAIN_MISSING");
}

#[test]
fn a_stream_is_one_tenant_one_issuer_and_one_name() {
    let key = evidence_key();
    let signed = run(&key, 2);
    let first = statement_of(&signed[0]);

    let elsewhere = signed_link(&key, 2, "erp/invoices", 1, Some(first));
    assert_eq!(
        code(chain(&[signed[0].clone(), elsewhere], None)),
        "CHAIN_MIXED_STREAMS"
    );

    let other = Key::new("test-other-gateway", 7, &["erp"]);
    let by_another = signed_link(&other, 2, STREAM, 1, Some(first));
    let both = trust(&[&key, &other]);
    let statements = [signed[0].clone(), by_another];
    assert_eq!(
        code(verify_chain(&authentic(&statements, &both), None)),
        "CHAIN_MIXED_STREAMS"
    );

    let head = chain(&signed[..1], None).expect("the first step").head;
    for anchor in [
        Anchor {
            tenant: "tenant-other".to_owned(),
            ..head.clone()
        },
        Anchor {
            issuer: other.issuer.clone(),
            ..head.clone()
        },
        Anchor {
            stream: "erp/invoices".to_owned(),
            ..head.clone()
        },
    ] {
        assert_eq!(
            code(chain(&signed[1..], Some(&anchor))),
            "CHAIN_MIXED_STREAMS"
        );
    }
}

fn signed_link(key: &Key, n: u32, stream: &str, sequence: i64, previous: Option<&Value>) -> Value {
    signed(key, link(key, n, stream, sequence, previous))
}

#[test]
fn two_different_statements_at_one_step_are_a_fork() {
    let key = evidence_key();
    let signed = run(&key, 2);
    let fork = signed_link(&key, 8, STREAM, 1, Some(statement_of(&signed[0])));
    let statements = [signed[0].clone(), signed[1].clone(), fork];
    assert_eq!(code(chain(&statements, None)), "CHAIN_EQUIVOCATION");
}

#[test]
fn statements_out_of_order_or_repeated_are_refused() {
    let signed = run(&evidence_key(), 3);
    let swapped = [signed[0].clone(), signed[2].clone(), signed[1].clone()];
    assert_eq!(code(chain(&swapped, None)), "CHAIN_REORDERED");
    // The same statement twice is not a fork, and is not a run either.
    let repeated = [signed[0].clone(), signed[1].clone(), signed[1].clone()];
    assert_eq!(code(chain(&repeated, None)), "CHAIN_REORDERED");
}

#[test]
fn without_an_anchor_a_run_starts_at_the_first_step() {
    let key = evidence_key();
    let signed = run(&key, 3);
    assert_eq!(code(chain(&signed[1..], None)), "CHAIN_GENESIS_INVALID");
    let first_with_predecessor = signed_link(&key, 1, STREAM, 0, Some(statement_of(&signed[2])));
    assert_eq!(
        code(chain(&[first_with_predecessor], None)),
        "CHAIN_GENESIS_INVALID"
    );
}

#[test]
fn a_skipped_step_is_a_gap() {
    let signed = run(&evidence_key(), 4);
    let skipped = [signed[0].clone(), signed[2].clone()];
    assert_eq!(code(chain(&skipped, None)), "CHAIN_GAP");

    let head = chain(&signed[..1], None).expect("the first step").head;
    assert_eq!(code(chain(&signed[2..], Some(&head))), "CHAIN_GAP");
    // A step cannot follow the largest sequence number there is.
    let last = Anchor {
        sequence: i64::MAX,
        ..head
    };
    assert_eq!(code(chain(&signed[1..], Some(&last))), "CHAIN_GAP");
}

#[test]
fn a_step_must_name_the_digest_of_the_step_before_it() {
    let key = evidence_key();
    let signed = run(&key, 3);
    let first = statement_of(&signed[0]);

    // Step 2 names step 0, not step 1.
    let misnamed = signed_link(&key, 3, STREAM, 2, Some(first));
    let statements = [signed[0].clone(), signed[1].clone(), misnamed];
    assert_eq!(code(chain(&statements, None)), "CHAIN_PREVIOUS_MISMATCH");

    // A later step that names nothing.
    let unnamed = signed_link(&key, 2, STREAM, 1, None);
    assert_eq!(
        code(chain(&[signed[0].clone(), unnamed], None)),
        "CHAIN_PREVIOUS_MISMATCH"
    );

    // The anchor is another statement than the one step 1 follows.
    let head = chain(&signed[..1], None).expect("the first step").head;
    let another = Anchor {
        digest: statement_of(&signed[2]).digest(),
        ..head
    };
    assert_eq!(
        code(chain(&signed[1..], Some(&another))),
        "CHAIN_PREVIOUS_MISMATCH"
    );
}

#[test]
fn only_a_signed_statement_of_the_protocol_s_structure_is_authenticated() {
    let key = evidence_key();
    let trust = trust(&[&key]);
    let signed = &run(&key, 1)[0];
    assert!(authenticate(signed, &trust).is_ok());

    let extra = replaced(signed, &["statement", "note"], Some(string("x")));
    assert_eq!(code(authenticate(&extra, &trust)), "MALFORMED");
    let missing = replaced(signed, &["statement", "chain"], None);
    assert_eq!(code(authenticate(&missing, &trust)), "MALFORMED");
    assert_eq!(code(authenticate(&string("x"), &trust)), "MALFORMED");

    let altered = replaced(
        signed,
        &["statement", "chain", "stream"],
        Some(string("erp/invoices")),
    );
    assert_eq!(code(authenticate(&altered, &trust)), "SIGNATURE_INVALID");
    assert_eq!(code(authenticate(signed, &self::trust(&[]))), "UNKNOWN_KEY");
}

#[test]
fn admission_orders_evidence_by_identifier_and_checks_each_body() {
    let key = evidence_key();
    let trust = trust(&[&key]);
    let items = [
        Item::new(2, &key, "erp", body(2)),
        Item::new(1, &key, "erp", body(1)),
    ];
    let signed: Vec<Value> = items.iter().map(Item::signed).collect();
    let authentic = authentic(&signed, &trust);
    let evidence = [
        (authentic[0], &items[0].body),
        (authentic[1], &items[1].body),
    ];
    let (first, second) = (items[1].id.as_str(), items[0].id.as_str());

    let admitted = admit(TENANT, &[first, second], &evidence).expect("admitted");
    let ids: Vec<&str> = admitted.statements().iter().map(|s| s.id).collect();
    assert_eq!(ids, [first, second]);

    let refused = |tenant, claimed: &[&str], evidence: &[(Authenticated<'_>, &Value)]| {
        admit(tenant, claimed, evidence)
            .expect_err("a refusal")
            .code
    };
    let shared = EvidenceCode::Shared;
    assert_eq!(
        refused("tenant-other", &[first, second], &evidence),
        shared(RefusalCode::ForeignTenantEvidence)
    );
    assert_eq!(
        refused(TENANT, &[first], &evidence),
        shared(RefusalCode::EvidenceNotClaimed)
    );
    assert_eq!(
        refused(TENANT, &[first, second], &evidence[..1]),
        shared(RefusalCode::MissingEvidence)
    );
    let swapped = [
        (authentic[0], &items[1].body),
        (authentic[1], &items[0].body),
    ];
    assert_eq!(
        refused(TENANT, &[first, second], &swapped),
        shared(RefusalCode::PayloadMismatch)
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Any prefix of a run is a run, and a run with a statement taken out
    /// of its middle, or with two neighbours exchanged, is not.
    #[test]
    fn nothing_can_be_removed_or_moved_inside_a_run(
        (length, at) in (3u32..8).prop_flat_map(|n| (Just(n), 1..n - 1)),
    ) {
        let signed = run(&evidence_key(), length);
        let at = at as usize;

        prop_assert!(chain(&signed[..at], None).is_ok());

        let mut removed = signed.clone();
        removed.remove(at);
        prop_assert_eq!(code(chain(&removed, None)), "CHAIN_GAP");

        let mut exchanged = signed;
        exchanged.swap(at - 1, at);
        prop_assert_eq!(code(chain(&exchanged, None)), "CHAIN_REORDERED");
    }
}
