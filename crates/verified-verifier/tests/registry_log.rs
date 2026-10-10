// SPDX-License-Identifier: Apache-2.0

//! Claim registration v1: a run of a registry's log, and an entry someone
//! holds, checked against it.
//!
//! Everything here is synthetic and built in process. The protocol's own
//! vectors are run by `registration_conformance.rs`.

mod support;

use support::{Key, hash, list, object, replaced, string, wrapped};
use verified_canonical::Value;
use verified_verifier::registration::RegistrationTrust;
use verified_verifier::registration::log::{Inclusion, LogCheck, check_log};

const PROTOCOL: &str = "verified-claim-registration-v1";
const REGISTRY: &str = "registry.test";
const OTHER_REGISTRY: &str = "registry.other.test";
const RECEIPT_DOMAIN: &str = "verified:claim-receipt:v1\n";
const CLOSURE_DOMAIN: &str = "verified:claim-closure:v1\n";
const DISPUTE_RECORD_DOMAIN: &str = "verified:claim-dispute-record:v1\n";

fn registry_key() -> Key {
    Key::new("test-registry", 13, &[])
}

fn other_registry_key() -> Key {
    Key::new("test-other-registry", 14, &[])
}

fn trust() -> RegistrationTrust {
    let record = |key: &Key, registry: &str| {
        object([
            ("algorithm", string(key.algorithm)),
            ("keyId", string(key.id)),
            ("publicKey", string(key.public_key())),
            ("registry", string(registry)),
            ("validFrom", wrapped(key.valid_from)),
        ])
    };
    let keys = object([
        ("parties", list([])),
        (
            "registries",
            list([
                record(&registry_key(), REGISTRY),
                record(&other_registry_key(), OTHER_REGISTRY),
            ]),
        ),
    ]);
    RegistrationTrust::from_value(&keys).expect("a usable trust configuration")
}

fn sha256(byte: char) -> Value {
    let hex: String = std::iter::repeat_n(byte, 64).collect();
    object([("algorithm", string("sha-256")), ("hex", string(hex))])
}

/// A minute of 2026-03-01, as an instant.
fn minute(n: u32) -> Value {
    wrapped(format!("2026-03-01T10:{n:02}:00Z"))
}

/// The members every kind of entry has, at position `sequence` after
/// `previous`.
fn common(sequence: i64, previous: Option<&Value>, claim: char) -> Vec<(&'static str, Value)> {
    vec![
        ("claim", sha256(claim)),
        ("previous", previous.map_or(Value::Null, hash)),
        ("protocol", string(PROTOCOL)),
        ("registry", string(REGISTRY)),
        ("sequence", Value::Integer(sequence.into())),
    ]
}

fn entry_of(mut members: Vec<(&'static str, Value)>, more: [(&'static str, Value); 2]) -> Value {
    members.extend(more);
    Value::Object(
        members
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect(),
    )
}

/// An unsigned receipt for claim `claim`, received at minute `sequence`.
fn receipt(sequence: i64, previous: Option<&Value>, claim: char) -> Value {
    let at = u32::try_from(sequence).expect("a small position");
    entry_of(
        common(sequence, previous, claim),
        [("receivedAt", minute(at)), ("respondBy", minute(at + 30))],
    )
}

fn closure(sequence: i64, previous: &Value, claim: char, closing: Value) -> Value {
    let at = u32::try_from(sequence).expect("a small position");
    entry_of(
        common(sequence, Some(previous), claim),
        [("closing", closing), ("recordedAt", minute(at))],
    )
}

fn dispute_record(sequence: i64, previous: &Value, claim: char, step: Value) -> Value {
    let at = u32::try_from(sequence).expect("a small position");
    entry_of(
        common(sequence, Some(previous), claim),
        [("recordedAt", minute(at)), ("step", step)],
    )
}

fn case(name: &str, member: Option<(&str, Value)>) -> Value {
    let content = member.map_or_else(|| object([]), |(name, value)| object([(name, value)]));
    object([(name, content)])
}

/// The signed text of an entry of `kind`, by `key`.
fn signed_by(key: &Key, kind: &str, domain: &str, entry: &Value) -> String {
    object([
        (kind, entry.clone()),
        ("signature", key.sign(domain, entry)),
    ])
    .to_canonical_string()
}

fn signed_receipt(entry: &Value) -> String {
    signed_by(&registry_key(), "receipt", RECEIPT_DOMAIN, entry)
}

/// `count` unsigned receipts for different claims: entries 0, 1, … of one
/// log, each naming the one before it.
fn receipts(count: u32) -> Vec<Value> {
    let mut entries: Vec<Value> = Vec::new();
    for n in 0..count {
        let claim = char::from_digit(n, 16).expect("fewer than 16 entries");
        let entry = receipt(i64::from(n), entries.last(), claim);
        entries.push(entry);
    }
    entries
}

fn check(
    entries: &[String],
    anchor: Option<&str>,
    held: Option<&str>,
) -> Result<LogCheck, &'static str> {
    let entries: Vec<&[u8]> = entries.iter().map(String::as_bytes).collect();
    check_log(
        &entries,
        anchor.map(str::as_bytes),
        held.map(str::as_bytes),
        &trust(),
    )
    .map_err(|refusal| refusal.code.as_str())
}

fn code(entries: &[String], anchor: Option<&str>) -> &'static str {
    check(entries, anchor, None).expect_err("a refusal")
}

fn texts(entries: &[Value]) -> Vec<String> {
    entries.iter().map(signed_receipt).collect()
}

#[test]
fn a_run_from_the_start_and_a_run_from_an_anchor_end_at_the_same_head() {
    let entries = receipts(4);
    let log = texts(&entries);
    let whole = check(&log, None, None).expect("a segment").segment;
    assert_eq!(whole.registry, REGISTRY);
    assert_eq!((whole.first, whole.last), (0, 3));
    assert_eq!(whole.head, entries[3].digest());

    let rest = check(&log[2..], Some(&log[1]), None)
        .expect("a segment")
        .segment;
    assert_eq!((rest.first, rest.last), (2, 3));
    assert_eq!(rest.head, whole.head);

    // Nothing shows that the end was left off.
    let shorter = check(&log[..2], None, None).expect("a segment").segment;
    assert_eq!(shorter.last, 1);
}

#[test]
fn a_log_holds_receipts_closures_and_dispute_records() {
    let key = registry_key();
    let received = receipt(0, None, 'a');
    let expired = closure(1, &received, 'a', case("Expired", None));
    let another = receipt(2, Some(&expired), 'b');
    let responded = closure(
        3,
        &another,
        'b',
        case("Responded", Some(("response", sha256('1')))),
    );
    let opened = dispute_record(
        4,
        &responded,
        'b',
        case("Opened", Some(("dispute", sha256('2')))),
    );
    let log = [
        signed_receipt(&received),
        signed_by(&key, "closure", CLOSURE_DOMAIN, &expired),
        signed_receipt(&another),
        signed_by(&key, "closure", CLOSURE_DOMAIN, &responded),
        signed_by(&key, "disputeRecord", DISPUTE_RECORD_DOMAIN, &opened),
    ];
    let segment = check(&log, None, None).expect("a segment").segment;
    assert_eq!((segment.last, segment.head), (4, opened.digest()));

    let with = |at: usize, text: String| {
        let mut log = log.clone();
        log[at] = text;
        code(&log, None)
    };
    // A signature for one kind of entry is not one for another.
    let under_receipt_domain = signed_by(&key, "closure", RECEIPT_DOMAIN, &expired);
    assert_eq!(with(1, under_receipt_domain), "SIGNATURE_INVALID");
    // Cases and their members are closed.
    for closing in [
        case("Reopened", None),
        case("Expired", Some(("response", sha256('1')))),
        case("Responded", None),
        case("Responded", Some(("notice", sha256('1')))),
    ] {
        let entry = closure(1, &received, 'a', closing);
        assert_eq!(
            with(1, signed_by(&key, "closure", CLOSURE_DOMAIN, &entry)),
            "MALFORMED"
        );
    }
    // What a closure rests on is a commitment like the others.
    let not_a_digest = object([("algorithm", string("sha-256")), ("hex", string("abc"))]);
    let entry = closure(
        1,
        &received,
        'a',
        case("Withdrawn", Some(("notice", not_a_digest))),
    );
    assert_eq!(
        with(1, signed_by(&key, "closure", CLOSURE_DOMAIN, &entry)),
        "MALFORMED_COMMITMENT"
    );
}

#[test]
fn each_entry_is_checked_on_its_own_first() {
    let entries = receipts(3);
    let log = texts(&entries);
    assert_eq!(code(&[], None), "MALFORMED");

    let with = |at: usize, text: String| {
        let mut log = log.clone();
        log[at] = text;
        code(&log, None)
    };
    assert_eq!(with(1, format!("{} ", log[1])), "MALFORMED");
    assert_eq!(with(1, "{}".to_owned()), "MALFORMED");
    let change =
        |path: &[&str], new: Value| signed_receipt(&replaced(&entries[1], path, Some(new)));
    assert_eq!(
        with(1, change(&["protocol"], string("other"))),
        "UNSUPPORTED_PROTOCOL"
    );
    assert_eq!(with(1, change(&["previous"], Value::Null)), "CHAIN_INVALID");
    assert_eq!(
        with(1, change(&["sequence"], Value::Integer((-1).into()))),
        "CHAIN_INVALID"
    );
    // The entry names one registry and is signed by another's key.
    let by_another = signed_by(
        &other_registry_key(),
        "receipt",
        RECEIPT_DOMAIN,
        &entries[1],
    );
    assert_eq!(with(1, by_another), "REGISTRY_MISMATCH");
    let stranger = Key::new("test-stranger", 21, &[]);
    let by_a_stranger = signed_by(&stranger, "receipt", RECEIPT_DOMAIN, &entries[1]);
    assert_eq!(with(1, by_a_stranger), "UNKNOWN_KEY");
    // Before the key was valid.
    let early = replaced(
        &entries[1],
        &["receivedAt"],
        Some(wrapped("2025-12-31T23:59:59Z")),
    );
    assert_eq!(with(1, signed_receipt(&early)), "KEY_NOT_VALID");
    // An anchor is checked like any entry.
    assert_eq!(code(&log[1..], Some(&format!("{} ", log[0]))), "MALFORMED");
    // The first entry at fault is the one reported.
    let mut both = log.clone();
    both[0] = change(&["protocol"], string("other"));
    both[2] = "{}".to_owned();
    assert_eq!(code(&both, None), "UNSUPPORTED_PROTOCOL");
}

#[test]
fn a_segment_is_one_registry_s_consecutive_entries_in_order() {
    let entries = receipts(4);
    let log = texts(&entries);
    let pick = |positions: &[usize]| -> Vec<String> {
        positions.iter().map(|i| log[*i].clone()).collect()
    };

    let elsewhere = replaced(&entries[1], &["registry"], Some(string(OTHER_REGISTRY)));
    let elsewhere = signed_by(&other_registry_key(), "receipt", RECEIPT_DOMAIN, &elsewhere);
    assert_eq!(
        code(&[log[0].clone(), elsewhere.clone()], None),
        "MIXED_REGISTRIES"
    );
    assert_eq!(code(&log[2..], Some(&elsewhere)), "MIXED_REGISTRIES");

    let fork = signed_receipt(&receipt(1, Some(&entries[0]), 'f'));
    assert_eq!(
        code(&[log[0].clone(), log[1].clone(), fork], None),
        "EQUIVOCATION"
    );
    assert_eq!(code(&pick(&[0, 2, 1]), None), "REORDERED");
    assert_eq!(code(&pick(&[0, 1, 1]), None), "REORDERED");
    assert_eq!(code(&pick(&[1, 2]), None), "GENESIS_INVALID");
    assert_eq!(code(&pick(&[0, 2]), None), "GAP");
    assert_eq!(code(&pick(&[3]), Some(&log[1])), "GAP");

    // Entry 2 names entry 0, not entry 1.
    let misnamed = signed_receipt(&receipt(2, Some(&entries[0]), '2'));
    assert_eq!(
        code(&[log[0].clone(), log[1].clone(), misnamed], None),
        "PREVIOUS_MISMATCH"
    );
    // The anchor is another entry 1 than the one entry 2 follows.
    let another_first = signed_receipt(&receipt(1, Some(&entries[0]), 'f'));
    assert_eq!(
        code(&pick(&[2, 3]), Some(&another_first)),
        "PREVIOUS_MISMATCH"
    );
}

#[test]
fn time_does_not_run_backwards_and_a_claim_is_registered_once() {
    let entries = receipts(2);
    let log = texts(&entries);

    let earlier = replaced(
        &receipt(2, Some(&entries[1]), '2'),
        &["receivedAt"],
        Some(minute(0)),
    );
    let mut reversed = log.clone();
    reversed.push(signed_receipt(&earlier));
    assert_eq!(code(&reversed, None), "TIME_REVERSED");
    assert_eq!(code(&reversed[2..], Some(&log[1])), "TIME_REVERSED");
    // The same minute is not earlier.
    let same = replaced(&earlier, &["receivedAt"], Some(minute(1)));
    assert!(
        check(
            &[log[0].clone(), log[1].clone(), signed_receipt(&same)],
            None,
            None
        )
        .is_ok()
    );

    // Claim 0 again, at position 2.
    let again = signed_receipt(&receipt(2, Some(&entries[1]), '0'));
    let mut twice = log.clone();
    twice.push(again.clone());
    assert_eq!(code(&twice, None), "DUPLICATE_CLAIM");
    // Also when the first registration is the anchor.
    let third = receipt(1, Some(&entries[0]), '0');
    assert_eq!(
        code(&[signed_receipt(&third)], Some(&log[0])),
        "DUPLICATE_CLAIM"
    );
    // A closure names its claim again; that is not a second registration.
    let closed = closure(2, &entries[1], '0', case("Expired", None));
    let mut closing = log.clone();
    closing.push(signed_by(
        &registry_key(),
        "closure",
        CLOSURE_DOMAIN,
        &closed,
    ));
    assert!(check(&closing, None, None).is_ok());
}

#[test]
fn a_held_entry_is_included_not_covered_or_contradicted() {
    let entries = receipts(4);
    let log = texts(&entries);
    let inclusion = |entries: &[String], anchor: Option<&str>, held: &str| {
        check(entries, anchor, Some(held))
            .expect("a checked log")
            .inclusion
            .expect("an inclusion outcome")
    };

    assert_eq!(inclusion(&log, None, &log[2]), Inclusion::Included);
    assert_eq!(inclusion(&log[..2], None, &log[3]), Inclusion::NotCovered);
    // The anchor is part of what the segment covers; what came before is not.
    assert_eq!(
        inclusion(&log[2..], Some(&log[1]), &log[1]),
        Inclusion::Included
    );
    assert_eq!(
        inclusion(&log[2..], Some(&log[1]), &log[0]),
        Inclusion::NotCovered
    );

    // A held entry is checked like any other, and must be of this registry.
    let stranger = Key::new("test-stranger", 21, &[]);
    let forged = signed_by(&stranger, "receipt", RECEIPT_DOMAIN, &entries[2]);
    assert_eq!(check(&log, None, Some(&forged)), Err("UNKNOWN_KEY"));
    let elsewhere = replaced(&entries[2], &["registry"], Some(string(OTHER_REGISTRY)));
    let elsewhere = signed_by(&other_registry_key(), "receipt", RECEIPT_DOMAIN, &elsewhere);
    assert_eq!(
        check(&log, None, Some(&elsewhere)),
        Err("REGISTRY_MISMATCH")
    );
    // A segment that does not verify says nothing about a held entry.
    assert_eq!(
        check(&log[1..], None, Some(&log[2])),
        Err("GENESIS_INVALID")
    );
}

#[test]
fn a_registry_that_drops_an_entry_is_contradicted_by_a_later_receipt() {
    let honest = receipts(4);
    let held = signed_receipt(&honest[2]);

    // The registry removes entry 1 and renumbers what came after it.
    let mut rewritten = vec![honest[0].clone()];
    for (position, claim) in [(1, '2'), (2, '3')] {
        let entry = receipt(position, rewritten.last(), claim);
        rewritten.push(entry);
    }
    let log = texts(&rewritten);

    // The rewritten log verifies on its own.
    let checked = check(&log, None, Some(&held)).expect("a segment");
    assert_eq!(checked.segment.last, 2);
    // The claimant's receipt for position 2 shows the rewrite.
    assert_eq!(
        checked.inclusion,
        Some(Inclusion::Equivocation {
            held: honest[2].digest(),
            logged: rewritten[2].digest(),
        })
    );
}
