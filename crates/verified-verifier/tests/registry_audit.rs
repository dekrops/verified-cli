// SPDX-License-Identifier: Apache-2.0

//! Claim registration v1: the audit of a whole log.
//!
//! Everything here is synthetic and built in process. The protocol's own
//! vectors are run by `registration_conformance.rs`.

mod support;

use support::{Key, hash, list, object, string, wrapped};
use verified_canonical::Value;
use verified_verifier::registration::RegistrationTrust;
use verified_verifier::registration::audit::{ClaimState, DisputeState, audit};

const PROTOCOL: &str = "verified-claim-registration-v1";
const REGISTRY: &str = "registry.test";

fn claimant() -> Key {
    Key::new("test-claimant", 11, &[])
}

fn respondent() -> Key {
    Key::new("test-respondent", 12, &[])
}

fn registry_key() -> Key {
    Key::new("test-registry", 13, &[])
}

fn resolver() -> Key {
    Key::new("test-resolver", 15, &[])
}

fn trust() -> RegistrationTrust {
    let record = |key: &Key, holder: (&str, Value)| {
        object([
            ("algorithm", string(key.algorithm)),
            ("keyId", string(key.id)),
            holder,
            ("publicKey", string(key.public_key())),
            ("validFrom", wrapped(key.valid_from)),
        ])
    };
    let party = |key: &Key| record(key, ("party", wrapped(key.issuer.clone())));
    let keys = object([
        (
            "parties",
            list([party(&claimant()), party(&respondent()), party(&resolver())]),
        ),
        (
            "registries",
            list([record(&registry_key(), ("registry", string(REGISTRY)))]),
        ),
    ]);
    RegistrationTrust::from_value(&keys).expect("a usable trust configuration")
}

fn sha256(byte: char) -> Value {
    let hex: String = std::iter::repeat_n(byte, 64).collect();
    object([("algorithm", string("sha-256")), ("hex", string(hex))])
}

/// A time on 2026-03-`day`, at `minute` past ten.
fn at(day: u32, minute: u32) -> Value {
    wrapped(format!("2026-03-{day:02}T10:{minute:02}:00Z"))
}

fn case(name: &str, member: Option<(&str, Value)>) -> Value {
    let content = member.map_or_else(|| object([]), |(name, value)| object([(name, value)]));
    object([(name, content)])
}

fn signed(key: &Key, kind: &str, domain: &str, document: &Value) -> String {
    object([
        (kind, document.clone()),
        ("signature", key.sign(domain, document)),
    ])
    .to_canonical_string()
}

/// A log being written, with the documents it names. Entry `n` is recorded
/// on day 1 at minute `n` unless a day is given; the response window is one
/// day.
struct Log {
    agreement: Value,
    entries: Vec<Value>,
    texts: Vec<String>,
    documents: Vec<String>,
}

impl Log {
    /// A log under an agreement that allows `limit` open claims.
    fn new(limit: i64) -> Self {
        let agreement = object([
            ("claimant", wrapped(claimant().issuer)),
            (
                "contract",
                object([
                    ("digest", sha256('a')),
                    ("id", string("orders")),
                    ("version", string("1")),
                ]),
            ),
            ("id", wrapped(support::uuid(0x701))),
            ("openClaimLimit", Value::Integer(limit.into())),
            ("protocol", string(PROTOCOL)),
            ("registry", string(REGISTRY)),
            ("respondWithinSeconds", Value::Integer(86_400.into())),
            ("respondent", wrapped(respondent().issuer)),
            (
                "scope",
                object([
                    ("identity", list([string("order")])),
                    ("operation", string("fulfil")),
                    ("scope", string("orders")),
                ]),
            ),
            ("tenant", wrapped("tenant-test")),
            ("unitKey", sha256('b')),
            ("validFrom", wrapped("2026-02-01T00:00:00Z")),
            ("validUntil", Value::Null),
        ]);
        let domain = "verified:claim-agreement:v1\n";
        let text = object([
            ("agreement", agreement.clone()),
            (
                "signatures",
                object([
                    ("claimant", claimant().sign(domain, &agreement)),
                    ("respondent", respondent().sign(domain, &agreement)),
                ]),
            ),
        ])
        .to_canonical_string();
        Self {
            agreement,
            entries: Vec::new(),
            texts: Vec::new(),
            documents: vec![text],
        }
    }

    fn common(&self, claim: &Value) -> Vec<(&'static str, Value)> {
        let sequence = i64::try_from(self.entries.len()).expect("a short log");
        vec![
            ("claim", hash(claim)),
            ("previous", self.entries.last().map_or(Value::Null, hash)),
            ("protocol", string(PROTOCOL)),
            ("registry", string(REGISTRY)),
            ("sequence", Value::Integer(sequence.into())),
        ]
    }

    fn push(&mut self, kind: &str, domain: &str, members: Vec<(&'static str, Value)>) {
        let entry = Value::Object(
            members
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v))
                .collect(),
        );
        self.texts
            .push(signed(&registry_key(), kind, domain, &entry));
        self.entries.push(entry);
    }

    fn minute(&self) -> u32 {
        u32::try_from(self.entries.len()).expect("a short log")
    }

    /// An unsigned claim `n` for the unit `unit`, not yet registered.
    fn claim(&mut self, n: u32, unit: char) -> Value {
        let unit: String = std::iter::repeat_n(unit, 64).collect();
        let claim = object([
            ("agreement", hash(&self.agreement)),
            ("claimedAt", wrapped("2026-03-01T09:00:00Z")),
            ("id", wrapped(support::uuid(0x500 + n))),
            ("inputs", sha256('c')),
            ("protocol", string(PROTOCOL)),
            (
                "unit",
                object([("algorithm", string("hmac-sha-256")), ("hex", string(unit))]),
            ),
        ]);
        self.documents.push(signed(
            &claimant(),
            "claim",
            "verified:claim-commitment:v1\n",
            &claim,
        ));
        claim
    }

    /// Registers `claim` on day 1; the deadline is a day later.
    fn register(&mut self, claim: &Value) {
        let minute = self.minute();
        let mut members = self.common(claim);
        members.push(("receivedAt", at(1, minute)));
        members.push(("respondBy", at(2, minute)));
        self.push("receipt", "verified:claim-receipt:v1\n", members);
    }

    /// Registers a new claim `n` for `unit` and returns it.
    fn registered(&mut self, n: u32, unit: char) -> Value {
        let claim = self.claim(n, unit);
        self.register(&claim);
        claim
    }

    fn close(&mut self, claim: &Value, day: u32, closing: Value) {
        let minute = self.minute();
        let mut members = self.common(claim);
        members.push(("closing", closing));
        members.push(("recordedAt", at(day, minute)));
        self.push("closure", "verified:claim-closure:v1\n", members);
    }

    /// The respondent answers `claim` and the registry records it.
    fn respond(&mut self, claim: &Value, answer: Value) {
        let response = object([
            ("answer", answer),
            ("claim", hash(claim)),
            ("protocol", string(PROTOCOL)),
            ("respondedAt", at(1, 0)),
        ]);
        self.documents.push(signed(
            &respondent(),
            "response",
            "verified:claim-response:v1\n",
            &response,
        ));
        self.close(
            claim,
            1,
            case("Responded", Some(("response", hash(&response)))),
        );
    }

    fn refuse(&mut self, claim: &Value) {
        let reason = case("Other", Some(("text", string("not our order"))));
        self.respond(claim, case("Refused", Some(("reason", reason))));
    }

    /// The claimant withdraws `claim`, or replaces it by `by`.
    fn notice(&mut self, claim: &Value, by: Option<&Value>) {
        let action = by.map_or_else(
            || case("Withdraw", None),
            |by| case("Supersede", Some(("by", hash(by)))),
        );
        let notice = object([
            ("action", action),
            ("claim", hash(claim)),
            ("issuedAt", at(1, 0)),
            ("protocol", string(PROTOCOL)),
        ]);
        self.documents.push(signed(
            &claimant(),
            "notice",
            "verified:claim-notice:v1\n",
            &notice,
        ));
        let closing = if by.is_some() {
            "Superseded"
        } else {
            "Withdrawn"
        };
        self.close(claim, 1, case(closing, Some(("notice", hash(&notice)))));
    }

    fn dispute_record(&mut self, claim: &Value, step: Value) {
        let minute = self.minute();
        let mut members = self.common(claim);
        members.push(("recordedAt", at(1, minute)));
        members.push(("step", step));
        self.push(
            "disputeRecord",
            "verified:claim-dispute-record:v1\n",
            members,
        );
    }

    /// `by` opens a dispute of `claim` under terms that name the resolver.
    /// Returns the dispute.
    fn dispute(&mut self, claim: &Value, by: &Key) -> Value {
        let terms = object([
            ("agreement", hash(&self.agreement)),
            ("disputeWithinSeconds", Value::Integer(3_600.into())),
            ("protocol", string(PROTOCOL)),
            ("resolver", wrapped(resolver().issuer)),
        ]);
        let domain = "verified:claim-dispute-terms:v1\n";
        let terms_text = object([
            (
                "signatures",
                object([
                    ("claimant", claimant().sign(domain, &terms)),
                    ("respondent", respondent().sign(domain, &terms)),
                ]),
            ),
            ("terms", terms.clone()),
        ])
        .to_canonical_string();
        self.documents.push(terms_text);
        let dispute = object([
            ("by", wrapped(by.issuer.clone())),
            ("claim", hash(claim)),
            ("ground", case("RefusalUnfounded", None)),
            ("openedAt", at(1, 0)),
            ("protocol", string(PROTOCOL)),
            ("terms", hash(&terms)),
        ]);
        self.documents.push(signed(
            by,
            "dispute",
            "verified:claim-dispute:v1\n",
            &dispute,
        ));
        self.dispute_record(claim, case("Opened", Some(("dispute", hash(&dispute)))));
        dispute
    }

    /// The resolver decides `dispute` of `claim`.
    fn resolve(&mut self, claim: &Value, dispute: &Value, outcome: &str) {
        let resolution = object([
            ("dispute", hash(dispute)),
            ("outcome", case(outcome, None)),
            ("protocol", string(PROTOCOL)),
            ("resolvedAt", at(1, 0)),
        ]);
        let signature = resolver().sign("verified:claim-resolution:v1\n", &resolution);
        let text = object([
            ("resolution", resolution.clone()),
            (
                "signatures",
                object([("Resolver", object([("signature", signature)]))]),
            ),
        ])
        .to_canonical_string();
        self.documents.push(text);
        let step = case("Resolved", Some(("resolution", hash(&resolution))));
        self.dispute_record(claim, step);
    }

    fn audit(&self) -> Result<Vec<(ClaimState, Option<DisputeState>)>, &'static str> {
        let entries: Vec<&[u8]> = self.texts.iter().map(String::as_bytes).collect();
        let documents: Vec<&[u8]> = self.documents.iter().map(String::as_bytes).collect();
        audit(&entries, &documents, &trust())
            .map(|claims| claims.iter().map(|c| (c.state, c.dispute)).collect())
            .map_err(|refusal| refusal.code.as_str())
    }

    fn states(&self) -> Vec<ClaimState> {
        let claims = self.audit().expect("an audited log");
        claims.into_iter().map(|(state, _)| state).collect()
    }
}

fn evidence() -> Value {
    case("Evidence", Some(("package", sha256('e'))))
}

#[test]
fn an_audit_finds_each_claim_s_state() {
    let mut log = Log::new(10);
    let answered = log.registered(1, '1');
    let refused = log.registered(2, '2');
    let expired = log.registered(3, '3');
    let withdrawn = log.registered(4, '4');
    log.registered(5, '5');
    log.respond(&answered, evidence());
    log.refuse(&refused);
    log.notice(&withdrawn, None);
    // Recorded two days later, after the deadline.
    log.close(&expired, 3, case("Expired", None));
    assert_eq!(
        log.states(),
        [
            ClaimState::Answered,
            ClaimState::Refused,
            ClaimState::Expired,
            ClaimState::Withdrawn,
            ClaimState::Open,
        ]
    );
    // Documents the log does not name change nothing.
    log.claim(9, '9');
    log.documents.push("not JSON".to_owned());
    assert_eq!(log.states().len(), 5);
}

#[test]
fn a_claim_is_closed_once_in_time_and_only_if_registered() {
    let mut early = Log::new(10);
    let claim = early.registered(1, '1');
    early.close(&claim, 1, case("Expired", None));
    assert_eq!(early.audit(), Err("EXPIRED_EARLY"));

    let mut twice = Log::new(10);
    let claim = twice.registered(1, '1');
    twice.refuse(&claim);
    twice.close(&claim, 3, case("Expired", None));
    assert_eq!(twice.audit(), Err("ALREADY_CLOSED"));

    let mut unknown = Log::new(10);
    unknown.registered(1, '1');
    let never = unknown.claim(2, '2');
    unknown.close(&never, 3, case("Expired", None));
    assert_eq!(unknown.audit(), Err("CLOSURE_WITHOUT_REGISTRATION"));

    let mut late = Log::new(10);
    let claim = late.registered(1, '1');
    let response = object([
        ("answer", evidence()),
        ("claim", hash(&claim)),
        ("protocol", string(PROTOCOL)),
        ("respondedAt", at(1, 0)),
    ]);
    late.documents.push(signed(
        &respondent(),
        "response",
        "verified:claim-response:v1\n",
        &response,
    ));
    late.close(
        &claim,
        3,
        case("Responded", Some(("response", hash(&response)))),
    );
    assert_eq!(late.audit(), Err("LATE_RESPONSE"));

    // A response the log names must be supplied, and in canonical text.
    let mut missing = Log::new(10);
    let claim = missing.registered(1, '1');
    missing.respond(&claim, evidence());
    let response = missing.documents.pop().expect("the response");
    assert_eq!(missing.audit(), Err("MISSING_RESPONSE"));
    missing.documents.push(format!("{response} "));
    assert_eq!(missing.audit(), Err("MALFORMED"));
}

#[test]
fn a_unit_is_held_by_one_claim_at_a_time() {
    let mut open = Log::new(10);
    open.registered(1, '1');
    open.registered(2, '1');
    assert_eq!(open.audit(), Err("UNIT_HELD"));

    let mut answered = Log::new(10);
    let first = answered.registered(1, '1');
    answered.respond(&first, evidence());
    answered.registered(2, '1');
    assert_eq!(answered.audit(), Err("UNIT_HELD"));

    let mut released = Log::new(10);
    let first = released.registered(1, '1');
    released.refuse(&first);
    released.registered(2, '1');
    assert_eq!(released.states(), [ClaimState::Refused, ClaimState::Open]);
}

#[test]
fn the_limit_counts_open_claims() {
    let mut log = Log::new(2);
    let first = log.registered(1, '1');
    log.registered(2, '2');
    let mut over = Log::new(2);
    over.registered(1, '1');
    over.registered(2, '2');
    over.registered(3, '3');
    assert_eq!(over.audit(), Err("LIMIT_EXCEEDED"));

    log.refuse(&first);
    log.registered(3, '3');
    assert_eq!(log.states().len(), 3);
}

#[test]
fn a_replaced_claim_is_followed_at_once_by_its_replacement() {
    let mut log = Log::new(10);
    let first = log.registered(1, '1');
    let other = log.registered(2, '2');
    let replacement = log.claim(3, '1');
    log.notice(&first, Some(&replacement));

    let mut ends = clone(&log);
    assert_eq!(ends.audit(), Err("SUPERSESSION_INCOMPLETE"));
    ends.refuse(&other);
    assert_eq!(ends.audit(), Err("SUPERSESSION_INCOMPLETE"));

    // The replacement takes the unit the replaced claim released.
    log.register(&replacement);
    assert_eq!(
        log.states(),
        [ClaimState::Superseded, ClaimState::Open, ClaimState::Open]
    );
}

fn clone(log: &Log) -> Log {
    Log {
        agreement: log.agreement.clone(),
        entries: log.entries.clone(),
        texts: log.texts.clone(),
        documents: log.documents.clone(),
    }
}

#[test]
fn a_dispute_is_recorded_beside_the_claim_and_holds_its_unit() {
    let mut log = Log::new(10);
    let claim = log.registered(1, '1');
    log.refuse(&claim);
    let dispute = log.dispute(&claim, &claimant());
    assert_eq!(
        log.audit(),
        Ok(vec![(ClaimState::Refused, Some(DisputeState::Open))])
    );

    // While the dispute is open, the unit is held and the claim stays.
    let mut taken = clone(&log);
    taken.registered(2, '1');
    assert_eq!(taken.audit(), Err("UNIT_HELD"));
    let mut withdrawn = clone(&log);
    withdrawn.notice(&claim, None);
    assert_eq!(withdrawn.audit(), Err("ALREADY_CLOSED"));

    // Upheld: the refusal was unfounded, and the claim keeps its unit.
    let mut upheld = clone(&log);
    upheld.resolve(&claim, &dispute, "Upheld");
    assert_eq!(
        upheld.audit(),
        Ok(vec![(ClaimState::Refused, Some(DisputeState::Upheld))])
    );
    upheld.registered(2, '1');
    assert_eq!(upheld.audit(), Err("UNIT_HELD"));

    // Rejected: the refusal stands, and the unit is free again.
    log.resolve(&claim, &dispute, "Rejected");
    log.registered(2, '1');
    assert_eq!(
        log.audit(),
        Ok(vec![
            (ClaimState::Refused, Some(DisputeState::Rejected)),
            (ClaimState::Open, None),
        ])
    );
    // A claim is disputed once.
    log.dispute(&claim, &claimant());
    assert_eq!(log.audit(), Err("ALREADY_DISPUTED"));
}

#[test]
fn only_some_claims_can_be_disputed_and_only_by_some_parties() {
    let mut open = Log::new(10);
    let claim = open.registered(1, '1');
    open.dispute(&claim, &claimant());
    assert_eq!(open.audit(), Err("NOT_DISPUTABLE"));

    // Only the claimant disputes a refusal.
    let mut refused = Log::new(10);
    let claim = refused.registered(1, '1');
    refused.refuse(&claim);
    refused.dispute(&claim, &respondent());
    assert_eq!(refused.audit(), Err("PARTY_MISMATCH"));

    // Either party disputes evidence.
    let mut answered = Log::new(10);
    let claim = answered.registered(1, '1');
    answered.respond(&claim, evidence());
    let dispute = answered.dispute(&claim, &respondent());
    assert_eq!(
        answered.audit(),
        Ok(vec![(ClaimState::Answered, Some(DisputeState::Open))])
    );
    // An answered claim with an open dispute cannot be withdrawn.
    let mut withdrawn = clone(&answered);
    withdrawn.notice(&claim, None);
    assert_eq!(withdrawn.audit(), Err("DISPUTE_OPEN"));
    // A resolution without an open dispute.
    answered.resolve(&claim, &dispute, "Rejected");
    answered.resolve(&claim, &dispute, "Rejected");
    assert_eq!(answered.audit(), Err("NO_OPEN_DISPUTE"));
}

#[test]
fn an_audit_needs_the_log_from_its_start() {
    let mut log = Log::new(10);
    log.registered(1, '1');
    log.registered(2, '2');
    log.texts.remove(0);
    assert_eq!(log.audit(), Err("GENESIS_INVALID"));

    let mut missing = Log::new(10);
    missing.registered(1, '1');
    let claim = missing.documents.pop().expect("the claim");
    assert_eq!(missing.audit(), Err("MISSING_CLAIM"));
    missing.documents = vec![claim];
    assert_eq!(missing.audit(), Err("MISSING_AGREEMENT"));
}
