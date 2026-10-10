// SPDX-License-Identifier: Apache-2.0

//! Claim registration v1: verifying a registration.
//!
//! Everything here is synthetic and built in process. The protocol's own
//! vectors are run by `registration_conformance.rs`.

mod support;

use support::{Key, hash, list, object, replaced, string, wrapped};
use verified_canonical::Value;
use verified_protocol::registration::RegistrationCode;
use verified_verifier::registration::{RegistrationTrust, verify_registration};

const PROTOCOL: &str = "verified-claim-registration-v1";
const REGISTRY: &str = "registry.test";
const AGREEMENT_DOMAIN: &str = "verified:claim-agreement:v1\n";
const CLAIM_DOMAIN: &str = "verified:claim-commitment:v1\n";
const RECEIPT_DOMAIN: &str = "verified:claim-receipt:v1\n";

fn claimant() -> Key {
    Key::new("test-claimant", 11, &[])
}

fn respondent() -> Key {
    Key::new("test-respondent", 12, &[])
}

fn registry_key() -> Key {
    Key::new("test-registry", 13, &[])
}

fn other_registry_key() -> Key {
    Key::new("test-other-registry", 14, &[])
}

fn integer(n: i64) -> Value {
    Value::Integer(n.into())
}

fn hex(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn sha256(byte: char) -> Value {
    object([("algorithm", string("sha-256")), ("hex", string(hex(byte)))])
}

fn key_record(key: &Key, holder: (&str, Value)) -> Value {
    let time = |t: Option<&str>| t.map_or(Value::Null, wrapped);
    object([
        ("algorithm", string(key.algorithm)),
        ("keyId", string(key.id)),
        holder,
        ("publicKey", string(key.public_key())),
        ("revokedAt", time(key.revoked_at)),
        ("validFrom", wrapped(key.valid_from)),
        ("validUntil", time(key.valid_until)),
    ])
}

fn trust_of(parties: &[&Key], registries: &[(&Key, &str)]) -> RegistrationTrust {
    let keys = object([
        (
            "parties",
            list(
                parties
                    .iter()
                    .map(|k| key_record(k, ("party", wrapped(k.issuer.clone())))),
            ),
        ),
        (
            "registries",
            list(
                registries
                    .iter()
                    .map(|(k, name)| key_record(k, ("registry", string(*name)))),
            ),
        ),
    ]);
    RegistrationTrust::from_value(&keys).expect("a usable trust configuration")
}

fn trust() -> RegistrationTrust {
    trust_of(
        &[&claimant(), &respondent()],
        &[
            (&registry_key(), REGISTRY),
            (&other_registry_key(), "registry.other.test"),
        ],
    )
}

/// Who signs what.
#[derive(Clone)]
struct Signers {
    agreement_claimant: Key,
    agreement_respondent: Key,
    claim: Key,
    receipt: Key,
}

/// The three unsigned objects of a registration. Change one and call
/// [`Parts::relinked`], and the objects after it name it again, so that a
/// test isolates exactly one fault.
#[derive(Clone)]
struct Parts {
    agreement: Value,
    claim: Value,
    receipt: Value,
    signers: Signers,
}

fn base() -> Parts {
    let agreement = object([
        ("claimant", wrapped(claimant().issuer)),
        (
            "contract",
            object([
                ("digest", sha256('a')),
                ("id", string("order-fulfilment")),
                ("version", string("1.0.0")),
            ]),
        ),
        ("id", wrapped(support::uuid(0x701))),
        ("openClaimLimit", integer(5)),
        ("protocol", string(PROTOCOL)),
        ("registry", string(REGISTRY)),
        ("respondWithinSeconds", integer(3_600)),
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
        ("validUntil", wrapped("2027-02-01T00:00:00Z")),
    ]);
    let claim = object([
        ("agreement", Value::Null),
        ("claimedAt", wrapped("2026-03-01T10:00:00Z")),
        ("id", wrapped(support::uuid(0x501))),
        ("inputs", sha256('c')),
        ("protocol", string(PROTOCOL)),
        (
            "unit",
            object([
                ("algorithm", string("hmac-sha-256")),
                ("hex", string(hex('d'))),
            ]),
        ),
    ]);
    let receipt = object([
        ("claim", Value::Null),
        ("previous", Value::Null),
        ("protocol", string(PROTOCOL)),
        ("receivedAt", wrapped("2026-03-01T10:00:05Z")),
        ("registry", string(REGISTRY)),
        ("respondBy", wrapped("2026-03-01T11:00:05Z")),
        ("sequence", integer(0)),
    ]);
    Parts {
        agreement,
        claim,
        receipt,
        signers: Signers {
            agreement_claimant: claimant(),
            agreement_respondent: respondent(),
            claim: claimant(),
            receipt: registry_key(),
        },
    }
    .relinked()
}

impl Parts {
    /// The claim names this agreement and the receipt names this claim.
    fn relinked(mut self) -> Self {
        self.claim = replaced(&self.claim, &["agreement"], Some(hash(&self.agreement)));
        self.receipt = replaced(&self.receipt, &["claim"], Some(hash(&self.claim)));
        self
    }

    fn agreement(mut self, path: &[&str], new: Value) -> Self {
        self.agreement = replaced(&self.agreement, path, Some(new));
        self.relinked()
    }

    fn claim(mut self, path: &[&str], new: Value) -> Self {
        self.claim = replaced(&self.claim, path, Some(new));
        self.relinked()
    }

    fn receipt(mut self, path: &[&str], new: Value) -> Self {
        self.receipt = replaced(&self.receipt, path, Some(new));
        self
    }

    fn signed_by(mut self, change: impl FnOnce(&mut Signers)) -> Self {
        change(&mut self.signers);
        self
    }

    /// The three signed objects.
    fn signed(&self) -> [Value; 3] {
        let signers = &self.signers;
        [
            object([
                ("agreement", self.agreement.clone()),
                (
                    "signatures",
                    object([
                        (
                            "claimant",
                            signers
                                .agreement_claimant
                                .sign(AGREEMENT_DOMAIN, &self.agreement),
                        ),
                        (
                            "respondent",
                            signers
                                .agreement_respondent
                                .sign(AGREEMENT_DOMAIN, &self.agreement),
                        ),
                    ]),
                ),
            ]),
            object([
                ("claim", self.claim.clone()),
                ("signature", signers.claim.sign(CLAIM_DOMAIN, &self.claim)),
            ]),
            object([
                ("receipt", self.receipt.clone()),
                (
                    "signature",
                    signers.receipt.sign(RECEIPT_DOMAIN, &self.receipt),
                ),
            ]),
        ]
    }
}

fn verify_texts(texts: [&str; 3], trust: &RegistrationTrust) -> Result<(), RegistrationCode> {
    verify_registration(
        texts[0].as_bytes(),
        texts[1].as_bytes(),
        texts[2].as_bytes(),
        trust,
    )
    .map(|_| ())
    .map_err(|refusal| refusal.code)
}

fn verify_signed(signed: &[Value; 3], trust: &RegistrationTrust) -> Result<(), RegistrationCode> {
    let texts = signed.each_ref().map(Value::to_canonical_string);
    verify_texts(texts.each_ref().map(String::as_str), trust)
}

fn code(parts: &Parts) -> &'static str {
    verify_signed(&parts.signed(), &trust())
        .expect_err("a refusal")
        .as_str()
}

#[test]
fn a_registration_states_its_facts() {
    let parts = base();
    let [agreement, claim, receipt] = parts.signed().map(|v| v.to_canonical_string());
    let registration = verify_registration(
        agreement.as_bytes(),
        claim.as_bytes(),
        receipt.as_bytes(),
        &trust(),
    )
    .expect("a registration");
    assert_eq!(registration.agreement, parts.agreement.digest());
    assert_eq!(registration.claim, parts.claim.digest());
    assert_eq!(registration.receipt, parts.receipt.digest());
    assert_eq!(registration.claim_id, support::uuid(0x501));
    assert_eq!(registration.claimant, claimant().issuer);
    assert_eq!(registration.respondent, respondent().issuer);
    assert_eq!(registration.registry, REGISTRY);
    assert_eq!(registration.sequence, 0);
    assert_eq!(registration.received_at, "2026-03-01T10:00:05Z");
    assert_eq!(registration.respond_by, "2026-03-01T11:00:05Z");
}

#[test]
fn a_later_entry_of_the_log_names_its_predecessor() {
    let later = base()
        .receipt(&["sequence"], integer(7))
        .receipt(&["previous"], sha256('e'));
    assert_eq!(verify_signed(&later.signed(), &trust()), Ok(()));
}

#[test]
fn an_agreement_without_an_end_stays_in_force() {
    let open = base().agreement(&["validUntil"], Value::Null);
    assert_eq!(verify_signed(&open.signed(), &trust()), Ok(()));
}

#[test]
fn text_that_is_not_canonical_or_not_of_the_structure_is_malformed() {
    let trust = trust();
    let signed = base().signed();
    let texts = signed.each_ref().map(Value::to_canonical_string);
    let malformed = |at: usize, text: String| {
        let mut texts = texts.clone();
        texts[at] = text;
        assert_eq!(
            verify_texts(texts.each_ref().map(String::as_str), &trust),
            Err(RegistrationCode::Malformed),
            "{}",
            texts[at]
        );
    };
    for at in 0..3 {
        malformed(at, format!("{} ", texts[at]));
        malformed(at, format!("{}\n", texts[at]));
        malformed(at, texts[at].replacen(':', ": ", 1));
        malformed(at, "[]".to_owned());
        malformed(at, String::new());
        malformed(
            at,
            replaced(&signed[at], &["note"], Some(string("x"))).to_canonical_string(),
        );
    }
    // An integer beyond what every implementation represents exactly.
    let too_large = base().agreement(&["respondWithinSeconds"], integer(1 << 53));
    assert_eq!(code(&too_large), "MALFORMED");
    let largest = base().agreement(&["openClaimLimit"], integer((1 << 53) - 1));
    assert_eq!(verify_signed(&largest.signed(), &trust), Ok(()));
    // Spellings with another canonical form.
    let upper = base().claim(&["id"], wrapped(support::uuid(0xabc).to_uppercase()));
    assert_eq!(code(&upper), "MALFORMED");
    let zone = base().receipt(&["receivedAt"], wrapped("2026-03-01T10:00:05+00:00"));
    assert_eq!(code(&zone), "MALFORMED");
    let year = base().receipt(&["respondBy"], wrapped("+10000-01-01T00:00:00Z"));
    assert_eq!(code(&year), "MALFORMED");
    let unsigned = base().signed().map(|v| replaced(&v, &["signatures"], None));
    assert_eq!(
        verify_signed(&unsigned, &trust),
        Err(RegistrationCode::Malformed)
    );
}

#[test]
fn every_object_must_be_of_this_protocol() {
    let other = string("verified-claim-registration-v2");
    assert_eq!(
        code(&base().agreement(&["protocol"], other.clone())),
        "UNSUPPORTED_PROTOCOL"
    );
    assert_eq!(
        code(&base().claim(&["protocol"], other.clone())),
        "UNSUPPORTED_PROTOCOL"
    );
    assert_eq!(
        code(&base().receipt(&["protocol"], other)),
        "UNSUPPORTED_PROTOCOL"
    );
}

#[test]
fn commitments_are_digests_and_the_unit_is_a_nullifier() {
    let short = object([("algorithm", string("sha-256")), ("hex", string("abc"))]);
    let upper = object([("algorithm", string("sha-256")), ("hex", string(hex('A')))]);
    let other = object([("algorithm", string("sha-512")), ("hex", string(hex('a')))]);
    for bad in [short, upper, other] {
        for parts in [
            base().agreement(&["contract", "digest"], bad.clone()),
            base().agreement(&["unitKey"], bad.clone()),
            base().claim(&["inputs"], bad.clone()),
            base().receipt(&["previous"], bad.clone()),
            base().receipt(&["claim"], bad.clone()),
        ] {
            assert_eq!(code(&parts), "MALFORMED_COMMITMENT");
        }
    }
    // A unit that is a plain hash says nothing was keyed.
    assert_eq!(
        code(&base().claim(&["unit"], sha256('d'))),
        "MALFORMED_COMMITMENT"
    );
}

#[test]
fn an_agreement_s_terms_must_be_sound() {
    let unsound = [
        base().agreement(&["respondent"], wrapped(claimant().issuer)),
        base().agreement(&["respondWithinSeconds"], integer(0)),
        base().agreement(&["respondWithinSeconds"], integer(-1)),
        base().agreement(&["openClaimLimit"], integer(0)),
        base().agreement(&["registry"], string("")),
        base().agreement(&["contract", "id"], string("")),
        base().agreement(&["contract", "version"], string("")),
        base().agreement(&["scope", "operation"], string("")),
        base().agreement(
            &["scope", "identity"],
            list([string("order"), string("line"), string("order")]),
        ),
        base().agreement(&["validUntil"], wrapped("2026-02-01T00:00:00Z")),
        base().agreement(&["validUntil"], wrapped("2026-01-01T00:00:00Z")),
    ];
    for parts in &unsound {
        assert_eq!(code(parts), "AGREEMENT_INVALID");
    }
}

#[test]
fn both_parties_must_have_signed_the_agreement_with_their_own_keys() {
    let by_claimant_twice = base().signed_by(|s| s.agreement_respondent = claimant());
    assert_eq!(code(&by_claimant_twice), "PARTY_MISMATCH");
    let by_respondent_twice = base().signed_by(|s| s.agreement_claimant = respondent());
    assert_eq!(code(&by_respondent_twice), "PARTY_MISMATCH");

    // A key the relying party does not hold, even one a registry holds.
    let stranger = Key::new("test-stranger", 21, &[]);
    assert_eq!(
        code(&base().signed_by(|s| s.agreement_respondent = stranger)),
        "UNKNOWN_KEY"
    );
    assert_eq!(
        code(&base().signed_by(|s| s.agreement_claimant = registry_key())),
        "UNKNOWN_KEY"
    );

    // The respondent signed other terms than the ones presented.
    let mut signed = base().signed();
    let other_terms = base().agreement(&["openClaimLimit"], integer(500)).signed();
    let theirs = other_terms[0]
        .as_object()
        .and_then(|o| o.get("signatures")?.as_object()?.get("respondent"))
        .expect("a signature")
        .clone();
    signed[0] = replaced(&signed[0], &["signatures", "respondent"], Some(theirs));
    assert_eq!(
        verify_signed(&signed, &trust()),
        Err(RegistrationCode::SignatureInvalid)
    );
}

#[test]
fn a_key_counts_only_while_it_is_valid_and_only_if_it_is_ed25519() {
    let parts = base();
    let verify_under = |change: fn(&mut Key)| {
        let mut key = respondent();
        change(&mut key);
        let trust = trust_of(&[&claimant(), &key], &[(&registry_key(), REGISTRY)]);
        verify_signed(&parts.signed(), &trust)
    };
    // The agreement's signatures count at its start.
    assert_eq!(verify_under(|_| ()), Ok(()));
    assert_eq!(
        verify_under(|k| k.valid_from = "2026-02-01T00:00:01Z"),
        Err(RegistrationCode::KeyNotValid)
    );
    assert_eq!(
        verify_under(|k| k.valid_until = Some("2026-02-01T00:00:00Z")),
        Err(RegistrationCode::KeyNotValid)
    );
    assert_eq!(
        verify_under(|k| k.revoked_at = Some("2026-01-15T00:00:00Z")),
        Err(RegistrationCode::KeyNotValid)
    );
    assert_eq!(
        verify_under(|k| k.revoked_at = Some("2026-02-01T00:00:01Z")),
        Ok(())
    );
    assert_eq!(
        verify_under(|k| k.algorithm = "Ed448"),
        Err(RegistrationCode::UnsupportedAlgorithm)
    );

    let mut signed = parts.signed();
    signed[1] = replaced(&signed[1], &["signature", "scheme"], Some(string("Ed448")));
    assert_eq!(
        verify_signed(&signed, &trust()),
        Err(RegistrationCode::UnsupportedAlgorithm)
    );
}

#[test]
fn the_claim_is_the_claimant_s_under_this_agreement() {
    let mut elsewhere = base();
    elsewhere.claim = replaced(&elsewhere.claim, &["agreement"], Some(sha256('f')));
    elsewhere.receipt = replaced(&elsewhere.receipt, &["claim"], Some(hash(&elsewhere.claim)));
    assert_eq!(code(&elsewhere), "AGREEMENT_MISMATCH");

    assert_eq!(
        code(&base().signed_by(|s| s.claim = respondent())),
        "PARTY_MISMATCH"
    );

    // A signature made for another kind of object is not a claim signature.
    let mut signed = base().signed();
    let claim = base().claim;
    let under_another_domain = claimant().sign(AGREEMENT_DOMAIN, &claim);
    signed[1] = replaced(&signed[1], &["signature"], Some(under_another_domain));
    assert_eq!(
        verify_signed(&signed, &trust()),
        Err(RegistrationCode::SignatureInvalid)
    );

    // The claimant's key must be valid when the claim says it was made.
    let before_the_key = base().claim(&["claimedAt"], wrapped("2025-12-31T23:59:59Z"));
    assert_eq!(code(&before_the_key), "KEY_NOT_VALID");
}

#[test]
fn the_receipt_is_the_named_registry_s_for_this_claim() {
    let mut for_another = base();
    for_another.receipt = replaced(&for_another.receipt, &["claim"], Some(sha256('f')));
    assert_eq!(code(&for_another), "CLAIM_MISMATCH");

    let unnamed = base().receipt(&["registry"], string("registry.other.test"));
    assert_eq!(code(&unnamed), "REGISTRY_MISMATCH");

    // The right name, signed by a key trusted for another registry.
    let by_another = base().signed_by(|s| s.receipt = other_registry_key());
    assert_eq!(code(&by_another), "REGISTRY_MISMATCH");

    // A party's key is not a registry's key.
    let by_a_party = base().signed_by(|s| s.receipt = respondent());
    assert_eq!(code(&by_a_party), "UNKNOWN_KEY");

    // Any change to a signed receipt, here one that keeps its times
    // consistent, is found at its signature.
    let mut altered = base().signed();
    for (member, time) in [
        ("receivedAt", "2026-03-01T10:00:04Z"),
        ("respondBy", "2026-03-01T11:00:04Z"),
    ] {
        altered[2] = replaced(&altered[2], &["receipt", member], Some(wrapped(time)));
    }
    assert_eq!(
        verify_signed(&altered, &trust()),
        Err(RegistrationCode::SignatureInvalid)
    );
}

#[test]
fn only_entry_0_has_no_predecessor() {
    let first_with = base().receipt(&["previous"], sha256('e'));
    assert_eq!(code(&first_with), "CHAIN_INVALID");
    let later_without = base().receipt(&["sequence"], integer(3));
    assert_eq!(code(&later_without), "CHAIN_INVALID");
    let negative = base()
        .receipt(&["sequence"], integer(-1))
        .receipt(&["previous"], sha256('e'));
    assert_eq!(code(&negative), "CHAIN_INVALID");
}

#[test]
fn the_receipt_s_times_fit_the_agreement_and_the_claim() {
    let received = |at: &str, by: &str| {
        base()
            .receipt(&["receivedAt"], wrapped(at))
            .receipt(&["respondBy"], wrapped(by))
    };
    // The agreement is in force from its start, and no longer at its end.
    let at_the_end = received("2027-02-01T00:00:00Z", "2027-02-01T01:00:00Z");
    assert_eq!(code(&at_the_end), "AGREEMENT_NOT_IN_FORCE");
    let just_before = received("2027-01-31T23:59:59Z", "2027-02-01T00:59:59Z");
    assert_eq!(verify_signed(&just_before.signed(), &trust()), Ok(()));
    let early = base().agreement(&["validFrom"], wrapped("2026-03-01T10:00:06Z"));
    assert_eq!(code(&early), "AGREEMENT_NOT_IN_FORCE");

    let claimed_later = base().claim(&["claimedAt"], wrapped("2026-03-01T10:00:06Z"));
    assert_eq!(code(&claimed_later), "CLAIMED_AFTER_RECEIPT");
    let claimed_then = base().claim(&["claimedAt"], wrapped("2026-03-01T10:00:05Z"));
    assert_eq!(verify_signed(&claimed_then.signed(), &trust()), Ok(()));

    for deadline in ["2026-03-01T11:00:04Z", "2026-03-01T11:00:06Z"] {
        let moved = base().receipt(&["respondBy"], wrapped(deadline));
        assert_eq!(code(&moved), "DEADLINE_MISMATCH");
    }
    // A fraction of a second in the receipt time is kept in the deadline.
    let fraction = received("2026-03-01T10:00:05.250Z", "2026-03-01T11:00:05.250Z");
    assert_eq!(verify_signed(&fraction.signed(), &trust()), Ok(()));
    let dropped = received("2026-03-01T10:00:05.250Z", "2026-03-01T11:00:05Z");
    assert_eq!(code(&dropped), "DEADLINE_MISMATCH");
}

#[test]
fn the_first_failing_check_is_the_one_reported() {
    // An unsound agreement that also names another protocol.
    let both = base()
        .agreement(&["openClaimLimit"], integer(0))
        .receipt(&["protocol"], string("other"));
    assert_eq!(code(&both), "UNSUPPORTED_PROTOCOL");
    // A receipt for another claim that also has a wrong deadline and an
    // unknown signer.
    let mut many = base().receipt(&["respondBy"], wrapped("2026-03-01T12:00:00Z"));
    many.receipt = replaced(&many.receipt, &["claim"], Some(sha256('f')));
    let many = many.signed_by(|s| s.receipt = Key::new("test-stranger", 21, &[]));
    assert_eq!(code(&many), "CLAIM_MISMATCH");
    // A bad commitment in the receipt is found before an unsigned agreement.
    let early = base()
        .receipt(&["previous"], string_digest("sha-512"))
        .signed_by(|s| s.agreement_claimant = Key::new("test-stranger", 21, &[]));
    assert_eq!(code(&early), "MALFORMED_COMMITMENT");
}

fn string_digest(algorithm: &str) -> Value {
    object([("algorithm", string(algorithm)), ("hex", string(hex('a')))])
}

#[test]
fn a_trust_configuration_is_closed_and_names_each_key_once() {
    let record = |key: &Key| key_record(key, ("party", wrapped(key.issuer.clone())));
    let config = |parties: Value| object([("parties", parties), ("registries", list([]))]);
    assert!(RegistrationTrust::from_value(&config(list([record(&claimant())]))).is_ok());

    let misspelt = replaced(&record(&claimant()), &["revoked"], Some(Value::Null));
    assert!(RegistrationTrust::from_value(&config(list([misspelt]))).is_err());
    let twice = list([record(&claimant()), record(&claimant())]);
    assert!(RegistrationTrust::from_value(&config(twice)).is_err());
    let no_holder = replaced(&record(&claimant()), &["party"], None);
    assert!(RegistrationTrust::from_value(&config(list([no_holder]))).is_err());
    let not_a_key = replaced(&record(&claimant()), &["publicKey"], Some(string("AAAA")));
    assert!(RegistrationTrust::from_value(&config(list([not_a_key]))).is_err());
    assert!(RegistrationTrust::from_value(&object([("parties", list([]))])).is_err());
}
