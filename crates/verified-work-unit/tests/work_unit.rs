// SPDX-License-Identifier: Apache-2.0

//! Work-unit identities and nullifiers. The known answers were computed with
//! another implementation of HMAC-SHA-256 and SHA-256 (Python's standard
//! library), not with this crate.

use verified_canonical::{Limits, Value, parse};
use verified_work_unit::{Error, Identity, Nullifier, Scope, SecretKey};

fn json(text: &str) -> Value {
    parse(text.as_bytes(), &Limits::DEFAULT).expect("test JSON")
}

fn scope(operation: &str, inputs: &[&str]) -> Scope {
    Scope {
        scope: "posting-test".to_owned(),
        operation: operation.to_owned(),
        identity: inputs.iter().map(|input| (*input).to_owned()).collect(),
    }
}

fn text(s: &str) -> Value {
    Value::String(s.to_owned())
}

fn key(byte: u8) -> SecretKey {
    SecretKey::from_bytes([byte; 32])
}

fn unit(tenant: &str, operation: &str, invoice: &str) -> Identity {
    Identity::new(tenant, &scope(operation, &["invoice"]), &[text(invoice)]).expect("an identity")
}

#[test]
fn known_answers() {
    let identity = unit("tenant-test", "post", "INV-1");
    assert_eq!(
        identity.canonical(),
        r#"["work-unit-1","tenant-test","posting-test","post",["INV-1"]]"#
    );
    let nullifier = key(7).nullifier(&identity);
    assert_eq!(
        nullifier.to_hex(),
        "c210ecf7c697a6a3c672dad4fc6e92625390a4c7441162dc7a1aa45dfb44a184"
    );
    assert_eq!(
        nullifier.to_string(),
        "hmac-sha-256:c210ecf7c697a6a3c672dad4fc6e92625390a4c7441162dc7a1aa45dfb44a184"
    );
    assert_eq!(
        nullifier.to_value(),
        json(
            r#"{"algorithm": "hmac-sha-256", "hex": "c210ecf7c697a6a3c672dad4fc6e92625390a4c7441162dc7a1aa45dfb44a184"}"#
        )
    );
    assert_eq!(
        key(7).commitment().to_hex(),
        "d8f15c2e1943a10e38eaaaf61faf8d396533c8a421dc41900790b9dbb4c4af30"
    );

    // Two identifying inputs, one of them a boolean.
    let two = Identity::new(
        "tenant-test",
        &scope("post", &["invoice", "urgent"]),
        &[text("INV-1"), Value::Bool(true)],
    )
    .expect("an identity");
    assert_eq!(
        key(7).nullifier(&two).to_hex(),
        "913dadbd85ca9975b18693ef8bf944ec094b00722ee6987fb4e2d60da1159f0d"
    );
}

#[test]
fn the_same_unit_has_the_same_nullifier_and_every_part_of_it_matters() {
    let base = key(1).nullifier(&unit("tenant-a", "process", "INV-1001"));
    assert_eq!(
        base,
        key(1).nullifier(&unit("tenant-a", "process", "INV-1001"))
    );

    let others: [Nullifier; 6] = [
        key(1).nullifier(&unit("tenant-a", "process", "INV-1002")),
        // Other work on the same object.
        key(1).nullifier(&unit("tenant-a", "post", "INV-1001")),
        // The same number for another tenant, even under the same key.
        key(1).nullifier(&unit("tenant-b", "process", "INV-1001")),
        // Values are compared exactly.
        key(1).nullifier(&unit("tenant-a", "process", "INV-01001")),
        key(1).nullifier(&unit("tenant-a", "process", "inv-1001")),
        // The same unit under the tenant's next key.
        key(2).nullifier(&unit("tenant-a", "process", "INV-1001")),
    ];
    for (i, other) in others.iter().enumerate() {
        assert_ne!(*other, base, "{i}");
        assert!(others[..i].iter().all(|earlier| earlier != other), "{i}");
    }
}

#[test]
fn the_scope_not_the_contract_decides_what_one_unit_is() {
    // Another line of work with the same operation and value is another unit.
    let mut other = scope("process", &["invoice"]);
    other.scope = "invoice-archiving".to_owned();
    let a = Identity::new(
        "tenant-a",
        &scope("process", &["invoice"]),
        &[text("INV-1")],
    )
    .expect("identity");
    let b = Identity::new("tenant-a", &other, &[text("INV-1")]).expect("identity");
    assert_ne!(a, b);
    // The names of the identifying inputs are not part of the identity: two
    // contracts that call the input differently share the unit if they share
    // the scope.
    let renamed = Identity::new(
        "tenant-a",
        &scope("process", &["invoiceNumber"]),
        &[text("INV-1")],
    )
    .expect("identity");
    assert_eq!(a, renamed);
    // When the scope names the source system, the same number in two systems
    // is two units.
    let with_system = scope("process", &["system", "invoice"]);
    let sap =
        Identity::new("tenant-a", &with_system, &[text("sap"), text("INV-1")]).expect("identity");
    let oracle = Identity::new("tenant-a", &with_system, &[text("oracle"), text("INV-1")])
        .expect("identity");
    assert_ne!(sap, oracle);
    // Order is the scope's: swapping values is another unit.
    let swapped =
        Identity::new("tenant-a", &with_system, &[text("INV-1"), text("sap")]).expect("identity");
    assert_ne!(sap, swapped);
}

#[test]
fn an_identity_is_taken_from_the_claim_inputs_the_scope_names() {
    let scope = scope("process", &["system", "invoice"]);
    let inputs = json(r#"{"cutoff": "1767225600", "invoice": "INV-1", "system": "sap"}"#);
    let from_claim = Identity::of_claim("tenant-a", &scope, &inputs).expect("identity");
    let direct =
        Identity::new("tenant-a", &scope, &[text("sap"), text("INV-1")]).expect("identity");
    assert_eq!(from_claim, direct);

    assert_eq!(
        Identity::of_claim("tenant-a", &scope, &json(r#"{"invoice": "INV-1"}"#)),
        Err(Error::MissingInput("system".to_owned()))
    );
    assert_eq!(
        Identity::of_claim("tenant-a", &scope, &json("[]")),
        Err(Error::InputsNotAnObject)
    );
}

#[test]
fn values_that_no_claim_input_can_be_are_refused() {
    let one = scope("process", &["invoice"]);
    assert_eq!(
        Identity::new("tenant-a", &one, &[]),
        Err(Error::ValueCount {
            expected: 1,
            found: 0
        })
    );
    assert_eq!(
        Identity::new("tenant-a", &one, &[text("a"), text("b")]),
        Err(Error::ValueCount {
            expected: 1,
            found: 2
        })
    );
    for bad in ["null", "1001", "[\"INV-1\"]", "{\"n\": \"INV-1\"}"] {
        assert_eq!(
            Identity::new("tenant-a", &one, &[json(bad)]),
            Err(Error::UnsupportedValue(0)),
            "{bad}"
        );
    }
}

#[test]
fn a_scope_is_a_closed_object() {
    let read = |text: &str| Scope::from_value(&json(text));
    assert_eq!(
        read(r#"{"scope": "posting-test", "operation": "post", "identity": ["invoice"]}"#),
        Ok(scope("post", &["invoice"]))
    );
    for bad in [
        r#"{"scope": "s", "operation": "o"}"#,
        r#"{"scope": "s", "operation": "o", "identity": ["invoice"], "version": 1}"#,
        r#"{"scope": "s", "operation": 1, "identity": ["invoice"]}"#,
        r#"{"scope": "s", "operation": "o", "identity": "invoice"}"#,
        r#"{"scope": "s", "operation": "o", "identity": [1]}"#,
        r#"["s", "o", ["invoice"]]"#,
    ] {
        assert_eq!(read(bad), Err(Error::MalformedScope), "{bad}");
    }
}

#[test]
fn a_secret_key_is_never_printed() {
    let shown = format!("{:?}", key(0xab));
    assert!(!shown.contains("abab"), "{shown}");
    assert!(shown.contains(&key(0xab).commitment().to_hex()), "{shown}");
}

/// The upstream vectors, when available: see `conformance/README.md`.
#[test]
#[allow(clippy::print_stderr)] // a progress note for whoever runs the corpus
fn every_vector_in_the_corpus_is_reproduced() {
    let Some(dir) = std::env::var_os("VERIFIED_CONFORMANCE_DIR") else {
        assert!(
            std::env::var_os("VERIFIED_CONFORMANCE_REQUIRED").is_none(),
            "VERIFIED_CONFORMANCE_REQUIRED is set but VERIFIED_CONFORMANCE_DIR is not"
        );
        eprintln!("skipped: VERIFIED_CONFORMANCE_DIR is not set");
        return;
    };
    let path = std::path::PathBuf::from(dir).join("work-unit/v1/vectors.json");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let vectors = parse(&bytes, &Limits::DEFAULT).expect("JSON");
    let vectors = vectors.as_object().expect("an object");
    let member = |object: &verified_canonical::Object, name: &str| {
        object
            .get(name)
            .cloned()
            .unwrap_or_else(|| panic!("no {name}"))
    };
    assert_eq!(member(vectors, "version"), text("work-unit-1"));

    let mut keys = Vec::new();
    for entry in member(vectors, "keys").as_array().expect("keys") {
        let entry = entry.as_object().expect("a key");
        let hex = member(entry, "secretHex");
        let hex = hex.as_str().expect("hex");
        let mut secret = [0u8; 32];
        assert_eq!(hex.len(), 64);
        for (byte, pair) in secret.iter_mut().zip(hex.as_bytes().chunks(2)) {
            *byte = u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII"), 16).expect("hex");
        }
        let key = SecretKey::from_bytes(secret);
        let commitment = member(entry, "commitment");
        let commitment = commitment.as_object().expect("a digest");
        assert_eq!(member(commitment, "algorithm"), text("sha-256"));
        assert_eq!(member(commitment, "hex"), text(&key.commitment().to_hex()));
        keys.push((member(entry, "id"), key));
    }

    let cases = member(vectors, "cases");
    let cases = cases.as_array().expect("cases");
    for case in cases {
        let case = case.as_object().expect("a case");
        let name = member(case, "name");
        let scope = Scope::from_value(&member(case, "scope")).expect("a scope");
        let tenant = member(case, "tenant");
        let values = member(case, "values");
        let identity = Identity::new(
            tenant.as_str().expect("tenant"),
            &scope,
            values.as_array().expect("values"),
        )
        .expect("an identity");
        assert_eq!(
            text(&identity.canonical()),
            member(case, "identityCanonical"),
            "{name:?}"
        );
        let key_id = member(case, "key");
        let (_, key) = keys
            .iter()
            .find(|(id, _)| *id == key_id)
            .expect("a known key");
        assert_eq!(
            key.nullifier(&identity).to_value(),
            member(case, "nullifier"),
            "{name:?}"
        );
    }
    eprintln!(
        "work-unit-1: {} key commitments and {} nullifiers reproduced",
        keys.len(),
        cases.len()
    );
    assert_ne!(cases.len(), 0, "the corpus holds no cases");
}

mod registered {
    use verified_canonical::{Limits, Value, parse};
    use verified_work_unit::registered::{UnitCheckCode, check_registered_unit};
    use verified_work_unit::{Identity, Scope, SecretKey};

    const KEY: &str = "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a";
    const INPUTS: &str = r#"{"amount":"1250","order":"SO-1001"}"#;

    fn json(text: &str) -> Value {
        parse(text.as_bytes(), &Limits::DEFAULT).expect("test JSON")
    }

    fn digest(value: &Value) -> String {
        format!(
            r#"{{"algorithm":"sha-256","hex":"{}"}}"#,
            value.digest().to_hex()
        )
    }

    /// The canonical text of a JSON document written loosely.
    fn canonical(text: &str) -> String {
        json(text).to_canonical_string()
    }

    fn signature() -> &'static str {
        // The unit check verifies no signature; the structure needs one.
        r#"{"encoded":"AA==","keyId":"k","scheme":"Ed25519"}"#
    }

    /// A signed agreement whose scope identifies a unit by `identity`.
    fn agreement(identity: &str, key: &SecretKey) -> String {
        canonical(&format!(
            r#"{{"agreement":{{
                "claimant":{{"value":"00000000-0000-4000-8000-000000000601"}},
                "contract":{{"digest":{{"algorithm":"sha-256","hex":"{zero}"}},"id":"orders","version":"1"}},
                "id":{{"value":"00000000-0000-4000-8000-000000000701"}},
                "openClaimLimit":5,
                "protocol":"verified-claim-registration-v1",
                "registry":"registry.test",
                "respondWithinSeconds":3600,
                "respondent":{{"value":"00000000-0000-4000-8000-000000000602"}},
                "scope":{{"identity":{identity},"operation":"fulfil","scope":"orders"}},
                "tenant":{{"value":"tenant-test"}},
                "unitKey":{{"algorithm":"sha-256","hex":"{commitment}"}},
                "validFrom":{{"value":"2026-02-01T00:00:00Z"}},
                "validUntil":null}},
              "signatures":{{"claimant":{signature},"respondent":{signature}}}}}"#,
            zero = "0".repeat(64),
            commitment = key.commitment().to_hex(),
            signature = signature(),
        ))
    }

    /// A signed claim under `agreement`, committing to `inputs`, with `unit`.
    fn claim(agreement: &str, inputs: &str, unit: &str) -> String {
        let unsigned = json(agreement);
        let unsigned = unsigned
            .as_object()
            .and_then(|o| o.get("agreement"))
            .expect("an agreement");
        canonical(&format!(
            r#"{{"claim":{{
                "agreement":{agreement},
                "claimedAt":{{"value":"2026-03-01T10:00:00Z"}},
                "id":{{"value":"00000000-0000-4000-8000-000000000501"}},
                "inputs":{inputs},
                "protocol":"verified-claim-registration-v1",
                "unit":{{"algorithm":"hmac-sha-256","hex":"{unit}"}}}},
              "signature":{signature}}}"#,
            agreement = digest(unsigned),
            inputs = digest(&json(inputs)),
            signature = signature(),
        ))
    }

    fn key() -> SecretKey {
        SecretKey::from_bytes([0x2a; 32])
    }

    /// The nullifier of order `order` under the test scope and key.
    fn unit_of(order: &str) -> String {
        let scope = Scope {
            scope: "orders".to_owned(),
            operation: "fulfil".to_owned(),
            identity: vec!["order".to_owned()],
        };
        let identity = Identity::new("tenant-test", &scope, &[Value::String(order.to_owned())])
            .expect("an identity");
        key().nullifier(&identity).to_hex()
    }

    fn check(agreement: &str, claim: &str, inputs: &str, key: &str) -> Result<(), UnitCheckCode> {
        check_registered_unit(
            agreement.as_bytes(),
            claim.as_bytes(),
            inputs.as_bytes(),
            key,
        )
        .map_err(|refusal| refusal.code)
    }

    #[test]
    fn a_unit_is_the_nullifier_of_the_inputs_the_scope_names() {
        let agreement = agreement(r#"["order"]"#, &key());
        let claim = claim(&agreement, INPUTS, &unit_of("SO-1001"));
        assert_eq!(check(&agreement, &claim, INPUTS, KEY), Ok(()));
    }

    #[test]
    fn each_check_refuses_with_its_own_code_in_order() {
        use UnitCheckCode as Code;
        let agreement = agreement(r#"["order"]"#, &key());
        let good = claim(&agreement, INPUTS, &unit_of("SO-1001"));

        // Step 1: text, structure and the key's spelling.
        for bad_key in [
            &KEY[..62],
            &KEY.to_uppercase(),
            &format!("{KEY}2a"),
            "",
            &KEY.replace('2', "g"),
        ] {
            assert_eq!(
                check(&agreement, &good, INPUTS, bad_key),
                Err(Code::Malformed)
            );
        }
        assert_eq!(
            check(&format!("{agreement} "), &good, INPUTS, KEY),
            Err(Code::Malformed)
        );
        assert_eq!(check(&agreement, "{}", INPUTS, KEY), Err(Code::Malformed));
        for inputs in [
            r#"{"order":7}"#,
            r#"["SO-1001"]"#,
            r#"{"order": "SO-1001"}"#,
        ] {
            assert_eq!(check(&agreement, &good, inputs, KEY), Err(Code::Malformed));
        }

        // Step 2.
        let other_agreement = self::agreement(r#"["order","amount"]"#, &key());
        assert_eq!(
            check(&other_agreement, &good, INPUTS, KEY),
            Err(Code::AgreementMismatch)
        );
        // Step 3.
        let other_key = "2b".repeat(32);
        assert_eq!(
            check(&agreement, &good, INPUTS, &other_key),
            Err(Code::UnitKeyMismatch)
        );
        // Step 4.
        let other_inputs = r#"{"amount":"1250","order":"SO-1002"}"#;
        assert_eq!(
            check(&agreement, &good, other_inputs, KEY),
            Err(Code::InputsMismatch)
        );
        // Step 5.
        let no_order = r#"{"amount":"1250"}"#;
        let claim_without = claim(&agreement, no_order, &unit_of("SO-1001"));
        assert_eq!(
            check(&agreement, &claim_without, no_order, KEY),
            Err(Code::MissingInput)
        );
        // Step 6: the unit of another order, and a unit that is not keyed.
        let another = claim(&agreement, INPUTS, &unit_of("SO-1002"));
        assert_eq!(
            check(&agreement, &another, INPUTS, KEY),
            Err(Code::UnitMismatch)
        );
        let plain = good.replace("hmac-sha-256", "sha-256");
        assert_eq!(
            check(&agreement, &plain, INPUTS, KEY),
            Err(Code::UnitMismatch)
        );
    }

    #[test]
    fn a_refusal_never_shows_the_key_or_an_input_value() {
        let agreement = agreement(r#"["order"]"#, &key());
        let another = claim(&agreement, INPUTS, &unit_of("SO-1002"));
        let refusal = check_registered_unit(
            agreement.as_bytes(),
            another.as_bytes(),
            INPUTS.as_bytes(),
            KEY,
        )
        .expect_err("a refusal");
        let shown = format!("{refusal} {refusal:?}");
        assert!(!shown.contains(KEY) && !shown.contains("SO-100"), "{shown}");
    }

    #[test]
    #[allow(clippy::print_stderr)] // progress notes for whoever runs the corpus
    fn every_unit_case_in_the_corpus_is_reproduced() {
        let Some(dir) = std::env::var_os("VERIFIED_CONFORMANCE_DIR") else {
            assert!(
                std::env::var_os("VERIFIED_CONFORMANCE_REQUIRED").is_none(),
                "VERIFIED_CONFORMANCE_REQUIRED is set but VERIFIED_CONFORMANCE_DIR is not"
            );
            eprintln!("skipped: VERIFIED_CONFORMANCE_DIR is not set");
            return;
        };
        let path = std::path::PathBuf::from(dir).join("claim-registration/v1/unit.json");
        let at = path.display().to_string();
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{at}: {e}"));
        let corpus = parse(&bytes, &Limits::DEFAULT).unwrap_or_else(|e| panic!("{at}: {e}"));
        let member = |value: &Value, name: &str| {
            value
                .as_object()
                .and_then(|o| o.get(name))
                .unwrap_or_else(|| panic!("{at}: no {name}"))
                .clone()
        };
        let text = |value: &Value, name: &str| {
            member(value, name)
                .as_str()
                .unwrap_or_else(|| panic!("{at}: {name} is not text"))
                .to_owned()
        };
        let cases = member(&corpus, "cases");
        let cases = cases.as_array().expect("a list of cases");
        assert!(!cases.is_empty(), "{at}: no cases");
        for case in cases {
            let name = text(case, "name");
            let outcome = check(
                &text(case, "agreementJson"),
                &text(case, "claimJson"),
                &text(case, "inputsJson"),
                &text(case, "unitKeyHex"),
            );
            let expected = member(case, "expected");
            let expected = match member(&expected, "accept") {
                Value::Bool(true) => Ok(()),
                _ => Err(text(&expected, "error")),
            };
            assert_eq!(
                outcome.map_err(|code| code.as_str().to_owned()),
                expected,
                "{at}: {name}"
            );
        }
        eprintln!(
            "claim-registration-1: {} unit cases reproduced",
            cases.len()
        );
    }
}
