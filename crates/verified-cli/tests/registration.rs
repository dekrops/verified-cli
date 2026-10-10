// SPDX-License-Identifier: Apache-2.0

//! `verified registration verify` and `verified registration log`, run as a
//! user would run them, on synthetic objects.

#[path = "../../verified-verifier/tests/support/mod.rs"]
mod support;

use std::path::PathBuf;
use std::process::{Command, Output};

use support::{Key, hash, list, object, string, wrapped};
use verified_canonical::Value;

const PROTOCOL: &str = "verified-claim-registration-v1";
const REGISTRY: &str = "registry.test";

/// A directory under the system's temporary directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("verified-cli-reg-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch directory");
        Self(dir)
    }

    fn file(&self, name: &str, contents: &str) -> String {
        let path = self.0.join(name);
        std::fs::write(&path, contents).expect("write scratch file");
        name.to_owned()
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_verified"))
            .env_clear()
            .env("LANG", "en_US.UTF-8")
            .current_dir(&self.0)
            .args(args)
            .output()
            .expect("run verified")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn exit(output: &Output) -> i32 {
    output.status.code().expect("an exit code")
}

fn json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).expect("JSON on standard output")
}

fn claimant() -> Key {
    Key::new("test-claimant", 11, &[])
}

fn respondent() -> Key {
    Key::new("test-respondent", 12, &[])
}

fn registry_key() -> Key {
    Key::new("test-registry", 13, &[])
}

fn sha256(byte: char) -> Value {
    let hex: String = std::iter::repeat_n(byte, 64).collect();
    object([("algorithm", string("sha-256")), ("hex", string(hex))])
}

fn trust(registries: &[&Key]) -> String {
    let record = |key: &Key, holder: (&str, Value)| {
        object([
            ("algorithm", string(key.algorithm)),
            ("keyId", string(key.id)),
            holder,
            ("publicKey", string(key.public_key())),
            ("validFrom", wrapped(key.valid_from)),
        ])
    };
    object([
        (
            "parties",
            list(
                [&claimant(), &respondent()]
                    .map(|k| record(k, ("party", wrapped(k.issuer.clone())))),
            ),
        ),
        (
            "registries",
            list(
                registries
                    .iter()
                    .map(|k| record(k, ("registry", string(REGISTRY)))),
            ),
        ),
    ])
    .to_canonical_string()
}

fn signed(key: &Key, kind: &str, domain: &str, entry: &Value) -> String {
    object([
        (kind, entry.clone()),
        ("signature", key.sign(domain, entry)),
    ])
    .to_canonical_string()
}

/// An unsigned receipt at `sequence`, received at that minute.
fn receipt(sequence: u32, previous: Option<&Value>, claim: Value) -> Value {
    object([
        ("claim", claim),
        ("previous", previous.map_or(Value::Null, hash)),
        ("protocol", string(PROTOCOL)),
        (
            "receivedAt",
            wrapped(format!("2026-03-01T10:{sequence:02}:00Z")),
        ),
        ("registry", string(REGISTRY)),
        (
            "respondBy",
            wrapped(format!("2026-03-01T11:{sequence:02}:00Z")),
        ),
        ("sequence", Value::Integer(i64::from(sequence).into())),
    ])
}

fn signed_receipt(entry: &Value) -> String {
    signed(
        &registry_key(),
        "receipt",
        "verified:claim-receipt:v1\n",
        entry,
    )
}

/// The signed agreement, claim and receipt of one registration.
fn registration() -> [String; 3] {
    let unit: String = std::iter::repeat_n('d', 64).collect();
    registration_of(sha256('b'), sha256('c'), &unit)
}

/// A registration whose agreement pins `unit_key`, and whose claim commits
/// to `inputs` and states `unit`.
fn registration_of(unit_key: Value, inputs: Value, unit: &str) -> [String; 3] {
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
        ("openClaimLimit", Value::Integer(5.into())),
        ("protocol", string(PROTOCOL)),
        ("registry", string(REGISTRY)),
        ("respondWithinSeconds", Value::Integer(3_600.into())),
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
        ("unitKey", unit_key),
        ("validFrom", wrapped("2026-02-01T00:00:00Z")),
        ("validUntil", Value::Null),
    ]);
    let claim = object([
        ("agreement", hash(&agreement)),
        ("claimedAt", wrapped("2026-03-01T09:59:00Z")),
        ("id", wrapped(support::uuid(0x501))),
        ("inputs", inputs),
        ("protocol", string(PROTOCOL)),
        (
            "unit",
            object([("algorithm", string("hmac-sha-256")), ("hex", string(unit))]),
        ),
    ]);
    let domain = "verified:claim-agreement:v1\n";
    let signed_agreement = object([
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
    [
        signed_agreement,
        signed(
            &claimant(),
            "claim",
            "verified:claim-commitment:v1\n",
            &claim,
        ),
        signed_receipt(&receipt(0, None, hash(&claim))),
    ]
}

#[test]
fn verify_reports_a_registration_and_refuses_one_under_untrusted_keys() {
    let scratch = Scratch::new("verify");
    let [agreement, claim, receipt] = registration();
    // A file's one final line end is the file's, not the object's.
    scratch.file("agreement.json", &format!("{agreement}\n"));
    scratch.file("claim.json", &claim);
    scratch.file("receipt.json", &format!("{receipt}\r\n"));
    scratch.file("keys.json", &trust(&[&registry_key()]));
    scratch.file("no-registry.json", &trust(&[]));
    let args = |keys: &'static str| {
        [
            "registration",
            "verify",
            "--agreement",
            "agreement.json",
            "--claim",
            "claim.json",
            "--receipt",
            "receipt.json",
            "--trust",
            keys,
            "--json",
        ]
    };

    let registered = scratch.run(&args("keys.json"));
    assert_eq!(exit(&registered), 0, "{registered:?}");
    let result = json(&registered);
    assert_eq!(result["outcome"], "registered");
    assert_eq!(result["claim"], support::uuid(0x501));
    assert_eq!(result["registry"], REGISTRY);
    assert_eq!(result["sequence"], 0);
    assert_eq!(result["respondBy"], "2026-03-01T11:00:00Z");

    let refused = scratch.run(&args("no-registry.json"));
    assert_eq!(exit(&refused), 1);
    let result = json(&refused);
    assert_eq!(result["outcome"], "refused");
    assert_eq!(result["refusal"]["code"], "UNKNOWN_KEY");

    let human = scratch.run(&args("keys.json")[..10]);
    assert_eq!(exit(&human), 0);
    let text = String::from_utf8_lossy(&human.stdout);
    assert!(
        text.contains("does not show that the claim is true"),
        "{text}"
    );

    let missing = scratch.run(&args("absent.json"));
    assert_eq!(exit(&missing), 2);
    assert_eq!(json(&missing)["outcome"], "error");
}

#[test]
fn log_checks_a_run_and_an_entry_held_against_it() {
    let scratch = Scratch::new("log");
    scratch.file("keys.json", &trust(&[&registry_key()]));
    let mut entries: Vec<Value> = Vec::new();
    for n in 0..4 {
        let claim = sha256(char::from_digit(n, 16).expect("a digit"));
        let entry = receipt(n, entries.last(), claim);
        entries.push(entry);
    }
    let lines: Vec<String> = entries.iter().map(signed_receipt).collect();
    scratch.file("log.jsonl", &format!("{}\n", lines.join("\n")));
    scratch.file("start.jsonl", &lines[..2].join("\n"));
    scratch.file("rest.jsonl", &lines[2..].join("\n"));
    scratch.file("entry-1.json", &lines[1]);
    scratch.file("entry-3.json", &lines[3]);
    scratch.file("empty.jsonl", "");
    // Another entry 3 than the one the log has.
    let other = signed_receipt(&receipt(3, Some(&entries[2]), sha256('f')));
    scratch.file("other-3.json", &other);
    let run = |args: &[&str]| {
        let mut all = vec!["registration", "log", "--json", "--trust", "keys.json"];
        all.extend_from_slice(args);
        scratch.run(&all)
    };

    let whole = run(&["log.jsonl"]);
    assert_eq!(exit(&whole), 0, "{whole:?}");
    let result = json(&whole);
    assert_eq!(result["outcome"], "verified");
    assert_eq!(
        (result["first"].as_i64(), result["last"].as_i64()),
        (Some(0), Some(3))
    );
    assert_eq!(result["head"]["hex"], entries[3].digest().to_hex());
    assert!(result["inclusion"].is_null());

    let continued = run(&["rest.jsonl", "--anchor", "entry-1.json"]);
    assert_eq!(exit(&continued), 0);
    assert_eq!(json(&continued)["first"], 2);
    let unanchored = run(&["rest.jsonl"]);
    assert_eq!(exit(&unanchored), 1);
    assert_eq!(json(&unanchored)["refusal"]["code"], "GENESIS_INVALID");
    let empty = run(&["empty.jsonl"]);
    assert_eq!(exit(&empty), 1);
    assert_eq!(json(&empty)["refusal"]["code"], "MALFORMED");

    let included = run(&["log.jsonl", "--held", "entry-3.json"]);
    assert_eq!(exit(&included), 0);
    assert_eq!(json(&included)["inclusion"], "INCLUDED");

    let not_covered = run(&["start.jsonl", "--held", "entry-3.json"]);
    assert_eq!(exit(&not_covered), 3);
    assert_eq!(json(&not_covered)["outcome"], "not_covered");

    let contradicted = run(&["log.jsonl", "--held", "other-3.json"]);
    assert_eq!(exit(&contradicted), 1);
    let result = json(&contradicted);
    assert_eq!(result["outcome"], "equivocation");
    assert_eq!(result["logged"]["hex"], entries[3].digest().to_hex());

    let human = scratch.run(&["registration", "log", "--trust", "keys.json", "log.jsonl"]);
    assert_eq!(exit(&human), 0);
    let text = String::from_utf8_lossy(&human.stdout);
    assert!(
        text.contains("entries 0 to 3 are consecutive and unaltered"),
        "{text}"
    );
}

#[test]
fn audit_reports_each_claim_s_state_from_the_log_and_its_documents() {
    let scratch = Scratch::new("audit");
    let [agreement, claim, receipt] = registration();
    scratch.file("keys.json", &trust(&[&registry_key()]));
    scratch.file("log.jsonl", &format!("{receipt}\n"));
    // Documents in any order, one per line, with one the log does not name.
    scratch.file(
        "documents.jsonl",
        &format!("{claim}\n{agreement}\n{receipt}\n"),
    );
    scratch.file("agreement.json", &agreement);
    let run = |args: &[&str]| {
        let mut all = vec!["registration", "audit", "--json", "--trust", "keys.json"];
        all.extend_from_slice(args);
        scratch.run(&all)
    };

    let audited = run(&["log.jsonl", "documents.jsonl"]);
    assert_eq!(exit(&audited), 0, "{audited:?}");
    let result = json(&audited);
    assert_eq!(result["outcome"], "audited");
    assert_eq!(result["claims"].as_array().map(Vec::len), Some(1));
    let first = &result["claims"][0];
    assert_eq!(first["claim"], support::uuid(0x501));
    assert_eq!(first["state"], "OPEN");
    assert_eq!(first["position"], 0);
    assert!(first["dispute"].is_null());

    let without_claim = run(&["log.jsonl", "agreement.json"]);
    assert_eq!(exit(&without_claim), 1);
    assert_eq!(json(&without_claim)["refusal"]["code"], "MISSING_CLAIM");

    let human = scratch.run(&[
        "registration",
        "audit",
        "--trust",
        "keys.json",
        "log.jsonl",
        "documents.jsonl",
    ]);
    assert_eq!(exit(&human), 0);
    let text = String::from_utf8_lossy(&human.stdout);
    assert!(
        text.contains("OPEN") && text.contains("not a verification result"),
        "{text}"
    );
}

#[test]
fn unit_checks_a_claim_s_unit_against_its_inputs_without_showing_the_key() {
    use verified_work_unit::{Identity, Scope, SecretKey};

    let key_hex = "5c".repeat(32);
    let key = SecretKey::from_bytes([0x5c; 32]);
    let scope = Scope {
        scope: "orders".to_owned(),
        operation: "fulfil".to_owned(),
        identity: vec!["order".to_owned()],
    };
    let unit_of = |order: &str| {
        let identity = Identity::new("tenant-test", &scope, &[string(order)]).expect("a unit");
        key.nullifier(&identity).to_hex()
    };
    let inputs = object([("amount", string("1250")), ("order", string("SO-1001"))]);
    let commitment = object([
        ("algorithm", string("sha-256")),
        ("hex", string(key.commitment().to_hex())),
    ]);

    let scratch = Scratch::new("unit");
    let [agreement, claim, _] =
        registration_of(commitment.clone(), hash(&inputs), &unit_of("SO-1001"));
    let [_, other_claim, _] = registration_of(commitment, hash(&inputs), &unit_of("SO-1002"));
    scratch.file("agreement.json", &agreement);
    scratch.file("claim.json", &claim);
    scratch.file("other-claim.json", &other_claim);
    scratch.file(
        "inputs.json",
        &format!("{}\n", inputs.to_canonical_string()),
    );
    scratch.file("unit.key", &format!("{key_hex}\n"));
    scratch.file("wrong.key", &"5d".repeat(32));
    let run = |claim: &str, key: &str| {
        scratch.run(&[
            "registration",
            "unit",
            "--json",
            "--agreement",
            "agreement.json",
            "--claim",
            claim,
            "--inputs",
            "inputs.json",
            "--unit-key",
            key,
        ])
    };

    let matches = run("claim.json", "unit.key");
    assert_eq!(exit(&matches), 0, "{matches:?}");
    assert_eq!(json(&matches)["outcome"], "unit_matches");
    assert_eq!(json(&matches)["signaturesChecked"], false);

    for (claim, key, code) in [
        ("other-claim.json", "unit.key", "UNIT_MISMATCH"),
        ("claim.json", "wrong.key", "UNIT_KEY_MISMATCH"),
        ("claim.json", "inputs.json", "MALFORMED"),
    ] {
        let refused = run(claim, key);
        assert_eq!(exit(&refused), 1, "{refused:?}");
        assert_eq!(json(&refused)["refusal"]["code"], code);
        let shown = format!(
            "{}{}",
            String::from_utf8_lossy(&refused.stdout),
            String::from_utf8_lossy(&refused.stderr)
        );
        assert!(
            !shown.contains(&key_hex) && !shown.contains("5d5d"),
            "{shown}"
        );
    }
    assert_eq!(exit(&run("claim.json", "absent.key")), 2);
}
