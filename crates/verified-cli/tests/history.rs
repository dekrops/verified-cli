// SPDX-License-Identifier: Apache-2.0

//! `verified history read`, run as a user would run it, on a synthetic
//! relation and work record.

#[path = "../../verified-verifier/tests/support/mod.rs"]
mod support;

use std::path::PathBuf;
use std::process::{Command, Output};

use support::{Item, Key, hash, list, object, registry, string, uuid, wrapped};
use verified_canonical::Value;

const SOURCE: &str = "ledger";

fn ledger_key() -> Key {
    Key::new("test-ledger", 7, &[SOURCE])
}

/// A directory under the system's temporary directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("verified-cli-hi-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch directory");
        let scratch = Self(dir);
        scratch.file(
            "trust.json",
            &registry(&[&ledger_key()]).to_canonical_string(),
        );
        scratch
    }

    fn file(&self, name: &str, contents: &str) -> String {
        std::fs::write(self.0.join(name), contents).expect("write scratch file");
        name.to_owned()
    }

    fn history(&self, relations: Vec<Value>, records: Vec<Value>) -> String {
        let history = object([("records", list(records)), ("relations", list(relations))]);
        self.file("history.json", &history.to_canonical_string())
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_verified"))
            .env_clear()
            .env("LANG", "en_US.UTF-8")
            // Windows needs its system directory to start a process; elsewhere
            // the variable is absent and nothing is added.
            .envs(std::env::var_os("SYSTEMROOT").map(|root| ("SYSTEMROOT", root)))
            .current_dir(&self.0)
            .args(args)
            .output()
            .expect("run verified")
    }

    fn read(&self, history: &str) -> Output {
        self.run(&[
            "--json",
            "history",
            "read",
            history,
            "--trust",
            "trust.json",
        ])
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
    serde_json::from_slice(&output.stdout).expect("JSON output")
}

/// A work record of the right structure. Its digests are of placeholders:
/// the reader names a record and compares what it states, no more.
fn work_record(claim: &str) -> Value {
    let digest = |of: &str| hash(&string(of));
    let text = |of: &str| string(of);
    object([
        ("claim", digest("claim")),
        ("claimId", wrapped(claim)),
        ("contract", digest("contract")),
        ("contractId", text("invoice-processing")),
        ("contractVersion", text("1.0.0")),
        ("decision", text("SUPPORTED")),
        ("decisionDigest", digest("decision")),
        ("evaluator", text("work-contract")),
        ("evidence", digest("evidence")),
        ("inputs", digest("inputs")),
        ("language", text("work-contract-1")),
        ("packageCommitment", digest("package")),
        ("protocol", text("wvp-0.2")),
        ("semantics", text("kleene-1")),
        ("specification", text("1")),
    ])
}

fn offered(record: &Value) -> Value {
    object([
        ("kind", string("work-record")),
        ("text", string(record.to_canonical_string())),
    ])
}

/// The ledger's signed word that it holds `record`, as the record of
/// `claim`, signed by `key`.
fn recorded(record: &Value, claim: &str, key: &Key) -> Value {
    let body = object([
        ("protocol", string("verified-work-relation-v1")),
        (
            "recorded",
            object([
                ("claimId", wrapped(claim)),
                (
                    "record",
                    object([("digest", hash(record)), ("kind", string("work-record"))]),
                ),
            ]),
        ),
    ]);
    let mut item = Item::new(1, key, SOURCE, body.clone());
    item.kind = "SignedAttestation";
    item.subject = object([
        ("key", string(claim)),
        ("kind", string("work-relation")),
        ("system", string(SOURCE)),
    ]);
    object([("body", body), ("statement", item.signed())])
}

#[test]
fn a_relation_whose_record_is_given_and_agrees_is_checked() {
    let scratch = Scratch::new("checked");
    let claim = uuid(501);
    let record = work_record(&claim);
    let history = scratch.history(
        vec![recorded(&record, &claim, &ledger_key())],
        vec![offered(&record)],
    );

    let output = scratch.read(&history);

    assert_eq!(exit(&output), 0);
    let report = json(&output);
    assert_eq!(report["outcome"], "checked");
    // The command reads relations. It says that it verified no record.
    assert_eq!(report["recordsVerified"], false);
    let relation = &report["reading"]["relations"][0];
    assert_eq!(relation["standing"], "CHECKED");
    assert_eq!(relation["relation"], "recorded");
    assert_eq!(relation["source"], SOURCE);
}

#[test]
fn a_record_that_was_not_given_makes_the_relation_stated_not_refused() {
    let scratch = Scratch::new("stated");
    let claim = uuid(501);
    let record = work_record(&claim);
    let history = scratch.history(vec![recorded(&record, &claim, &ledger_key())], vec![]);

    let output = scratch.read(&history);

    assert_eq!(exit(&output), 3);
    let report = json(&output);
    assert_eq!(report["outcome"], "stated");
    let relation = &report["reading"]["relations"][0];
    assert_eq!(relation["standing"], "STATED");
    assert_eq!(relation["absent"][0]["kind"], "work-record");
}

#[test]
fn a_relation_is_accepted_only_from_a_key_the_registry_trusts_for_the_source() {
    let scratch = Scratch::new("refused");
    let claim = uuid(501);
    let record = work_record(&claim);
    let stranger = Key::new("test-stranger", 8, &[SOURCE]);
    let history = scratch.history(
        vec![recorded(&record, &claim, &stranger)],
        vec![offered(&record)],
    );

    let output = scratch.read(&history);

    assert_eq!(exit(&output), 1);
    let report = json(&output);
    assert_eq!(report["outcome"], "refused");
    let relation = &report["reading"]["relations"][0];
    assert_eq!(relation["standing"], "REFUSED");
    assert_eq!(relation["code"], "UNKNOWN_KEY");
    // Nobody the registry trusts said it, so no authority is named.
    assert!(relation.get("source").is_none());
}

#[test]
fn a_record_that_states_another_claim_contradicts_the_relation() {
    let scratch = Scratch::new("contradicted");
    let claim = uuid(501);
    let record = work_record(&uuid(502));
    let history = scratch.history(
        vec![recorded(&record, &claim, &ledger_key())],
        vec![offered(&record)],
    );

    let output = scratch.read(&history);

    assert_eq!(exit(&output), 1);
    let relation = &json(&output)["reading"]["relations"][0];
    assert_eq!(relation["standing"], "CONTRADICTED");
    assert_eq!(relation["code"], "CLAIM_MISMATCH");
}

#[test]
fn records_that_nobody_says_anything_about_are_not_a_checked_history() {
    let scratch = Scratch::new("silent");
    let record = work_record(&uuid(501));
    let history = scratch.history(vec![], vec![offered(&record)]);

    let output = scratch.read(&history);

    assert_eq!(exit(&output), 3);
    assert_eq!(json(&output)["outcome"], "stated");
}

#[test]
fn a_file_that_is_not_a_history_is_an_input_error_and_concludes_nothing() {
    let scratch = Scratch::new("input");
    let not_a_history = scratch.file("other.json", "{\"relations\":[]}");
    let many: Vec<Value> = (0..1025).map(|_| offered(&string("x"))).collect();
    let too_many = scratch.history(vec![], many);

    for history in [not_a_history, too_many] {
        let output = scratch.read(&history);
        assert_eq!(exit(&output), 2);
        assert_eq!(json(&output)["outcome"], "error");
    }
}
