// SPDX-License-Identifier: Apache-2.0

//! `verify --record`, `export`, `diff` and `replay`, run as a user would
//! run them, on synthetic packages.

#[path = "../../verified-verifier/tests/support/mod.rs"]
mod support;

use std::path::PathBuf;
use std::process::{Command, Output};

use support::{Scenario, evidence_key, issuer_key, registry, replaced, string};

/// A directory under the system's temporary directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("verified-cli-port-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch directory");
        Self(dir)
    }

    fn file(&self, name: &str, contents: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, contents).expect("write scratch file");
        path
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

    /// Imports a scenario and returns its package and object identifiers.
    fn import(&self, name: &str, scenario: &Scenario) -> (String, String) {
        self.file(name, scenario.text().as_bytes());
        let imported = json(&self.run(&["import", "--json", name]));
        let text = |member: &str| imported[member].as_str().expect("an identifier").to_owned();
        (text("package"), text("object"))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("UTF-8 output")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("UTF-8 output")
}

fn json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).expect("JSON on standard output")
}

fn signed() -> Scenario {
    let mut scenario = Scenario::posted();
    scenario.issuers = vec![issuer_key()];
    scenario
}

fn undetermined() -> Scenario {
    let mut scenario = Scenario::posted();
    scenario.items[0].body = support::json(
        r#"{"record": {"kind": "posting", "fields": {"document": "D-2", "invoice": "INV-2"}}}"#,
    );
    scenario.outcome = support::json(
        r#"{"decision": "UNDETERMINED", "requirements": [{"id": "POSTED", "value": "UNKNOWN"}],
            "ignored": [], "conflicts": []}"#,
    );
    scenario
}

#[test]
fn a_work_record_must_be_about_the_package() {
    let scratch = Scratch::new("record");
    scratch.file("package.json", Scenario::posted().text().as_bytes());
    scratch.file(
        "trust.json",
        registry(&[&evidence_key()])
            .to_canonical_string()
            .as_bytes(),
    );

    // The record a complete verification yields is in its JSON output.
    let output = scratch.run(&["verify", "--json", "package.json", "--trust", "trust.json"]);
    assert_eq!(output.status.code(), Some(0));
    let result = json(&output);
    assert_eq!(result["recordMatched"], false);
    let record = &result["workRecord"];
    assert_eq!(record["decision"], "SUPPORTED");
    assert_eq!(record["contractId"], "posting-test");
    assert_eq!(record["language"], "work-contract-1");
    scratch.file(
        "record.json",
        serde_json::to_string_pretty(record)
            .expect("JSON")
            .as_bytes(),
    );

    let output = scratch.run(&[
        "verify",
        "package.json",
        "--trust",
        "trust.json",
        "--record",
        "record.json",
    ]);
    let text = stdout(&output);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(
        text.contains("work record           the supplied record is about this package\n"),
        "{text}"
    );

    // A record of another decision and another contract version.
    let mut other = record.clone();
    other["decision"] = "CONTRADICTED".into();
    other["contractVersion"] = "2.0.0".into();
    scratch.file("other.json", other.to_string().as_bytes());
    let output = scratch.run(&[
        "verify",
        "--json",
        "package.json",
        "--trust",
        "trust.json",
        "--record",
        "other.json",
    ]);
    assert_eq!(output.status.code(), Some(1));
    let refusal = json(&output);
    assert_eq!(refusal["refusal"]["code"], "RECORD_MISMATCH");
    assert!(
        refusal["refusal"]["detail"]
            .as_str()
            .is_some_and(|d| d.ends_with(": contractVersion, decision")),
        "{refusal}"
    );

    // Unusable record files, and a record for a version that defines none.
    scratch.file("broken.json", b"{");
    let output = scratch.run(&[
        "verify",
        "--json",
        "package.json",
        "--record",
        "broken.json",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(json(&output)["error"]["code"], "WORK_RECORD");
    scratch.file("shipped.json", Scenario::shipped().text().as_bytes());
    let output = scratch.run(&[
        "verify",
        "--json",
        "shipped.json",
        "--record",
        "record.json",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(json(&output)["error"]["code"], "RECORD_UNDEFINED");
}

#[test]
fn export_writes_the_exact_imported_text_and_never_overwrites() {
    let scratch = Scratch::new("export");
    let text = Scenario::posted().text();
    scratch.run(&["init"]);
    // Imported from a file with a line end; the package has none.
    scratch.file("in.json", format!("{text}\n").as_bytes());
    let imported = json(&scratch.run(&["import", "--json", "in.json"]));
    let id = imported["package"].as_str().expect("package");

    let output = scratch.run(&["export", id]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, text.as_bytes());
    assert_eq!(stderr(&output), "");

    let output = scratch.run(&["export", id, "--output", "out.json"]);
    let message = stdout(&output);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(message.contains("Nothing was added"), "{message}");
    assert_eq!(
        std::fs::read(scratch.0.join("out.json")).expect("read"),
        text.as_bytes()
    );

    // An existing file is left alone.
    scratch.file("mine.json", b"mine");
    let output = scratch.run(&["export", id, "-o", "mine.json"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        std::fs::read(scratch.0.join("mine.json")).expect("read"),
        b"mine"
    );

    // What was exported verifies as the original does, and re-imports as
    // the same object.
    let again = json(&scratch.run(&["import", "--json", "out.json"]));
    assert_eq!(again["object"], imported["object"]);
    assert_eq!(again["alreadyPresent"], true);

    assert_eq!(
        scratch.run(&["export", "--json", id]).status.code(),
        Some(2)
    );
    assert_eq!(scratch.run(&["export", "0000"]).status.code(), Some(2));
}

#[test]
fn diff_compares_what_two_packages_state() {
    let scratch = Scratch::new("diff");
    scratch.run(&["init"]);
    let (posted, unsigned_object) = scratch.import("posted.json", &Scenario::posted());
    let (_, signed_object) = scratch.import("signed.json", &signed());
    scratch.file("undetermined.json", undetermined().text().as_bytes());

    // The same text, named two ways.
    let output = scratch.run(&["diff", "posted.json", &unsigned_object]);
    assert_eq!(output.status.code(), Some(0));
    assert!(stdout(&output).ends_with("identical: the two texts are the same, byte for byte\n"));
    assert_eq!(
        json(&scratch.run(&["diff", "--json", "posted.json", &unsigned_object]))["outcome"],
        "identical"
    );

    // Two texts of one package: only the issuer signatures differ.
    let output = scratch.run(&["diff", &unsigned_object, &signed_object]);
    let text = stdout(&output);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(text.contains("claim.json                same\n"), "{text}");
    assert!(!text.contains("differs"), "{text}");
    assert!(text.contains("issuer signatures     a: none\n"), "{text}");
    assert!(text.contains("b: test-decision-issuer\n"), "{text}");
    assert!(text.contains("different texts of one package"), "{text}");
    let _ = posted;

    // Two packages.
    let output = scratch.run(&["diff", "--json", "posted.json", "undetermined.json"]);
    assert_eq!(output.status.code(), Some(1));
    let result = json(&output);
    assert_eq!(result["outcome"], "different");
    assert_eq!(result["samePackageIdentifier"], false);
    let differing: Vec<&str> = result["components"]
        .as_array()
        .expect("components")
        .iter()
        .filter(|c| c["same"] == false)
        .map(|c| c["path"].as_str().expect("path"))
        .collect();
    assert_eq!(
        differing,
        [
            "decision.json",
            "evidence/bodies.json",
            "evidence/statements.json"
        ]
    );
    assert_eq!(result["stated"][0]["what"], "recorded decision");
    assert_eq!(result["stated"][0]["b"], "UNDETERMINED");
    let text = stdout(&scratch.run(&["diff", "posted.json", "undetermined.json"]));
    assert!(
        text.contains("stated differently (checked by nobody)\n"),
        "{text}"
    );
    assert!(text.ends_with("different packages\n"), "{text}");

    // A package without integrity is not compared.
    scratch.file("broken.json", b"{}");
    let output = scratch.run(&["diff", "posted.json", "broken.json"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr(&output).contains("only packages with integrity are compared"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn replay_verifies_stored_packages_now_and_reuses_nothing() {
    let scratch = Scratch::new("replay");
    scratch.run(&["init"]);
    scratch.file(
        "trust.json",
        registry(&[&evidence_key()])
            .to_canonical_string()
            .as_bytes(),
    );
    scratch.file(
        "other.json",
        registry(&[&issuer_key()]).to_canonical_string().as_bytes(),
    );
    let (posted, _) = scratch.import("posted.json", &Scenario::posted());
    scratch.import("undetermined.json", &undetermined());

    let output = scratch.run(&["replay", "--trust", "trust.json"]);
    let text = stdout(&output);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(text.contains("SUPPORTED reproduced\n"), "{text}");
    assert!(text.contains("UNDETERMINED reproduced\n"), "{text}");
    assert!(
        text.contains(
            "2 package(s) verified now under the supplied registry; 0 refused or damaged."
        ),
        "{text}"
    );

    // A script that needs every package supported says so.
    let output = scratch.run(&[
        "replay",
        "--json",
        "--trust",
        "trust.json",
        "--require-decision",
        "SUPPORTED",
    ]);
    assert_eq!(output.status.code(), Some(4));
    assert_eq!(json(&output)["outcome"], "decision_not_required");
    // Named packages only.
    let output = scratch.run(&[
        "replay",
        "--quiet",
        "--trust",
        "trust.json",
        "--require-decision",
        "SUPPORTED",
        &posted,
    ]);
    assert_eq!(output.status.code(), Some(0));

    // The same packages under a registry that does not hold their signer.
    let output = scratch.run(&["replay", "--json", "--trust", "other.json"]);
    assert_eq!(output.status.code(), Some(1));
    let result = json(&output);
    assert_eq!(result["outcome"], "failed");
    assert!(
        result["packages"]
            .as_array()
            .expect("packages")
            .iter()
            .all(|p| p["status"] == "refused" && p["detail"] == "UNKNOWN_KEY")
    );

    // A recorded decision that does not follow is refused however it was
    // stored, and a registry is not optional.
    let mut overstated = undetermined();
    overstated.outcome = replaced(
        &overstated.outcome,
        &["decision"],
        Some(string("SUPPORTED")),
    );
    overstated.outcome = replaced(
        &overstated.outcome,
        &["requirements", "0", "value"],
        Some(string("TRUE")),
    );
    scratch.import("overstated.json", &overstated);
    let output = scratch.run(&["replay", "--trust", "trust.json"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stdout(&output).contains("refused: DECISION_MISMATCH\n"));
    assert_eq!(scratch.run(&["replay"]).status.code(), Some(2));
}
