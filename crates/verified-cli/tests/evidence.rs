// SPDX-License-Identifier: Apache-2.0

//! `verified evidence chain`, run as a user would run it, on synthetic
//! statements.

#[path = "../../verified-verifier/tests/support/mod.rs"]
mod support;

use std::path::PathBuf;
use std::process::{Command, Output};

use support::{
    Item, Key, STATEMENT_DOMAIN, evidence_key, hash, object, registry, replaced, string,
};
use verified_canonical::Value;

const STREAM: &str = "erp/orders";

/// A directory under the system's temporary directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("verified-cli-ev-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch directory");
        let scratch = Self(dir);
        scratch.file(
            "trust.json",
            &registry(&[&evidence_key()]).to_canonical_string(),
        );
        scratch
    }

    fn file(&self, name: &str, contents: &str) -> String {
        std::fs::write(self.0.join(name), contents).expect("write scratch file");
        name.to_owned()
    }

    /// Statements as a file has them: one per line, with a final line end.
    fn statements(&self, name: &str, statements: &[Value], line_end: &str) -> String {
        let text: String = statements
            .iter()
            .map(|s| s.to_canonical_string() + line_end)
            .collect();
        self.file(name, &text)
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

/// `count` signed statements: steps 0, 1, … of one stream, each naming the
/// one before it.
fn run(key: &Key, count: u32) -> Vec<Value> {
    let mut statements: Vec<Value> = Vec::new();
    for n in 0..count {
        let chain = object([
            ("previous", statements.last().map_or(Value::Null, hash)),
            ("sequence", Value::Integer(i64::from(n).into())),
            ("stream", string(STREAM)),
        ]);
        let item = Item::new(n + 1, key, "erp", string(format!("body {n}")));
        statements.push(replaced(&item.statement(), &["chain"], Some(chain)));
    }
    statements
        .into_iter()
        .map(|statement| {
            object([
                ("signature", key.sign(STATEMENT_DOMAIN, &statement)),
                ("statement", statement),
            ])
        })
        .collect()
}

#[test]
fn a_run_is_verified_and_its_head_continues_the_next_run() {
    let scratch = Scratch::new("continue");
    let signed = run(&evidence_key(), 4);
    let first = scratch.statements("first.jsonl", &signed[..2], "\n");
    let rest = scratch.statements("rest.jsonl", &signed[2..], "\n");

    let output = scratch.run(&[
        "--json",
        "evidence",
        "chain",
        &first,
        "--trust",
        "trust.json",
    ]);
    assert_eq!(
        exit(&output),
        0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result = json(&output);
    assert_eq!(result["outcome"], "verified");
    assert_eq!(result["fromGenesis"], true);
    assert_eq!(
        (result["first"].clone(), result["last"].clone()),
        (0.into(), 1.into())
    );

    // The head, kept as printed, anchors the steps after it.
    let anchor = scratch.file("anchor.json", &result["head"].to_string());
    let args = [
        "--json",
        "evidence",
        "chain",
        &rest,
        "--trust",
        "trust.json",
    ];
    let output = scratch.run(&[&args[..], &["--anchor", &anchor]].concat());
    assert_eq!(
        exit(&output),
        0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result = json(&output);
    assert_eq!(result["fromGenesis"], false);
    assert_eq!(
        (result["first"].clone(), result["last"].clone()),
        (2.into(), 3.into())
    );

    // Without the anchor, the same steps are not a run from the start.
    let output = scratch.run(&args);
    assert_eq!(exit(&output), 1);
    assert_eq!(json(&output)["refusal"]["code"], "CHAIN_GENESIS_INVALID");
}

#[test]
fn what_is_not_one_unbroken_run_is_refused_with_its_code() {
    let scratch = Scratch::new("refused");
    let signed = run(&evidence_key(), 3);
    for (name, statements, code) in [
        (
            "reordered",
            vec![signed[0].clone(), signed[2].clone(), signed[1].clone()],
            "CHAIN_REORDERED",
        ),
        (
            "gap",
            vec![signed[0].clone(), signed[2].clone()],
            "CHAIN_GAP",
        ),
        ("none", vec![], "CHAIN_MISSING"),
    ] {
        let file = scratch.statements(name, &statements, "\n");
        let output = scratch.run(&[
            "--json",
            "evidence",
            "chain",
            &file,
            "--trust",
            "trust.json",
        ]);
        assert_eq!(exit(&output), 1, "{name}");
        assert_eq!(json(&output)["refusal"]["code"], code, "{name}");
    }
}

#[test]
fn a_statement_that_is_not_authentic_is_refused_by_its_line() {
    let scratch = Scratch::new("untrusted");
    let signed = run(&evidence_key(), 2);
    let file = scratch.statements("statements.jsonl", &signed, "\n");
    scratch.file("nobody.json", &registry(&[]).to_canonical_string());
    let output = scratch.run(&[
        "--json",
        "evidence",
        "chain",
        &file,
        "--trust",
        "nobody.json",
    ]);
    assert_eq!(exit(&output), 1);
    let refusal = &json(&output)["refusal"];
    assert!(
        refusal["detail"]
            .as_str()
            .expect("a detail")
            .starts_with("statement 1: "),
        "{refusal}"
    );

    let not_json = scratch.file("broken.jsonl", "{\n");
    let output = scratch.run(&[
        "--json",
        "evidence",
        "chain",
        &not_json,
        "--trust",
        "trust.json",
    ]);
    assert_eq!(exit(&output), 1);
    assert_eq!(json(&output)["refusal"]["code"], "MALFORMED");
}

#[test]
fn an_unusable_anchor_or_registry_means_the_command_could_not_run() {
    let scratch = Scratch::new("unusable");
    let file = scratch.statements("statements.jsonl", &run(&evidence_key(), 1), "\n");
    let anchor = scratch.file("anchor.json", "{\"sequence\":0}");
    let output = scratch.run(&[
        "evidence",
        "chain",
        &file,
        "--trust",
        "trust.json",
        "--anchor",
        &anchor,
    ]);
    assert_eq!(exit(&output), 2);
    let output = scratch.run(&["evidence", "chain", &file, "--trust", "missing.json"]);
    assert_eq!(exit(&output), 2);
}

#[test]
fn lines_may_end_as_windows_ends_them_and_people_are_told_what_is_not_shown() {
    let scratch = Scratch::new("human");
    let file = scratch.statements("statements.jsonl", &run(&evidence_key(), 3), "\r\n");
    let output = scratch.run(&["evidence", "chain", &file, "--trust", "trust.json"]);
    assert_eq!(
        exit(&output),
        0,
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("steps 0 to 2 of erp/orders are consecutive and unaltered"),
        "{text}"
    );
    assert!(text.contains("authentic, not true"), "{text}");
    assert!(text.contains("leave off the end"), "{text}");
}

#[test]
fn the_first_failure_in_line_order_is_the_one_reported() {
    let scratch = Scratch::new("order");
    scratch.file("nobody.json", &registry(&[]).to_canonical_string());
    let signed = run(&evidence_key(), 1);
    // Line 1 is not authentic under this registry; line 2 is not JSON.
    let file = scratch.file(
        "statements.jsonl",
        &format!("{}\n{{\n", signed[0].to_canonical_string()),
    );
    let output = scratch.run(&[
        "--json",
        "evidence",
        "chain",
        &file,
        "--trust",
        "nobody.json",
    ]);
    assert_eq!(exit(&output), 1);
    let refusal = &json(&output)["refusal"];
    assert_ne!(refusal["code"], "MALFORMED", "{refusal}");
    assert!(
        refusal["detail"]
            .as_str()
            .expect("a detail")
            .starts_with("statement 1: "),
        "{refusal}"
    );
}
