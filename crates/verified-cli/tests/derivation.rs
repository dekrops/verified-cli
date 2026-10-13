// SPDX-License-Identifier: Apache-2.0

//! `verified derivation`, run as a user would run it, on the example
//! packages of `examples/derivation-replay`.

use std::path::PathBuf;
use std::process::{Command, Output};

fn example(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/derivation-replay")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_verified"))
        .env_clear()
        .env("LANG", "en_US.UTF-8")
        // Windows needs its system directory to start a process; elsewhere
        // the variable is absent and nothing is added.
        .envs(std::env::var_os("SYSTEMROOT").map(|root| ("SYSTEMROOT", root)))
        .args(args)
        .output()
        .expect("run verified")
}

fn json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).expect("JSON on stdout")
}

#[test]
fn a_package_is_reproduced_from_its_evidence() {
    let output = run(&[
        "--json",
        "derivation",
        "replay",
        &example("01-allowed.json"),
        "--trust",
        &example("trust.json"),
    ]);
    assert_eq!(output.status.code(), Some(0));
    let report = json(&output);
    assert_eq!(report["outcome"], "reproduced");
    assert_eq!(report["draft"], true);
    assert_eq!(report["decision"], "SUPPORTED");
    assert_eq!(report["authorization"][0]["outcome"], "ALLOW");
    assert_eq!(
        report["authorization"][0]["diagnostics"]["engineDecision"],
        "Allow"
    );
    assert_eq!(report["bindings"][0]["requirement"], "APPROVAL_AUTHORIZED");
    // No member says more than was checked.
    for forbidden in ["valid", "verified", "ok", "trusted"] {
        assert!(report.get(forbidden).is_none(), "{forbidden}");
    }
}

#[test]
fn a_presented_result_the_evidence_does_not_yield_is_not_reproduced() {
    let output = run(&[
        "--json",
        "derivation",
        "replay",
        &example("25-outcome-altered.json"),
        "--trust",
        &example("trust.json"),
    ]);
    assert_eq!(output.status.code(), Some(1));
    let report = json(&output);
    assert_eq!(report["outcome"], "not-reproduced");
    assert_eq!(report["stage"], "DERIVATION");
    assert!(
        report["detail"][0]
            .as_str()
            .expect("detail")
            .contains("computed \"DENY\"")
    );
}

#[test]
fn an_altered_statement_fails_before_anything_is_computed() {
    let output = run(&[
        "--json",
        "derivation",
        "replay",
        &example("20-statement-altered.json"),
        "--trust",
        &example("trust.json"),
    ]);
    assert_eq!(output.status.code(), Some(1));
    let report = json(&output);
    assert_eq!(
        (report["stage"].as_str(), report["code"].as_str()),
        (Some("EVIDENCE"), Some("SIGNATURE_INVALID"))
    );
}

#[test]
fn an_unusable_registry_and_an_unreadable_package_have_their_own_codes() {
    let registry = run(&[
        "--json",
        "derivation",
        "replay",
        &example("01-allowed.json"),
        "--trust",
        "no-such-file.json",
    ]);
    assert_eq!(registry.status.code(), Some(2));
    assert_eq!(json(&registry)["error"]["code"], "TRUST_REGISTRY");
    let package = run(&[
        "--json",
        "derivation",
        "replay",
        "no-such-file.json",
        "--trust",
        &example("trust.json"),
    ]);
    assert_eq!(package.status.code(), Some(2));
    assert_eq!(json(&package)["error"]["code"], "INPUT");
}

#[test]
fn inspect_checks_nothing_and_says_so() {
    let output = run(&[
        "--json",
        "derivation",
        "inspect",
        &example("02-denied.json"),
    ]);
    assert_eq!(output.status.code(), Some(0));
    let report = json(&output);
    assert_eq!(report["checked"], "nothing");
    assert_eq!(
        report["presented"]["core"]["result"]["decision"],
        "CONTRADICTED"
    );
}

#[test]
fn compare_reads_only_what_both_must_agree_on() {
    let same = run(&[
        "--json",
        "derivation",
        "compare",
        &example("01-allowed.json"),
        &example("14-statements-in-another-order.json"),
    ]);
    assert_eq!(same.status.code(), Some(0));
    assert_eq!(json(&same)["outcome"], "equal");
    let other = run(&[
        "--json",
        "derivation",
        "compare",
        &example("01-allowed.json"),
        &example("02-denied.json"),
    ]);
    assert_eq!(other.status.code(), Some(1));
    assert!(
        json(&other)["differing"]
            .as_array()
            .expect("differing")
            .iter()
            .any(|m| m == "result")
    );
}

#[test]
fn cedars_own_answer_is_shown_beside_what_was_made_of_it() {
    let output = run(&[
        "--json",
        "derivation",
        "replay",
        &example("09-evaluation-error.json"),
        "--trust",
        &example("trust.json"),
    ]);
    assert_eq!(output.status.code(), Some(0));
    let authorization = &json(&output)["authorization"][0];
    // Cedar skipped an errored policy and allowed. That is reported, and decides nothing.
    assert_eq!(authorization["diagnostics"]["engineDecision"], "Allow");
    assert_eq!(authorization["outcome"], "UNDETERMINED");
    assert_eq!(
        authorization["diagnostics"]["interpretation"]["reasons"][0],
        "EVALUATION_ERROR"
    );
}
