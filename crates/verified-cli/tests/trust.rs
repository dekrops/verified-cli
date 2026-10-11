// SPDX-License-Identifier: Apache-2.0

//! `verified trust`, run as a user would run it: a registry written with it
//! is one `verify` accepts, and it never writes one `verify` would not.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const ISSUED: [&str; 2] = ["supported.json", "supported-issuer-signed.json"];

/// A directory under the system's temporary directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("verified-cli-trust-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch directory");
        Self(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
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

fn examples() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/invoice-posting")
}

fn exit(output: &Output) -> i32 {
    output.status.code().expect("an exit code")
}

fn json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).expect("JSON output")
}

/// The example registry's records, as `trust add` arguments.
fn example_keys() -> Vec<Vec<String>> {
    let text = std::fs::read_to_string(examples().join("trust.json")).expect("trust.json");
    let registry: serde_json::Value = serde_json::from_str(&text).expect("JSON");
    let value =
        |key: &serde_json::Value, name: &str| key[name]["value"].as_str().map(str::to_owned);
    registry["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .map(|key| {
            let mut args = vec![
                "--key-id".to_owned(),
                key["keyId"].as_str().expect("keyId").to_owned(),
                "--public-key".to_owned(),
                key["publicKey"].as_str().expect("publicKey").to_owned(),
                "--issuer".to_owned(),
                value(key, "issuer").expect("issuer"),
                "--tenant".to_owned(),
                value(key, "tenant").expect("tenant"),
                "--valid-from".to_owned(),
                value(key, "validFrom").expect("validFrom"),
            ];
            for source in key["sources"].as_array().expect("sources") {
                args.push("--source".to_owned());
                args.push(source.as_str().expect("source").to_owned());
            }
            args
        })
        .collect()
}

fn add(scratch: &Scratch, registry: &str, args: &[String]) -> Output {
    let mut all = vec!["trust", "add", registry];
    all.extend(args.iter().map(String::as_str));
    scratch.run(&all)
}

#[test]
fn a_registry_written_with_trust_add_verifies_what_the_example_registry_does() {
    let scratch = Scratch::new("rebuild");
    assert_eq!(exit(&scratch.run(&["trust", "init", "trust.json"])), 0);
    for args in example_keys() {
        let output = add(&scratch, "trust.json", &args);
        assert_eq!(
            exit(&output),
            0,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    for name in ISSUED {
        let package = examples().join(name);
        let package = package.to_str().expect("a UTF-8 path");
        let ours = scratch.run(&["--json", "verify", package, "--trust", "trust.json"]);
        let example = examples().join("trust.json");
        let theirs = scratch.run(&[
            "--json",
            "verify",
            package,
            "--trust",
            example.to_str().expect("a UTF-8 path"),
        ]);
        assert_eq!(exit(&ours), 0, "{name}");
        assert_eq!(json(&ours), json(&theirs), "{name}");
    }

    let shown = scratch.run(&["--json", "trust", "show", "trust.json"]);
    assert_eq!(exit(&shown), 0);
    let shown = json(&shown);
    assert_eq!(shown["outcome"], "usable");
    let keys = shown["keys"].as_array().expect("keys");
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0]["validFrom"], "2026-01-01T00:00:00Z");
    assert_eq!(keys[1]["maySignDecisions"], true);
}

#[test]
fn a_revoked_key_no_longer_verifies_what_it_signed_after_the_revocation() {
    let scratch = Scratch::new("revoke");
    scratch.run(&["trust", "init", "trust.json"]);
    for args in example_keys() {
        add(&scratch, "trust.json", &args);
    }
    // The example's evidence is observed on 2026-03-01.
    let output = scratch.run(&[
        "trust",
        "revoke",
        "trust.json",
        "test-erp-gateway",
        "--at",
        "2026-02-01T00:00:00Z",
    ]);
    assert_eq!(
        exit(&output),
        0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let package = examples().join("supported.json");
    let verified = scratch.run(&[
        "--json",
        "verify",
        package.to_str().expect("a UTF-8 path"),
        "--trust",
        "trust.json",
    ]);
    assert_eq!(exit(&verified), 1);
    assert_eq!(json(&verified)["outcome"], "refused");

    // A second revocation changes nothing.
    let before = std::fs::read(scratch.path("trust.json")).expect("registry");
    let again = scratch.run(&[
        "trust",
        "revoke",
        "trust.json",
        "test-erp-gateway",
        "--at",
        "2026-03-01T00:00:00Z",
    ]);
    assert_eq!(exit(&again), 2);
    assert_eq!(
        std::fs::read(scratch.path("trust.json")).expect("registry"),
        before
    );
}

#[test]
fn a_pem_public_key_is_read_and_a_private_key_is_refused_without_printing_it() {
    let scratch = Scratch::new("pem");
    scratch.run(&["trust", "init", "trust.json"]);
    let mut args = example_keys().remove(0);
    let base64 = args[3].clone();
    let pem = format!("-----BEGIN PUBLIC KEY-----\n{base64}\n-----END PUBLIC KEY-----\n");
    std::fs::write(scratch.path("erp.pub"), pem).expect("write");
    args.splice(2..4, ["--public-key-file".to_owned(), "erp.pub".to_owned()]);
    let output = add(&scratch, "trust.json", &args);
    assert_eq!(
        exit(&output),
        0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let written = std::fs::read_to_string(scratch.path("trust.json")).expect("registry");
    assert!(written.contains(&base64));

    let secret = "MC4CAQAwBQYDK2VwBCIEIPRIVATEMATERIALNOTREALLYAKEYATALL0000000";
    let private = format!("-----BEGIN PRIVATE KEY-----\n{secret}\n-----END PRIVATE KEY-----\n");
    std::fs::write(scratch.path("erp.key"), private).expect("write");
    args[1] = "another".to_owned();
    args[3] = "erp.key".to_owned();
    let output = add(&scratch, "trust.json", &args);
    assert_eq!(exit(&output), 2);
    let printed = [output.stdout, output.stderr].concat();
    let printed = String::from_utf8_lossy(&printed);
    assert!(printed.contains("private key"), "{printed}");
    assert!(!printed.contains(secret), "{printed}");
}

#[test]
fn nothing_verify_would_refuse_is_written() {
    let scratch = Scratch::new("refuse");
    scratch.run(&["trust", "init", "trust.json"]);
    // An existing registry is not overwritten.
    assert_eq!(exit(&scratch.run(&["trust", "init", "trust.json"])), 2);

    let keys = example_keys();
    add(&scratch, "trust.json", &keys[0]);
    let before = std::fs::read(scratch.path("trust.json")).expect("registry");
    let mut alias = keys[0].clone();
    alias[1] = "alias".to_owned();
    let mut bad_time = keys[1].clone();
    let at = bad_time
        .iter()
        .position(|a| a == "--valid-from")
        .expect("--valid-from");
    bad_time[at + 1] = "2026-01-01".to_owned();
    let mut bad_key = keys[1].clone();
    bad_key[3] = "bm90IGEga2V5".to_owned();
    for (what, args) in [("alias", alias), ("time", bad_time), ("key", bad_key)] {
        let output = add(&scratch, "trust.json", &args);
        assert_eq!(exit(&output), 2, "{what}");
        assert_eq!(
            std::fs::read(scratch.path("trust.json")).expect("registry"),
            before,
            "{what}: the file changed"
        );
    }

    std::fs::write(
        scratch.path("broken.json"),
        "{\"keys\":[{\"keyId\":\"x\"}]}",
    )
    .expect("write");
    let shown = scratch.run(&["--json", "trust", "show", "broken.json"]);
    assert_eq!(exit(&shown), 1);
    assert_eq!(json(&shown)["outcome"], "unusable");
}
