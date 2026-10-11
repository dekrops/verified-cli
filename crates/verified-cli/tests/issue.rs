// SPDX-License-Identifier: Apache-2.0

//! `verified issue` and `verified sign`, run as a user would run them, on
//! the example packages: taking one apart and issuing and signing it again
//! from its parts gives the same bytes.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer as _, SigningKey};

/// The issuer key of the examples: a published test seed, never to be
/// trusted (examples/invoice-posting/README.md).
const ISSUER_SEED: [u8; 32] = [2; 32];
const EVIDENCE_SEED: [u8; 32] = [1; 32];
const PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// A directory under the system's temporary directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("verified-cli-issue-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch directory");
        let scratch = Self(dir);
        std::fs::copy(examples().join("trust.json"), scratch.path("trust.json")).expect("copy");
        scratch
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn write(&self, name: &str, contents: impl AsRef<[u8]>) {
        std::fs::write(self.path(name), contents).expect("write scratch file");
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

fn example(name: &str) -> Vec<u8> {
    std::fs::read(examples().join(name)).expect("an example")
}

fn exit(output: &Output) -> i32 {
    output.status.code().expect("an exit code")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The draft an example package was issued from.
fn draft_of(name: &str) -> serde_json::Value {
    let package: serde_json::Value = serde_json::from_slice(&example(name)).expect("JSON");
    let file = |i: usize| package["files"][i]["content"].clone();
    let (claim, contract, bodies, statements, inputs) =
        (file(0), file(1), file(3), file(4), file(5));
    let value = |v: &serde_json::Value, name: &str| v[name]["value"].clone();
    let evidence: Vec<serde_json::Value> = statements
        .as_array()
        .expect("statements")
        .iter()
        .zip(bodies.as_array().expect("bodies"))
        .map(
            |(statement, body)| serde_json::json!({ "statement": statement, "body": body["body"] }),
        )
        .collect();
    serde_json::json!({
        "tenant": value(&claim, "tenant"),
        "contract": contract,
        "claim": value(&claim, "id"),
        "claimant": value(&claim, "claimant"),
        "inputs": claim["inputs"],
        "submittedAt": value(&claim, "submittedAt"),
        "evidence": evidence,
        "evidenceSet": value(&inputs, "packageId"),
        "ingestedAt": value(&inputs, "ingestedAt"),
        "assembledAt": value(&inputs, "assembledAt"),
        "evaluatedAt": value(&inputs, "evaluatedAt"),
    })
}

fn pem(seed: [u8; 32]) -> String {
    let der = [&PKCS8_PREFIX[..], &seed].concat();
    format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        STANDARD.encode(der)
    )
}

#[test]
fn issuing_and_signing_an_example_from_its_parts_gives_the_same_bytes() {
    let scratch = Scratch::new("roundtrip");
    scratch.write("draft.json", draft_of("supported.json").to_string());
    let output = scratch.run(&[
        "issue",
        "draft.json",
        "--trust",
        "trust.json",
        "-o",
        "out.json",
    ]);
    assert_eq!(exit(&output), 0, "{}", stderr(&output));
    assert_eq!(
        std::fs::read(scratch.path("out.json")).expect("out"),
        example("supported.json")
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("decision reproduced"), "{text}");
    assert!(
        text.contains("a recipient verifies it under their own registry"),
        "{text}"
    );

    scratch.write("issuer.pem", pem(ISSUER_SEED));
    let output = scratch.run(&[
        "sign",
        "out.json",
        "--key-id",
        "test-decision-issuer",
        "--key",
        "issuer.pem",
        "--trust",
        "trust.json",
        "-o",
        "signed.json",
    ]);
    assert_eq!(exit(&output), 0, "{}", stderr(&output));
    assert_eq!(
        std::fs::read(scratch.path("signed.json")).expect("signed"),
        example("supported-issuer-signed.json")
    );
}

#[test]
fn a_signature_made_elsewhere_over_the_signing_input_gives_the_same_bytes() {
    let scratch = Scratch::new("external");
    std::fs::copy(
        examples().join("supported.json"),
        scratch.path("package.json"),
    )
    .expect("copy");
    let output = scratch.run(&["sign", "package.json", "--signing-input-out", "input.bin"]);
    assert_eq!(exit(&output), 0, "{}", stderr(&output));
    let again = scratch.run(&[
        "--json",
        "issue",
        "missing.json",
        "--trust",
        "trust.json",
        "-o",
        "x.json",
    ]);
    assert_eq!(exit(&again), 2);

    // The signer elsewhere: it sees only the bytes to sign.
    let input = std::fs::read(scratch.path("input.bin")).expect("input");
    assert!(input.starts_with(b"verified:wvp-decision:v0.2\n"));
    let signature = SigningKey::from_bytes(&ISSUER_SEED).sign(&input);
    scratch.write(
        "signature.txt",
        STANDARD.encode(signature.to_bytes()) + "\n",
    );

    let output = scratch.run(&[
        "sign",
        "package.json",
        "--key-id",
        "test-decision-issuer",
        "--signature-file",
        "signature.txt",
        "--trust",
        "trust.json",
        "-o",
        "signed.json",
    ]);
    assert_eq!(exit(&output), 0, "{}", stderr(&output));
    assert_eq!(
        std::fs::read(scratch.path("signed.json")).expect("signed"),
        example("supported-issuer-signed.json")
    );

    // The JSON outcome, as docs/sdk/json-output.md names it.
    let output = scratch.run(&[
        "--json",
        "sign",
        "package.json",
        "--key-id",
        "test-decision-issuer",
        "--signature-file",
        "signature.txt",
        "--trust",
        "trust.json",
        "-o",
        "signed-again.json",
    ]);
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(result["outcome"], "signed");
    assert_eq!(
        result["report"]["properties"]["issuerSignature"]["status"],
        "established"
    );
}

#[test]
fn what_a_verifier_would_refuse_is_not_written() {
    let scratch = Scratch::new("refused");
    // Evidence whose body is not the one its statement commits to.
    let mut draft = draft_of("supported.json");
    draft["evidence"][0]["body"]["record"]["fields"]["invoice"] = "INV-2".into();
    scratch.write("draft.json", draft.to_string());
    let output = scratch.run(&[
        "--json",
        "issue",
        "draft.json",
        "--trust",
        "trust.json",
        "-o",
        "out.json",
    ]);
    assert_eq!(exit(&output), 1, "{}", stderr(&output));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(result["outcome"], "refused");
    assert!(!scratch.path("out.json").exists());

    // The evidence key may not sign decisions.
    std::fs::copy(
        examples().join("supported.json"),
        scratch.path("package.json"),
    )
    .expect("copy");
    scratch.write("erp.pem", pem(EVIDENCE_SEED));
    let output = scratch.run(&[
        "--json",
        "sign",
        "package.json",
        "--key-id",
        "test-erp-gateway",
        "--key",
        "erp.pem",
        "--trust",
        "trust.json",
        "-o",
        "signed.json",
    ]);
    assert_eq!(exit(&output), 1, "{}", stderr(&output));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(result["refusal"]["code"], "ISSUER_SIGNATURE_INVALID");
    assert!(!scratch.path("signed.json").exists());
    // Nothing of the key is printed.
    let key_body = STANDARD.encode([&PKCS8_PREFIX[..], &EVIDENCE_SEED].concat());
    let printed = [output.stdout, output.stderr].concat();
    assert!(!String::from_utf8_lossy(&printed).contains(&key_body));
}

#[test]
fn an_existing_file_is_never_overwritten_and_a_bad_draft_cannot_run() {
    let scratch = Scratch::new("files");
    scratch.write("draft.json", draft_of("supported.json").to_string());
    scratch.write("out.json", "keep me");
    let output = scratch.run(&[
        "issue",
        "draft.json",
        "--trust",
        "trust.json",
        "-o",
        "out.json",
    ]);
    assert_eq!(exit(&output), 2);
    assert_eq!(
        std::fs::read(scratch.path("out.json")).expect("out"),
        b"keep me"
    );

    let mut draft = draft_of("supported.json");
    draft["decision"] = "SUPPORTED".into();
    scratch.write("extra.json", draft.to_string());
    let output = scratch.run(&[
        "issue",
        "extra.json",
        "--trust",
        "trust.json",
        "-o",
        "x.json",
    ]);
    assert_eq!(exit(&output), 2);
    assert!(
        stderr(&output).contains("exactly the members"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_refusal_says_what_it_was_reached_under() {
    let scratch = Scratch::new("reached");
    std::fs::copy(
        examples().join("refused-component-digest.json"),
        scratch.path("damaged.json"),
    )
    .expect("copy");
    // No registry is read for the signing input: only the container checks.
    let output = scratch.run(&["sign", "damaged.json", "--signing-input-out", "input.bin"]);
    assert_eq!(exit(&output), 1);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("no registry was read"), "{text}");
    assert!(!text.contains("holding this registry"), "{text}");
    assert!(!scratch.path("input.bin").exists());

    // An unusable registry is reported as one.
    scratch.write("draft.json", draft_of("supported.json").to_string());
    let output = scratch.run(&[
        "--json",
        "issue",
        "draft.json",
        "--trust",
        "missing.json",
        "-o",
        "x.json",
    ]);
    assert_eq!(exit(&output), 2);
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(result["error"]["code"], "TRUST_REGISTRY");
}
