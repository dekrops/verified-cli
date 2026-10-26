// SPDX-License-Identifier: Apache-2.0

//! `verified approval verify`, run as a user would run it, on a synthetic
//! approval signed by an Ed25519 key standing in for a passkey.

use std::path::PathBuf;
use std::process::{Command, Output};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer as _, SigningKey};
use verified_canonical::{Limits, Sha256Digest, parse};

const RP: &str = "approvals.test";
const ORIGIN: &str = "https://approvals.test";

/// A directory under the system's temporary directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "verified-cli-approval-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch directory");
        Self(dir)
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_verified"))
            .env_clear()
            .env("LANG", "en_US.UTF-8")
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

fn sha256(bytes: &[u8]) -> [u8; 32] {
    *Sha256Digest::of(bytes).as_bytes()
}

/// An approval signed for `rp` from `origin`, as a passkey would sign it.
fn approval(rp: &str, origin: &str) -> String {
    let key = SigningKey::from_bytes(&[7; 32]);
    let shown = r#"{"contract":"sha-256:cccc","view":{"summary":["Only the finance lead approves finance."]}}"#;
    let shown_digest = parse(shown.as_bytes(), &Limits::DEFAULT)
        .expect("the snapshot parses")
        .digest()
        .to_hex();
    let statement = format!(
        r#"{{"approver":"approver-1","contract":"sha-256:cccc","issuedAt":"2026-10-26T12:00:00Z","nonce":"n-1","repository":"example/repository","shown":"sha-256:{shown_digest}","tenant":"tenant-1","type":"verified.contract-approval/1"}}"#
    );
    let challenge = sha256(statement.as_bytes());
    let client = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"{origin}"}}"#,
        URL_SAFE_NO_PAD.encode(challenge)
    );
    let mut data = sha256(rp.as_bytes()).to_vec();
    data.extend_from_slice(&[0x05, 0, 0, 0, 1]);
    let mut message = data.clone();
    message.extend_from_slice(&sha256(client.as_bytes()));
    let signature = key.sign(&message).to_bytes();
    let mut spki = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    spki.extend_from_slice(key.verifying_key().as_bytes());
    let b = |bytes: &[u8]| URL_SAFE_NO_PAD.encode(bytes);
    format!(
        r#"{{"statement":{statement},"assertion":{{"credentialId":"credential-0001","authenticatorData":"{}","clientDataJSON":"{}","signature":"{}"}},"key":{{"credentialId":"credential-0001","publicKey":"{}","algorithm":-8}},"rpId":"{rp}","shown":{shown}}}
"#,
        b(&data),
        b(client.as_bytes()),
        b(&signature),
        b(&spki)
    )
}

fn exit(output: &Output) -> i32 {
    output.status.code().expect("an exit code")
}

#[test]
fn a_valid_approval_is_reported_with_what_it_names() {
    let scratch = Scratch::new("valid");
    std::fs::write(scratch.0.join("approval.json"), approval(RP, ORIGIN)).expect("write");
    let output = scratch.run(&[
        "--json",
        "approval",
        "verify",
        "approval.json",
        "--rp-id",
        RP,
        "--origin",
        ORIGIN,
    ]);
    assert_eq!(
        exit(&output),
        0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(report["outcome"], "valid");
    assert_eq!(report["approver"], "approver-1");
    assert_eq!(report["contract"], "sha-256:cccc");
    assert_eq!(report["algorithm"], -8);
}

#[test]
fn an_approval_from_another_origin_or_relying_party_is_refused() {
    let scratch = Scratch::new("refused");
    std::fs::write(
        scratch.0.join("origin.json"),
        approval(RP, "https://elsewhere.test"),
    )
    .expect("write");
    std::fs::write(
        scratch.0.join("rp.json"),
        approval("elsewhere.test", ORIGIN),
    )
    .expect("write");
    for (file, code) in [("origin.json", "ORIGIN"), ("rp.json", "RELYING_PARTY")] {
        let output = scratch.run(&[
            "--json", "approval", "verify", file, "--rp-id", RP, "--origin", ORIGIN,
        ]);
        assert_eq!(exit(&output), 1, "{file}");
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
        assert_eq!(report["refusal"]["code"], code, "{file}");
    }
}

#[test]
fn a_file_that_cannot_be_read_is_a_usage_error() {
    let scratch = Scratch::new("missing");
    let output = scratch.run(&[
        "approval",
        "verify",
        "absent.json",
        "--rp-id",
        RP,
        "--origin",
        ORIGIN,
    ]);
    assert_eq!(exit(&output), 2);
    assert_eq!(output.stdout, Vec::<u8>::new());
    assert!(String::from_utf8_lossy(&output.stderr).contains("absent.json"));
}
