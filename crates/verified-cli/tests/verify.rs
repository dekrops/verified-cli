// SPDX-License-Identifier: Apache-2.0

//! The `verified` binary, run as a user would run it, on synthetic packages.

#[path = "../../verified-verifier/tests/support/mod.rs"]
mod support;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use support::{
    Key, Scenario, evidence_key, hash, issuer_key, json, registry, replaced, string, uuid,
};
use verified_canonical::Value;

/// A directory under the system's temporary directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("verified-cli-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch directory");
        Self(dir)
    }

    fn file(&self, name: &str, contents: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, contents).expect("write scratch file");
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn verified() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_verified"));
    // A fixed environment: output must not depend on the developer's.
    command.env_clear().env("LANG", "en_US.UTF-8");
    command
}

fn run(args: &[&str], path: Option<&Path>) -> Output {
    let mut command = verified();
    command.args(args);
    if let Some(path) = path {
        command.arg(path);
    }
    command.output().expect("run verified")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("UTF-8 output")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("UTF-8 output")
}

fn result_json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).expect("JSON on standard output")
}

fn trust_file(scratch: &Scratch, keys: &[&Key]) -> PathBuf {
    scratch.file(
        "registry.json",
        registry(keys).to_canonical_string().as_bytes(),
    )
}

/// Runs `verified verify` with a registry.
fn verify_with(registry: &Path, args: &[&str], package: &Path) -> Output {
    let mut command = verified();
    command
        .arg("verify")
        .arg("--trust")
        .arg(registry)
        .args(args)
        .arg(package);
    command.output().expect("run verified")
}

#[test]
fn without_a_registry_the_report_is_incomplete_and_never_reads_as_verified() {
    let scratch = Scratch::new("incomplete");
    let draft = Scenario::posted().draft();
    let package = scratch.file("package.json", draft.text().as_bytes());
    let commitment = draft.manifest().digest().to_hex();
    let contract = Scenario::posted().contract.digest().to_hex();

    let output = run(&["verify"], Some(&package));
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(stderr(&output), "");
    let expected = format!(
        "\
Work Verification Protocol package (wvp-0.2, draft)
package               wvp:sha-256:{}…
tenant                tenant-test
claim                 {}
package integrity     established
contract              posting-test 1.0.0, sha-256:{}…
evidence signatures   not checked: no trust registry supplied
signer authority      not checked: no trust registry supplied
decision reproduced   not checked: no trust registry supplied
issuer signature      not checked: no trust registry supplied (0 carried)
source truthfulness   NOT established: no check can establish it

incomplete: no trust registry was supplied (--trust), so no signature was checked and the \
decision was not reproduced; the decision the package carries is its issuer's claim
",
        &commitment[..12],
        uuid(0x500),
        &contract[..12],
    );
    assert_eq!(stdout(&output), expected);
}

#[test]
fn with_the_relying_partys_registry_a_package_verifies_completely() {
    let scratch = Scratch::new("complete");
    let draft = Scenario::posted().draft();
    let package = scratch.file("package.json", draft.text().as_bytes());
    let trust = trust_file(&scratch, &[&evidence_key()]);
    let commitment = draft.manifest().digest().to_hex();
    let contract = Scenario::posted().contract.digest().to_hex();

    let output = verify_with(&trust, &[], &package);
    assert_eq!(stderr(&output), "");
    assert_eq!(output.status.code(), Some(0));
    let expected = format!(
        "\
Work Verification Protocol package (wvp-0.2, draft)
package               wvp:sha-256:{}…
tenant                tenant-test
claim                 {}
package integrity     established
contract              posting-test 1.0.0, sha-256:{}…
evidence signatures   established (1 of 1)
signer authority      established under the supplied registry
decision reproduced   SUPPORTED, matches the package
                        {:<28}TRUE
issuer signature      absent
source truthfulness   NOT established: no check can establish it

complete: every protocol check ran; the decision SUPPORTED was reproduced
",
        &commitment[..12],
        uuid(0x500),
        &contract[..12],
        "POSTED",
    );
    assert_eq!(stdout(&output), expected);

    assert_eq!(
        verify_with(&trust, &["--quiet"], &package).status.code(),
        Some(0)
    );

    // A file ends with a line end; the package inside it does not.
    for ending in ["\n", "\r\n"] {
        let text = format!("{}{ending}", draft.text());
        let package = scratch.file("with-line-end.json", text.as_bytes());
        assert_eq!(
            verify_with(&trust, &["--quiet"], &package).status.code(),
            Some(0)
        );
    }

    // A v0.1 package, issuer-signed.
    let mut shipped = Scenario::shipped();
    shipped.issuers = vec![issuer_key()];
    let package = scratch.file("shipped.json", shipped.text().as_bytes());
    let trust = trust_file(&scratch, &[&evidence_key(), &issuer_key()]);
    let output = verify_with(&trust, &[], &package);
    let text = stdout(&output);
    assert_eq!(output.status.code(), Some(0), "{text}");
    assert!(text.contains("(wvp-0.1, draft)"), "{text}");
    assert!(
        text.contains("issuer signature      established (1 of 1)\n"),
        "{text}"
    );
    assert!(
        text.contains(&format!("  {:<28}holds\n", "SUPPORTING_TRANSITION")),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "  {:<28}does not hold\n",
            "CONTRADICTING_TRANSITION"
        )),
        "{text}"
    );
}

#[test]
fn a_reproduced_decision_that_is_not_supported_exits_0_and_says_so() {
    let scratch = Scratch::new("undetermined");
    let agent = Key::new("test-agent-runtime", 3, &["agent"]);
    let mut scenario = Scenario::posted();
    scenario.items[0].key = agent.clone();
    scenario.items[0].source = "agent".to_owned();
    scenario.outcome = json(&format!(
        r#"{{"decision": "UNDETERMINED", "requirements": [{{"id": "POSTED", "value": "UNKNOWN"}}],
            "ignored": ["e-{}"], "conflicts": []}}"#,
        uuid(1)
    ));
    let package = scratch.file("package.json", scenario.text().as_bytes());
    let trust = trust_file(&scratch, &[&agent]);

    let output = verify_with(&trust, &[], &package);
    let text = stdout(&output);
    assert_eq!(output.status.code(), Some(0), "{text}");
    assert!(
        text.contains("decision reproduced   UNDETERMINED, matches the package\n"),
        "{text}"
    );
    assert!(text.contains("1 authentic record(s) ignored"), "{text}");
    assert!(
        text.ends_with("the reproduced decision is UNDETERMINED, so the claim is not supported\n"),
        "{text}"
    );

    let result = result_json(&verify_with(&trust, &["--json"], &package));
    assert_eq!(result["outcome"], "complete");
    let decision = &result["properties"]["decisionReproduced"];
    assert_eq!(decision["status"], "established");
    assert_eq!(decision["decision"], "UNDETERMINED");
    assert_eq!(decision["requirements"][0]["value"], "UNKNOWN");
    assert_eq!(decision["ignored"][0], format!("e-{}", uuid(1)));
}

#[test]
fn verbose_output_carries_full_identifiers_and_component_digests() {
    let scratch = Scratch::new("verbose");
    let draft = Scenario::shipped().draft();
    let package = scratch.file("package.json", draft.text().as_bytes());

    let output = run(&["verify", "--verbose"], Some(&package));
    let text = stdout(&output);
    assert_eq!(output.status.code(), Some(3));
    assert!(text.contains("(wvp-0.1, draft)"), "{text}");
    assert!(
        text.contains(&format!("wvp:sha-256:{}\n", draft.manifest().digest())),
        "{text}"
    );
    for (path, content) in &draft.files {
        let line = format!(
            "{:<26}sha-256:{}",
            path.as_str().expect("a path"),
            content.digest()
        );
        assert!(text.contains(&line), "{text}");
    }
}

#[test]
fn json_output_is_structured_and_has_no_single_validity_flag() {
    let scratch = Scratch::new("json");
    let mut scenario = Scenario::posted();
    scenario.issuers = vec![issuer_key()];
    let draft = scenario.draft();
    let package = scratch.file("package.json", draft.text().as_bytes());

    // Without a registry.
    let output = run(&["verify", "--json"], Some(&package));
    assert_eq!(output.status.code(), Some(3));
    let result = result_json(&output);
    assert_eq!(result["outcome"], "incomplete");
    assert_eq!(result["protocol"], "wvp-0.2");
    assert_eq!(result["protocolStatus"], "draft");
    assert_eq!(
        result["packageId"],
        format!("wvp:sha-256:{}", draft.manifest().digest())
    );
    assert_eq!(result["tenant"], "tenant-test");
    assert_eq!(result["claim"], uuid(0x500));
    assert_eq!(result["contract"]["id"], "posting-test");
    assert_eq!(
        result["contract"]["digest"]["hex"],
        scenario.contract.digest().to_hex()
    );
    assert_eq!(result["components"].as_array().map(Vec::len), Some(6));
    assert_eq!(result["components"][3]["path"], "evidence/bodies.json");
    assert_eq!(
        result["components"][3]["digest"]["hex"],
        draft.files[3].1.digest().to_hex()
    );
    let properties = result["properties"].as_object().expect("properties");
    assert_eq!(properties["packageIntegrity"]["status"], "established");
    for unchecked in [
        "evidenceSignatures",
        "signerAuthority",
        "decisionReproduced",
        "issuerSignature",
    ] {
        assert_eq!(
            properties[unchecked]["status"], "not_checked",
            "{unchecked}"
        );
        assert_eq!(
            properties[unchecked]["reason"], "no_trust_registry",
            "{unchecked}"
        );
    }
    // The decision the package carries is not echoed as if it were a finding.
    assert!(properties["decisionReproduced"].get("decision").is_none());
    assert_eq!(properties["issuerSignature"]["carried"], 1);
    assert_eq!(
        properties["sourceTruthfulness"]["status"],
        "not_established"
    );

    // With one.
    let trust = trust_file(&scratch, &[&evidence_key(), &issuer_key()]);
    let output = verify_with(&trust, &["--json"], &package);
    assert_eq!(output.status.code(), Some(0));
    let result = result_json(&output);
    assert_eq!(result["outcome"], "complete");
    assert!(result.get("note").is_none());
    let properties = result["properties"].as_object().expect("properties");
    for established in [
        "packageIntegrity",
        "evidenceSignatures",
        "signerAuthority",
        "decisionReproduced",
        "issuerSignature",
    ] {
        assert_eq!(
            properties[established]["status"], "established",
            "{established}"
        );
    }
    assert_eq!(properties["decisionReproduced"]["decision"], "SUPPORTED");
    assert_eq!(properties["issuerSignature"]["count"], 1);
    // Complete or not, no check establishes that a source told the truth.
    assert_eq!(
        properties["sourceTruthfulness"]["status"],
        "not_established"
    );
    for flag in ["valid", "verified", "isVerified", "ok", "trusted"] {
        assert!(result.get(flag).is_none(), "{flag}");
    }
}

#[test]
fn a_package_whose_signer_the_registry_does_not_hold_is_refused() {
    let scratch = Scratch::new("unknown-key");
    let package = scratch.file("package.json", Scenario::posted().text().as_bytes());
    // The registry of a relying party who trusts someone else.
    let trust = trust_file(&scratch, &[&issuer_key()]);

    let output = verify_with(&trust, &["--json"], &package);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(result_json(&output)["refusal"]["code"], "UNKNOWN_KEY");

    // A decision that does not follow from the evidence.
    let mut scenario = Scenario::posted();
    scenario.outcome = replaced(
        &scenario.outcome,
        &["decision"],
        Some(string("CONTRADICTED")),
    );
    let package = scratch.file("changed.json", scenario.text().as_bytes());
    let trust = trust_file(&scratch, &[&evidence_key()]);
    let output = verify_with(&trust, &[], &package);
    assert_eq!(output.status.code(), Some(1));
    assert!(stdout(&output).contains("refused               DECISION_MISMATCH\n"));
}

#[test]
fn a_registry_that_cannot_be_used_exits_2_and_says_nothing_about_the_package() {
    let scratch = Scratch::new("bad-registry");
    let package = scratch.file("package.json", Scenario::posted().text().as_bytes());
    let record = evidence_key().record();
    let registries: [(&str, Vec<u8>); 5] = [
        ("not JSON", b"{".to_vec()),
        ("not a registry", b"[]".to_vec()),
        (
            "a misspelt member",
            format!(
                r#"{{"keys":[{}]}}"#,
                replaced(&record, &["revokedAT"], Some(Value::Null)).to_canonical_string()
            )
            .into_bytes(),
        ),
        (
            "unusable key material",
            format!(
                r#"{{"keys":[{}]}}"#,
                replaced(&record, &["publicKey"], Some(string("AAAA"))).to_canonical_string()
            )
            .into_bytes(),
        ),
        (
            "the same key twice",
            format!(
                r#"{{"keys":[{},{}]}}"#,
                record.to_canonical_string(),
                replaced(&record, &["keyId"], Some(string("alias"))).to_canonical_string()
            )
            .into_bytes(),
        ),
    ];
    for (what, bytes) in registries {
        let trust = scratch.file("registry.json", &bytes);
        let output = verify_with(&trust, &["--json"], &package);
        assert_eq!(output.status.code(), Some(2), "{what}");
        let result = result_json(&output);
        assert_eq!(result["outcome"], "error", "{what}");
        assert_eq!(result["error"]["code"], "TRUST_REGISTRY", "{what}");
        assert!(
            stderr(&output).starts_with("error: trust registry "),
            "{what}: {}",
            stderr(&output)
        );
    }
    let output = verify_with(&scratch.0.join("missing.json"), &["--json"], &package);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(result_json(&output)["error"]["code"], "TRUST_REGISTRY");

    // One standard input cannot be both.
    let output = run(&["verify", "--trust", "-", "-"], None);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("cannot both be read from standard input"));
}

#[test]
fn expectations_refuse_a_package_about_something_else() {
    let scratch = Scratch::new("expectations");
    let scenario = Scenario::posted();
    let package = scratch.file("package.json", scenario.text().as_bytes());
    let trust = trust_file(&scratch, &[&evidence_key()]);
    let contract = scenario.contract.digest().to_hex();
    let prefixed = format!("sha-256:{contract}");

    let met = [
        "--expect-tenant",
        "tenant-test",
        "--expect-contract",
        &prefixed,
        "--expect-claim",
        &uuid(0x500),
    ];
    let output = verify_with(&trust, &met, &package);
    let text = stdout(&output);
    assert_eq!(output.status.code(), Some(0), "{text}");
    assert!(
        text.contains("expectations          met (tenant, contract, claim)\n"),
        "{text}"
    );
    let result = result_json(&verify_with(
        &trust,
        &[&met[..], &["--json"]].concat(),
        &package,
    ));
    assert_eq!(result["expectationsMet"]["contract"]["hex"], contract);

    let other = "0".repeat(64);
    let cases: [(&[&str], &str); 4] = [
        (&["--expect-tenant", "tenant-other"], "TENANT_NOT_EXPECTED"),
        (&["--expect-contract", &other], "CONTRACT_NOT_EXPECTED"),
        (&["--expect-claim", "another-claim"], "CLAIM_NOT_EXPECTED"),
        (
            &[
                "--expect-claim",
                "another-claim",
                "--expect-tenant",
                "tenant-other",
            ],
            "TENANT_NOT_EXPECTED",
        ),
    ];
    for (args, code) in cases {
        let output = verify_with(&trust, &[args, &["--json"]].concat(), &package);
        assert_eq!(output.status.code(), Some(1), "{code}");
        assert_eq!(result_json(&output)["refusal"]["code"], code);
    }

    // Not a digest: a usage error, before anything is read.
    let output = verify_with(&trust, &["--expect-contract", "sha-256:abc"], &package);
    assert_eq!(output.status.code(), Some(2));

    // wvp-0.1 defines no expectations; they are not silently dropped.
    let shipped = scratch.file("shipped.json", Scenario::shipped().text().as_bytes());
    let output = verify_with(
        &trust,
        &["--json", "--expect-tenant", "tenant-test"],
        &shipped,
    );
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        result_json(&output)["error"]["code"],
        "EXPECTATIONS_UNDEFINED"
    );
}

#[test]
fn a_refused_package_exits_1_with_its_protocol_code() {
    let scratch = Scratch::new("refused");
    let mut altered = Scenario::posted().draft();
    altered.manifest_files = Some(
        altered
            .files
            .iter()
            .map(|(path, content)| (path.clone(), hash(content)))
            .collect(),
    );
    altered.files[0].1 = Value::Null;
    let mut unknown = Scenario::posted().draft();
    unknown.protocol = support::string("wvp-7.0");
    let spaced = format!("{} ", Scenario::posted().draft().text());

    let text = Scenario::posted().text();
    let cases = [
        // One final line end is the file's; a second, or any other trailing
        // whitespace, makes the text not canonical.
        ("NOT_CANONICAL", format!("{text}\n\n")),
        ("NOT_CANONICAL", format!("{text}\t\n")),
        ("COMPONENT_DIGEST", altered.text()),
        ("UNSUPPORTED_VERSION", unknown.text()),
        ("NOT_CANONICAL", spaced),
        ("NOT_CANONICAL", "{".to_owned()),
    ];
    for (code, text) in cases {
        let package = scratch.file("package.json", text.as_bytes());

        let output = run(&["verify"], Some(&package));
        assert_eq!(output.status.code(), Some(1), "{code}");
        assert!(
            stdout(&output).contains(&format!("refused               {code}\n")),
            "{code}"
        );

        let output = run(&["verify", "--json"], Some(&package));
        assert_eq!(output.status.code(), Some(1), "{code}");
        let result = result_json(&output);
        assert_eq!(result["outcome"], "refused");
        assert_eq!(result["refusal"]["code"], code);
        assert!(result.get("packageId").is_none());

        let output = run(&["verify", "--quiet"], Some(&package));
        assert_eq!(
            (output.status.code(), stdout(&output).as_str()),
            (Some(1), ""),
            "{code}"
        );
    }
}

#[test]
fn requiring_a_protocol_version_refuses_a_package_of_the_other() {
    let scratch = Scratch::new("require");
    let package = scratch.file(
        "package.json",
        Scenario::shipped().draft().text().as_bytes(),
    );

    assert_eq!(
        run(&["verify", "--protocol", "wvp-0.1"], Some(&package))
            .status
            .code(),
        Some(3)
    );
    let output = run(
        &["verify", "--json", "--protocol", "wvp-0.2"],
        Some(&package),
    );
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        result_json(&output)["refusal"]["code"],
        "UNSUPPORTED_VERSION"
    );

    let output = run(&["verify", "--protocol", "wvp-9"], Some(&package));
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr(&output).contains("unknown protocol"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_package_is_read_from_standard_input() {
    let text = Scenario::posted().draft().text();
    let mut child = verified()
        .args(["verify", "--quiet", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run verified");
    child
        .stdin
        .take()
        .expect("piped")
        .write_all(text.as_bytes())
        .expect("write package");
    let output = child.wait_with_output().expect("verified exits");
    assert_eq!(
        (output.status.code(), stdout(&output).as_str()),
        (Some(3), "")
    );
}

#[test]
fn input_that_cannot_be_read_exits_2_and_says_nothing_about_the_package() {
    let scratch = Scratch::new("unreadable");
    let missing = scratch.0.join("missing.json");

    for path in [&missing, &scratch.0] {
        let output = run(&["verify"], Some(path));
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(stdout(&output), "");
        assert!(
            stderr(&output).starts_with("error: cannot "),
            "{}",
            stderr(&output)
        );

        let output = run(&["verify", "--json"], Some(path));
        assert_eq!(output.status.code(), Some(2));
        let result = result_json(&output);
        assert_eq!(result["outcome"], "error");
        assert_eq!(result["error"]["code"], "IO_ERROR");
    }
}

#[test]
fn oversized_input_is_not_examined() {
    let scratch = Scratch::new("oversized");
    let package = scratch.file("huge.json", &vec![b' '; 32 * 1024 * 1024 + 1]);

    let output = run(&["verify", "--json"], Some(&package));
    assert_eq!(output.status.code(), Some(2));
    let result = result_json(&output);
    assert_eq!(result["outcome"], "error");
    assert_eq!(result["error"]["code"], "RESOURCE_LIMIT");
    assert!(
        stderr(&output).contains("not examined"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn deeply_nested_input_is_not_examined_and_does_not_crash() {
    let scratch = Scratch::new("nested");
    let package = scratch.file("deep.json", "[".repeat(100_000).as_bytes());
    let output = run(&["verify", "--json"], Some(&package));
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(result_json(&output)["error"]["code"], "RESOURCE_LIMIT");
}

#[test]
fn output_is_plain_when_not_a_terminal_and_ascii_without_a_utf8_locale() {
    let scratch = Scratch::new("plain");
    let package = scratch.file("package.json", Scenario::posted().draft().text().as_bytes());

    let output = run(&["verify"], Some(&package));
    assert!(
        !stdout(&output).contains('\u{1b}'),
        "no escape sequences when piped"
    );

    let output = verified()
        .env("LANG", "C")
        .arg("verify")
        .arg(&package)
        .output()
        .expect("run");
    let text = stdout(&output);
    assert!(text.is_ascii(), "{text}");
    assert!(text.contains("...\n"), "{text}");
}

#[test]
fn usage_errors_exit_2_and_help_and_version_exit_0() {
    assert_eq!(run(&[], None).status.code(), Some(2));
    assert_eq!(run(&["verify"], None).status.code(), Some(2));
    assert_eq!(run(&["frobnicate"], None).status.code(), Some(2));
    assert_eq!(
        run(&["verify", "--quiet", "--json", "x"], None)
            .status
            .code(),
        Some(2)
    );

    let version = run(&["--version"], None);
    assert_eq!(version.status.code(), Some(0));
    assert_eq!(
        stdout(&version),
        format!("verified {}\n", env!("CARGO_PKG_VERSION"))
    );

    let help = run(&["--help"], None);
    assert_eq!(help.status.code(), Some(0));
    let text = stdout(&help);
    for expected in [
        "Git-like tools for verifiable work.",
        "verify",
        "Exit codes:",
        "draft",
    ] {
        assert!(text.contains(expected), "{expected}");
    }
    let help = run(&["verify", "--help"], None);
    let text = stdout(&help)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for expected in [
        "--trust <REGISTRY>",
        "--expect-contract <SHA-256>",
        "a key inside a package is never trusted",
        "Exit code 0 means every check ran, not that the claim is supported",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
}
