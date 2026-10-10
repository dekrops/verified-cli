//! The `verified` binary, run as a user would run it, on synthetic packages.

#[path = "../../verified-verifier/tests/support/mod.rs"]
mod support;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use support::{Draft, hash, json};
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

#[test]
fn a_consistent_container_is_reported_as_incomplete_never_as_verified() {
    let scratch = Scratch::new("incomplete");
    let draft = Draft::consistent("wvp-0.2");
    let package = scratch.file("package.json", draft.text().as_bytes());
    let commitment = draft.manifest().digest().to_hex();

    let output = run(&["verify"], Some(&package));
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(stderr(&output), "");
    let expected = format!(
        "\
Work Verification Protocol package (wvp-0.2, draft)
package               wvp:sha-256:{}…
container             consistent: canonical text, versions, component set, digests, commitment
component shapes      not checked: not implemented in this version
package integrity     NOT established: component shapes were not checked
evidence signatures   not checked: not implemented in this version
signer authority      not checked: not implemented in this version
decision reproduced   not checked: not implemented in this version
issuer signature      not checked: not implemented in this version
source truthfulness   NOT established: no check can establish it

incomplete: this version runs protocol steps 1 to 6 of 13; the package was not refused and is not verified
",
        &commitment[..12]
    );
    assert_eq!(stdout(&output), expected);
}

#[test]
fn verbose_output_carries_full_identifiers_and_component_digests() {
    let scratch = Scratch::new("verbose");
    let draft = Draft::consistent("wvp-0.1");
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
    let mut draft = Draft::consistent("wvp-0.2");
    draft.signatures = json(r#"[{"encoded":"AA==","keyId":"untrusted","scheme":"Ed25519"}]"#);
    let package = scratch.file("package.json", draft.text().as_bytes());

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
    assert_eq!(result["issuerSignaturesCarried"], 1);
    assert_eq!(result["components"].as_array().map(Vec::len), Some(6));
    assert_eq!(result["components"][3]["path"], "evidence/bodies.json");
    assert_eq!(
        result["components"][3]["digest"]["hex"],
        draft.files[3].1.digest().to_hex()
    );

    let properties = result["properties"].as_object().expect("properties");
    assert_eq!(properties["container"]["status"], "established");
    for unchecked in [
        "componentShapes",
        "packageIntegrity",
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
            properties[unchecked]["reason"], "not_implemented",
            "{unchecked}"
        );
    }
    assert_eq!(
        properties["sourceTruthfulness"]["status"],
        "not_established"
    );
    for flag in ["valid", "verified", "isVerified", "ok", "trusted"] {
        assert!(result.get(flag).is_none(), "{flag}");
    }
}

#[test]
fn a_refused_package_exits_1_with_its_protocol_code() {
    let scratch = Scratch::new("refused");
    let mut altered = Draft::consistent("wvp-0.2");
    altered.manifest_files = Some(
        altered
            .files
            .iter()
            .map(|(path, content)| (path.clone(), hash(content)))
            .collect(),
    );
    altered.files[0].1 = Value::Null;
    let mut unknown = Draft::consistent("wvp-0.2");
    unknown.protocol = support::string("wvp-7.0");
    let spaced = format!("{} ", Draft::consistent("wvp-0.2").text());

    let cases = [
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
        Draft::consistent("wvp-0.1").text().as_bytes(),
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
    let text = Draft::consistent("wvp-0.2").text();
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
    let package = scratch.file(
        "package.json",
        Draft::consistent("wvp-0.2").text().as_bytes(),
    );

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
    assert!(text.contains("never exits 0"), "{text}");
}
