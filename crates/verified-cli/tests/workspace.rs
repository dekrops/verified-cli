// SPDX-License-Identifier: Apache-2.0

//! `init`, `import`, `show`, `log` and `verify <identifier>`, run as a user
//! would run them, on synthetic packages.

#[path = "../../verified-verifier/tests/support/mod.rs"]
mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use support::{Scenario, evidence_key, hash, issuer_key, registry};
use verified_canonical::Value;

/// A directory under the system's temporary directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("verified-cli-ws-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch directory");
        // Compare paths as the tool prints them.
        Self(dir.canonicalize().expect("canonical scratch path"))
    }

    fn file(&self, name: &str, contents: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, contents).expect("write scratch file");
        path
    }

    /// Runs `verified` in this directory.
    fn run(&self, args: &[&str]) -> Output {
        run_in(&self.0, args)
    }
}

fn run_in(directory: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_verified"))
        .env_clear()
        .env("LANG", "en_US.UTF-8")
        .current_dir(directory)
        .args(args)
        .output()
        .expect("run verified")
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

#[test]
fn a_package_is_imported_inspected_and_only_then_verified() {
    let scratch = Scratch::new("flow");
    let scenario = Scenario::posted();
    let draft = scenario.draft();
    let id = format!("wvp:sha-256:{}", draft.manifest().digest());
    // As a file on disk has it: with a final line end.
    scratch.file("package.json", format!("{}\n", draft.text()).as_bytes());
    scratch.file(
        "trust.json",
        registry(&[&evidence_key()])
            .to_canonical_string()
            .as_bytes(),
    );

    let output = scratch.run(&["init"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        stdout(&output),
        format!(
            "Initialized an empty Verified workspace in {}\n\
             It is a cache for inspection, and authoritative for nothing.\n",
            scratch.0.join(".verified").display()
        )
    );
    assert!(stdout(&scratch.run(&["init"])).starts_with("A Verified workspace already exists in "));
    assert!(stdout(&scratch.run(&["log"])).contains("nothing imported yet"));

    // Import: stored, with integrity, and explicitly not verified.
    let output = scratch.run(&["import", "package.json"]);
    let text = stdout(&output);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(text.contains("(wvp-0.2, draft), stored\n"), "{text}");
    assert!(
        text.contains("package integrity     established\n"),
        "{text}"
    );
    assert!(
        text.contains("imported, not verified: importing is not accepting."),
        "{text}"
    );
    assert!(
        text.ends_with(&format!("verified verify {id} --trust <registry>\n")),
        "{text}"
    );
    assert!(
        !text.contains("SUPPORTED"),
        "an import reports no decision: {text}"
    );

    let again = json(&scratch.run(&["import", "--json", "package.json"]));
    assert_eq!(again["outcome"], "imported");
    assert_eq!(again["package"], id);
    assert_eq!(again["alreadyPresent"], true);
    assert_eq!(
        again["properties"]["packageIntegrity"]["status"],
        "established"
    );
    assert_eq!(
        again["properties"]["decisionReproduced"]["status"],
        "not_checked"
    );
    for flag in ["valid", "verified", "accepted", "trusted"] {
        assert!(again.get(flag).is_none(), "{flag}");
    }

    // The history is found from a subdirectory, newest first, and says what
    // it is.
    let nested = scratch.0.join("deeper");
    std::fs::create_dir(&nested).expect("create");
    let output = run_in(&nested, &["log", "--json"]);
    let log = json(&output);
    assert_eq!(log["imports"].as_array().map(Vec::len), Some(2));
    assert_eq!(log["imports"][0]["package"], id);
    assert_eq!(log["damagedRecords"], 0);
    assert!(
        log["note"]
            .as_str()
            .is_some_and(|note| note.contains("unauthenticated"))
    );
    let text = stdout(&scratch.run(&["log"]));
    assert!(text.contains("local and unauthenticated"), "{text}");
    assert!(text.contains("  wvp-0.2\n"), "{text}");
}

#[test]
fn show_reports_what_a_package_states_and_verify_takes_its_identifier() {
    let scratch = Scratch::new("show");
    let draft = Scenario::posted().draft();
    let id = format!("wvp:sha-256:{}", draft.manifest().digest());
    scratch.file("package.json", draft.text().as_bytes());
    scratch.file(
        "trust.json",
        registry(&[&evidence_key()])
            .to_canonical_string()
            .as_bytes(),
    );
    scratch.run(&["init"]);
    scratch.run(&["import", "--quiet", "package.json"]);
    scratch.run(&["import", "--quiet", "package.json"]);

    // Show: what the package states, labelled as that.
    let output = scratch.run(&["show", &id[..20]]);
    let text = stdout(&output);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    for expected in [
        "Stated by the package, and checked by nobody:\n",
        "tenant                tenant-test\n",
        "contract              posting-test 1.0.0, sha-256:",
        "recorded decision     SUPPORTED (the issuer's claim, not reproduced)\n",
        "evidence statements   1 (signatures not checked)\n",
        "from erp  key test-erp-gateway  2026-03-01T10:00:00Z\n",
        "issuer signatures     none\n",
        "imported here         ",
        "not verified. To check it: verified verify ",
    ] {
        assert!(text.contains(expected), "{expected:?} in {text}");
    }
    let shown = json(&scratch.run(&["show", "--json", &id]));
    assert_eq!(shown["package"], id);
    assert_eq!(shown["stated"]["decision"], "SUPPORTED");
    assert_eq!(
        shown["stated"]["status"],
        "stated_by_the_package_not_verified"
    );
    assert_eq!(shown["stated"]["statements"][0]["source"], "erp");
    assert_eq!(shown["importedAtUnix"].as_array().map(Vec::len), Some(2));

    // Verify a stored package by its identifier: nothing without a registry,
    // everything with the relying party's.
    assert_eq!(
        scratch.run(&["verify", "--quiet", &id]).status.code(),
        Some(3)
    );
    let output = scratch.run(&["verify", &id, "--trust", "trust.json"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stdout(&output).contains("decision reproduced   SUPPORTED, matches the package\n"));
}

#[test]
fn workspace_commands_outside_a_workspace_fail_without_creating_one() {
    let scratch = Scratch::new("outside");
    scratch.file("package.json", Scenario::posted().text().as_bytes());
    let id = format!("wvp:sha-256:{}", "0".repeat(64));
    for args in [
        &["import", "package.json"][..],
        &["log"],
        &["show", "abcd"],
        &["verify", &id],
    ] {
        let output = scratch.run(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert_eq!(stdout(&output), "", "{args:?}");
        assert!(
            stderr(&output).contains("not in a Verified workspace"),
            "{}",
            stderr(&output)
        );
    }
    assert!(!scratch.0.join(".verified").exists());
    // Verifying a file needs no workspace.
    assert_eq!(
        scratch
            .run(&["verify", "--quiet", "package.json"])
            .status
            .code(),
        Some(3)
    );
}

#[test]
fn a_package_without_integrity_is_refused_and_not_stored() {
    let scratch = Scratch::new("refused");
    let mut tampered = Scenario::posted().draft();
    tampered.manifest_files = Some(
        tampered
            .files
            .iter()
            .map(|(path, content)| (path.clone(), hash(content)))
            .collect(),
    );
    tampered.files[0].1 = Value::Null;
    scratch.file("tampered.json", tampered.text().as_bytes());
    scratch.run(&["init"]);

    let output = scratch.run(&["import", "--json", "tampered.json"]);
    assert_eq!(output.status.code(), Some(1));
    let result = json(&output);
    assert_eq!(result["outcome"], "refused");
    assert_eq!(result["refusal"]["code"], "COMPONENT_DIGEST");
    assert_eq!(
        json(&scratch.run(&["log", "--json"]))["imports"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );

    let output = scratch.run(&["import", "missing.json"]);
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn names_that_select_no_single_package_are_errors_that_say_why() {
    let scratch = Scratch::new("names");
    let unsigned = Scenario::posted();
    let mut signed = unsigned.clone();
    signed.issuers = vec![issuer_key()];
    scratch.file("unsigned.json", unsigned.text().as_bytes());
    scratch.file("signed.json", signed.text().as_bytes());
    scratch.run(&["init"]);
    let first = json(&scratch.run(&["import", "--json", "unsigned.json"]));
    let second = json(&scratch.run(&["import", "--json", "signed.json"]));
    let package = first["package"].as_str().expect("package").to_owned();
    assert_eq!(second["package"], package);
    assert_eq!(second["alreadyPresent"], false);

    // One package identifier, two texts: neither is silently chosen.
    for command in ["show", "verify"] {
        let output = scratch.run(&[command, &package]);
        let message = stderr(&output);
        assert_eq!(output.status.code(), Some(2), "{command}");
        assert!(
            message.contains("differ in their issuer signatures"),
            "{message}"
        );
        for object in [&first["object"], &second["object"]] {
            assert!(
                message.contains(object.as_str().expect("object")),
                "{message}"
            );
        }
    }
    let signed_object = second["object"].as_str().expect("object");
    let text = stdout(&scratch.run(&["show", signed_object]));
    assert!(
        text.contains(
            "issuer signatures     1 carried, by key test-decision-issuer (not checked)\n"
        ),
        "{text}"
    );

    for (name, expected) in [
        ("abc", "is not a package or object identifier"),
        ("../../etc/passwd", "is not a package or object identifier"),
        ("0000", "no stored package matches"),
    ] {
        let output = scratch.run(&["show", name]);
        assert_eq!(output.status.code(), Some(2), "{name}");
        assert!(
            stderr(&output).contains(expected),
            "{name}: {}",
            stderr(&output)
        );
    }
}

#[test]
fn text_from_a_package_cannot_rewrite_the_terminal() {
    let scratch = Scratch::new("hostile");
    // A source name that clears the screen and prints a decision of its own.
    let mut scenario = Scenario::posted();
    scenario.items[0].source = "erp\u{1b}[2J\rdecision reproduced   SUPPORTED\n\u{202e}".to_owned();
    scratch.file("package.json", scenario.text().as_bytes());
    scratch.run(&["init"]);
    let imported = json(&scratch.run(&["import", "--json", "package.json"]));
    let id = imported["package"].as_str().expect("package");

    let text = stdout(&scratch.run(&["show", id]));
    for raw in ['\u{1b}', '\r', '\u{202e}'] {
        assert!(
            !text.contains(raw),
            "{raw:?} reached the terminal: {text:?}"
        );
    }
    assert!(
        text.contains(r"from erp\u{1b}[2J\u{d}decision reproduced   SUPPORTED\u{a}\u{202e}  key"),
        "{text}"
    );
    // The statement stays on its own, single line.
    assert_eq!(
        text.lines()
            .filter(|line| line.starts_with("decision reproduced"))
            .count(),
        0
    );
}

#[test]
fn a_damaged_stored_package_is_reported_and_not_shown() {
    let scratch = Scratch::new("damaged");
    scratch.file("package.json", Scenario::posted().text().as_bytes());
    scratch.run(&["init"]);
    let imported = json(&scratch.run(&["import", "--json", "package.json"]));
    let id = imported["package"].as_str().expect("package");
    let hex = id.trim_start_matches("wvp:sha-256:");
    let object = imported["object"]
        .as_str()
        .expect("object")
        .trim_start_matches("object:sha-256:");
    let path = scratch
        .0
        .join(".verified/packages")
        .join(&hex[..2])
        .join(&hex[2..])
        .join(object);
    let text = std::fs::read_to_string(&path).expect("read");
    std::fs::write(&path, text.replace("INV-1", "INV-2")).expect("write");

    for command in ["show", "verify"] {
        let output = scratch.run(&[command, id]);
        assert_eq!(output.status.code(), Some(2), "{command}");
        assert_eq!(stdout(&output), "", "{command}");
        assert!(
            stderr(&output).contains("is damaged"),
            "{}",
            stderr(&output)
        );
    }
}
