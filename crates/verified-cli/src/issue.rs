// SPDX-License-Identifier: Apache-2.0

//! `verified issue` and `verified sign`: producing a package and standing
//! behind its decision. Every rule is in `verified_verifier::issue`, which
//! returns a package only if a verifier holding the caller's registry
//! accepts it; this reads files, signs with a local key if asked, and
//! writes.

use std::io::Write as _;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::json;
use verified_canonical::{Limits, Value};
use verified_verifier::issue::{
    Countersignature, Draft, IssueError, Issued, countersign, decision_signing_input,
    issue as issue_package,
};
use zeroize::Zeroizing;

use crate::cli::{Issue, Sign};
use crate::exit::Exit;
use crate::input::{self, InputError};
use crate::render::{Mode, Output, Row, Tone};
use crate::verify::{failed, json_file, not_examined, package_text, registry};

const TITLE: &str = "Issuing";

/// The DER of an Ed25519 private key in PKCS #8 (RFC 8410), before its
/// 32-byte seed. It is the only form read: anything else is refused.
const PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

const DRAFT_MEMBERS: [&str; 11] = [
    "assembledAt",
    "claim",
    "claimant",
    "contract",
    "evaluatedAt",
    "evidence",
    "evidenceSet",
    "ingestedAt",
    "inputs",
    "submittedAt",
    "tenant",
];

fn read(path: &Path, max: usize) -> Result<Vec<u8>, String> {
    match input::read(path, max) {
        Ok(bytes) => Ok(bytes),
        Err(InputError::Io(error)) => Err(format!("{error:#}")),
        Err(InputError::TooLarge(limit)) => Err(format!("{}: {limit}", path.display())),
    }
}

/// Writes `bytes` to a new file at `path`. An existing file is never
/// overwritten.
fn create(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::AlreadyExists => {
                format!("{} exists; nothing was written", path.display())
            }
            _ => format!("cannot create {}: {error}", path.display()),
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot write {}: {error}", path.display()))
}

/// The members of a draft, checked for shape; the library checks the rest.
fn draft<'a>(
    value: &'a Value,
    evidence: &'a mut Vec<(&'a Value, &'a Value)>,
) -> Result<Draft<'a>, String> {
    let object = value
        .as_object()
        .filter(|o| o.has_exactly(&DRAFT_MEMBERS))
        .ok_or_else(|| {
            format!("a draft is an object with exactly the members {DRAFT_MEMBERS:?}")
        })?;
    let member = |name: &str| object.get(name).unwrap_or(&Value::Null);
    let text = |name: &'static str| {
        member(name)
            .as_str()
            .ok_or_else(|| format!("the draft's {name} is not text"))
    };
    let items = member("evidence")
        .as_array()
        .ok_or("the draft's evidence is not a list")?;
    for (i, item) in items.iter().enumerate() {
        let pair = item
            .as_object()
            .filter(|o| o.has_exactly(&["body", "statement"]))
            .ok_or_else(|| format!("evidence {i} is not exactly {{ statement, body }}"))?;
        let (Some(statement), Some(body)) = (pair.get("statement"), pair.get("body")) else {
            unreachable!("both members were checked")
        };
        evidence.push((statement, body));
    }
    Ok(Draft {
        tenant: text("tenant")?,
        contract: member("contract"),
        claim: text("claim")?,
        claimant: text("claimant")?,
        inputs: member("inputs"),
        submitted_at: text("submittedAt")?,
        evidence,
        evidence_set: text("evidenceSet")?,
        ingested_at: text("ingestedAt")?,
        assembled_at: text("assembledAt")?,
        evaluated_at: text("evaluatedAt")?,
    })
}

/// What a refusal was reached under: the caller's registry, or the
/// container checks alone.
#[derive(Clone, Copy)]
enum Checked {
    UnderRegistry,
    ContainerOnly,
}

/// Reports a package that was not produced.
fn not_issued(out: &mut Output, error: IssueError, checked: Checked) -> Exit {
    match error {
        IssueError::Refused(refusal) => {
            match out.mode {
                Mode::Quiet => {}
                Mode::Json => out.json(&json!({
                    "outcome": "refused",
                    "refusal": { "code": refusal.code.as_str(), "detail": refusal.detail },
                })),
                Mode::Human => {
                    out.heading(TITLE);
                    out.rows(&[
                        Row::new("not issued", Tone::Negative, refusal.code.as_str()),
                        Row::new("", Tone::Plain, &refusal.detail),
                    ]);
                    out.line("");
                    out.line(match checked {
                        Checked::UnderRegistry => {
                            "A verifier holding this registry would refuse the package, so none \
                             was written."
                        }
                        Checked::ContainerOnly => {
                            "The package fails its container checks; no registry was read, and \
                             nothing was written."
                        }
                    });
                }
            }
            Exit::Refused
        }
        IssueError::Limit(limit) => not_examined(out, limit),
        other => failed(out, "INPUT", &other.to_string()),
    }
}

/// The registry a command checks its result under.
fn trust(path: &Path) -> Result<verified_verifier::Trust, (&'static str, String)> {
    registry(path, &Limits::DEFAULT).map_err(|message| ("TRUST_REGISTRY", message))
}

/// Writes an issued package and reports it.
fn written(out: &mut Output, issued: &Issued, path: &Path, what: &str) -> Exit {
    if let Err(message) = create(path, issued.package.as_bytes()) {
        return failed(out, "IO_ERROR", &message);
    }
    let report = &issued.report;
    match out.mode {
        Mode::Quiet => {}
        Mode::Json => out.json(&json!({
            "outcome": what.to_lowercase(),
            "output": path,
            "package": report.package_id.to_string(),
            "report": crate::verify::output_json(&report.to_value()),
        })),
        Mode::Human => {
            crate::verify::human(out, report, report.is_complete());
            out.line("");
            out.line(&format!(
                "{what} to {}. This is your statement: a recipient verifies it under their own \
                 registry.",
                path.display()
            ));
        }
    }
    Exit::Complete
}

pub(crate) fn issue(command: &Issue, out: &mut Output) -> Exit {
    let read = trust(&command.trust).and_then(|trust| {
        let draft = json_file(&command.draft, "draft", &Limits::DEFAULT);
        Ok((draft.map_err(|message| ("INPUT", message))?, trust))
    });
    let (value, trust) = match read {
        Ok(read) => read,
        Err((code, message)) => return failed(out, code, &message),
    };
    let mut evidence = Vec::new();
    let draft = match draft(&value, &mut evidence) {
        Ok(draft) => draft,
        Err(message) => {
            return failed(
                out,
                "INPUT",
                &format!("{}: {message}", command.draft.display()),
            );
        }
    };
    match issue_package(&draft, &trust) {
        Ok(issued) => written(out, &issued, &command.output, "Issued"),
        Err(error) => not_issued(out, error, Checked::UnderRegistry),
    }
}

/// The signing key in a PEM PKCS #8 file. Nothing read from it is printed.
fn private_key(path: &Path) -> Result<SigningKey, String> {
    let name = path.display();
    let bytes = Zeroizing::new(read(path, 64 * 1024)?);
    // Borrowed, never copied: every copy of the key would need wiping.
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| format!("{name} is not an unencrypted PEM private key"))?;
    let body = Zeroizing::new(
        text.split_once("-----BEGIN PRIVATE KEY-----")
            .and_then(|(_, rest)| rest.split_once("-----END PRIVATE KEY-----"))
            .map(|(body, _)| body.split_whitespace().collect::<String>())
            .ok_or_else(|| {
                format!(
                    "{name} is not an unencrypted PEM private key (-----BEGIN PRIVATE KEY-----)"
                )
            })?,
    );
    let der = Zeroizing::new(
        STANDARD
            .decode(body.as_bytes())
            .map_err(|_| format!("{name}: the key is not standard base64"))?,
    );
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
        der.strip_prefix(&PKCS8_PREFIX)
            .and_then(|seed| seed.try_into().ok())
            .ok_or_else(|| format!("{name} is not an Ed25519 private key"))?,
    );
    Ok(SigningKey::from_bytes(&seed))
}

pub(crate) fn sign(command: &Sign, out: &mut Output) -> Exit {
    let package = match read(&command.package, Limits::DEFAULT.max_bytes) {
        Ok(bytes) => bytes,
        Err(message) => return failed(out, "INPUT", &message),
    };
    let package = package_text(&package);
    let input = match decision_signing_input(package) {
        Ok(input) => input,
        Err(rejection) => {
            return not_issued(out, IssueError::from(rejection), Checked::ContainerOnly);
        }
    };

    if let Some(path) = &command.signing_input_out {
        if let Err(message) = create(path, &input) {
            return failed(out, "IO_ERROR", &message);
        }
        match out.mode {
            Mode::Quiet => {}
            Mode::Json => out
                .json(&json!({ "outcome": "signing_input", "output": path, "bytes": input.len() })),
            Mode::Human => out.line(&format!(
                "Wrote the {} bytes to sign to {}. Sign them with the issuer's Ed25519 key, write \
                 the signature as base64 to a file, and give it with --signature-file.",
                input.len(),
                path.display()
            )),
        }
        return Exit::Complete;
    }

    // clap requires these unless --signing-input-out was given.
    let (Some(key_id), Some(trust), Some(output)) =
        (&command.key_id, &command.trust, &command.output)
    else {
        return failed(out, "USAGE", "give --key-id, --trust and --output");
    };
    let trust = match self::trust(trust) {
        Ok(trust) => trust,
        Err((code, message)) => return failed(out, code, &message),
    };
    let encoded = match (&command.key, &command.signature_file) {
        (Some(path), None) => match private_key(path) {
            Ok(key) => STANDARD.encode(key.sign(&input).to_bytes()),
            Err(message) => return failed(out, "INPUT", &message),
        },
        (None, Some(path)) => match read(path, 4096) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).trim().to_owned(),
            Err(message) => return failed(out, "INPUT", &message),
        },
        _ => return failed(out, "USAGE", "give --key or --signature-file"),
    };
    let signature = Countersignature {
        key_id,
        encoded: &encoded,
    };
    match countersign(package, &[signature], &trust) {
        Ok(issued) => written(out, &issued, output, "Signed"),
        Err(error) => not_issued(out, error, Checked::UnderRegistry),
    }
}
