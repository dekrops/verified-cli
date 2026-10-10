// SPDX-License-Identifier: Apache-2.0

//! `verified registration`: checking a claim registration and a registry's
//! log. Every rule is in `verified_verifier::registration`; this reads
//! files and prints.

use std::path::Path;

use serde_json::json;
use verified_canonical::Limits;
use verified_verifier::registration::log::{Inclusion, check_log};
use verified_verifier::registration::{
    RegistrationRefusal, RegistrationTrust, verify_registration,
};

use crate::cli::{RegistrationLog, RegistrationVerify};
use crate::exit::Exit;
use crate::input::{self, InputError};
use crate::render::{Mode, Output, Row, Tone};
use crate::verify::{digest_json, failed, json_file, package_text};

const TITLE: &str = "Claim registration v1 (draft)";

fn trust(path: &Path) -> Result<RegistrationTrust, String> {
    let value = json_file(path, "trust configuration", &Limits::DEFAULT)?;
    RegistrationTrust::from_value(&value)
        .map_err(|error| format!("trust configuration {}: {error}", path.display()))
}

/// The text of a signed object in a file. As with packages, exactly one
/// final line end is the file's, not the object's.
fn object(path: &Path) -> Result<Vec<u8>, String> {
    match input::read(path, Limits::DEFAULT.max_bytes) {
        Ok(bytes) => Ok(package_text(&bytes).to_vec()),
        Err(InputError::Io(error)) => Err(format!("{error:#}")),
        Err(InputError::TooLarge(limit)) => Err(format!("{}: {limit}", path.display())),
    }
}

fn refused(out: &mut Output, refusal: &RegistrationRefusal) -> Exit {
    match out.mode {
        Mode::Quiet => {}
        Mode::Json => out.json(&json!({
            "outcome": "refused",
            "refusal": { "code": refusal.code.as_str(), "detail": refusal.detail },
        })),
        Mode::Human => {
            out.heading(TITLE);
            out.rows(&[
                Row::new("refused", Tone::Negative, refusal.code.as_str()),
                Row::new("", Tone::Plain, &refusal.detail),
            ]);
        }
    }
    Exit::Refused
}

pub(crate) fn verify(command: &RegistrationVerify, out: &mut Output) -> Exit {
    let read = trust(&command.trust).and_then(|trust| {
        Ok((
            object(&command.agreement)?,
            object(&command.claim)?,
            object(&command.receipt)?,
            trust,
        ))
    });
    let (agreement, claim, receipt, trust) = match read {
        Ok(read) => read,
        Err(message) => return failed(out, "INPUT", &message),
    };
    let registration = match verify_registration(&agreement, &claim, &receipt, &trust) {
        Ok(registration) => registration,
        Err(refusal) => return refused(out, &refusal),
    };
    match out.mode {
        Mode::Quiet => {}
        Mode::Json => out.json(&json!({
            "outcome": "registered",
            "claim": registration.claim_id,
            "claimDigest": digest_json(&registration.claim),
            "agreement": digest_json(&registration.agreement),
            "receipt": digest_json(&registration.receipt),
            "claimant": registration.claimant,
            "respondent": registration.respondent,
            "registry": registration.registry,
            "sequence": registration.sequence,
            "receivedAt": registration.received_at,
            "respondBy": registration.respond_by,
        })),
        Mode::Human => {
            out.heading(TITLE);
            out.rows(&[
                Row::new("registered", Tone::Established, &registration.claim_id),
                Row::new(
                    "agreement",
                    Tone::Established,
                    format!(
                        "signed by claimant {} and respondent {}",
                        registration.claimant, registration.respondent
                    ),
                ),
                Row::new(
                    "registry",
                    Tone::Established,
                    format!(
                        "{}, entry {} of its log",
                        registration.registry, registration.sequence
                    ),
                ),
                Row::new("received", Tone::Established, &registration.received_at),
                Row::new("respond by", Tone::Established, &registration.respond_by),
            ]);
            out.line("");
            out.line(
                "This shows that the claim was made and received, and when an answer is due. \
                 It does not show that the claim is true, or that the registry kept its rules.",
            );
        }
    }
    Exit::Complete
}

pub(crate) fn log(command: &RegistrationLog, out: &mut Output) -> Exit {
    let optional = |path: &Option<std::path::PathBuf>| path.as_deref().map(object).transpose();
    let read = trust(&command.trust).and_then(|trust| {
        Ok((
            object(&command.log)?,
            optional(&command.anchor)?,
            optional(&command.held)?,
            trust,
        ))
    });
    let (log, anchor, held, trust) = match read {
        Ok(read) => read,
        Err(message) => return failed(out, "INPUT", &message),
    };
    // One entry per line. An entry is canonical text, which has no line end.
    let entries: Vec<&[u8]> = if log.is_empty() {
        Vec::new()
    } else {
        log.split(|byte| *byte == b'\n').collect()
    };
    let check = match check_log(&entries, anchor.as_deref(), held.as_deref(), &trust) {
        Ok(check) => check,
        Err(refusal) => return refused(out, &refusal),
    };
    let segment = &check.segment;
    let (inclusion, tone, exit) = match check.inclusion {
        None => (None, Tone::Plain, Exit::Complete),
        Some(Inclusion::Included) => (
            Some(("INCLUDED", "the log has this entry at its position")),
            Tone::Established,
            Exit::Complete,
        ),
        Some(Inclusion::NotCovered) => (
            Some(("NOT_COVERED", "these entries do not reach its position")),
            Tone::Unknown,
            Exit::Incomplete,
        ),
        Some(Inclusion::Equivocation { .. }) => (
            Some(("EQUIVOCATION", "the log has another entry at its position")),
            Tone::Negative,
            Exit::Refused,
        ),
    };
    match out.mode {
        Mode::Quiet => {}
        Mode::Json => {
            let mut result = json!({
                "outcome": match exit {
                    Exit::Complete => "verified",
                    Exit::Incomplete => "not_covered",
                    _ => "equivocation",
                },
                "registry": segment.registry,
                "first": segment.first,
                "last": segment.last,
                "head": digest_json(&segment.head),
                "inclusion": inclusion.map(|(code, _)| code),
            });
            if let Some(Inclusion::Equivocation { held, logged }) = check.inclusion {
                result["held"] = digest_json(&held);
                result["logged"] = digest_json(&logged);
            }
            out.json(&result);
        }
        Mode::Human => {
            out.heading(TITLE);
            let mut rows = vec![
                Row::new(
                    "log",
                    Tone::Established,
                    format!(
                        "{}, entries {} to {} are consecutive and unaltered",
                        segment.registry, segment.first, segment.last
                    ),
                ),
                Row::new("head", Tone::Plain, out.short(&segment.head.to_hex())),
            ];
            if let Some((code, meaning)) = inclusion {
                rows.push(Row::new("held entry", tone, format!("{code}: {meaning}")));
            }
            if let Some(Inclusion::Equivocation { held, logged }) = check.inclusion {
                rows.push(Row::new(
                    "",
                    Tone::Plain,
                    format!(
                        "held {}, logged {}; the registry signed both",
                        out.short(&held.to_hex()),
                        out.short(&logged.to_hex())
                    ),
                ));
            }
            out.rows(&rows);
            out.line("");
            out.line(
                "Nothing is shown about entries after the last, or about whether the registry \
                 kept its rules.",
            );
        }
    }
    exit
}
