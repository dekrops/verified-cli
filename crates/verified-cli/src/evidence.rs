// SPDX-License-Identifier: Apache-2.0

//! `verified evidence`: evidence statements held outside a package. Every
//! rule is in `verified_verifier::evidence`; this reads files and prints.

use serde_json::json;
use verified_canonical::{Limits, parse};
use verified_verifier::evidence::{Anchor, EvidenceRefusal, authenticate, verify_chain};

use crate::cli::EvidenceChain;
use crate::exit::Exit;
use crate::registration::{lines, object};
use crate::render::{Mode, Output, Row, Tone};
use crate::verify::{failed, json_file, output_json, registry};

const TITLE: &str = "Evidence Statement v1 chain (draft)";

fn refused(out: &mut Output, code: &str, detail: &str) -> Exit {
    match out.mode {
        Mode::Quiet => {}
        Mode::Json => out.json(&json!({
            "outcome": "refused",
            "refusal": { "code": code, "detail": detail },
        })),
        Mode::Human => {
            out.heading(TITLE);
            out.rows(&[
                Row::new("refused", Tone::Negative, code),
                Row::new("", Tone::Plain, detail),
            ]);
        }
    }
    Exit::Refused
}

/// A statement's refusal, with the line it is on.
fn refused_at(out: &mut Output, line: usize, refusal: &EvidenceRefusal) -> Exit {
    let detail = format!("statement {line}: {}", refusal.detail);
    refused(out, refusal.code.as_str(), &detail)
}

pub(crate) fn chain(command: &EvidenceChain, out: &mut Output) -> Exit {
    let read = registry(&command.trust, &Limits::DEFAULT).and_then(|trust| {
        let anchor = command
            .anchor
            .as_deref()
            .map(|path| {
                let value = json_file(path, "anchor", &Limits::DEFAULT)?;
                Anchor::from_value(&value)
                    .map_err(|error| format!("anchor {}: {error}", path.display()))
            })
            .transpose()?;
        Ok((object(&command.statements)?, anchor, trust))
    });
    let (text, anchor, trust) = match read {
        Ok(read) => read,
        Err(message) => return failed(out, "INPUT", &message),
    };

    // Each line is read and then authenticated before the next, so the
    // first failure in line order is the one reported. Lines are numbered
    // from 1, as an editor shows them.
    let parsed: Vec<_> = lines(&text)
        .into_iter()
        .map(|line| parse(line, &Limits::DEFAULT))
        .collect();
    let mut authentic = Vec::with_capacity(parsed.len());
    for (i, statement) in parsed.iter().enumerate() {
        let statement = match statement {
            Ok(statement) => statement,
            Err(error) => {
                let detail = format!("statement {}: {error}", i + 1);
                return refused(out, "MALFORMED", &detail);
            }
        };
        match authenticate(statement, &trust) {
            Ok(statement) => authentic.push(statement),
            Err(refusal) => return refused_at(out, i + 1, &refusal),
        }
    }
    let segment = match verify_chain(&authentic, anchor.as_ref()) {
        Ok(segment) => segment,
        Err(refusal) => return refused(out, refusal.code.as_str(), &refusal.detail),
    };

    let head = &segment.head;
    match out.mode {
        Mode::Quiet => {}
        Mode::Json => out.json(&json!({
            "outcome": "verified",
            "fromGenesis": segment.from_genesis,
            "first": segment.first,
            "last": head.sequence,
            "head": output_json(&head.to_value()),
        })),
        Mode::Human => {
            out.heading(TITLE);
            let start = if segment.from_genesis {
                "the stream's first step".to_owned()
            } else {
                format!("the step after your anchor, {}", segment.first - 1)
            };
            let rows = [
                Row::new(
                    "chain",
                    Tone::Established,
                    format!(
                        "steps {} to {} of {} are consecutive and unaltered",
                        segment.first, head.sequence, head.stream
                    ),
                ),
                Row::new("starts at", Tone::Plain, start),
                Row::new("issuer", Tone::Plain, &head.issuer),
                Row::new("tenant", Tone::Plain, &head.tenant),
                Row::new("head", Tone::Plain, out.short(&head.digest.to_hex())),
            ];
            out.rows(&rows);
            out.line("");
            out.line(
                "Each statement is authentic, not true. Nothing is shown about steps after the \
                 last: whoever passed these on can leave off the end.",
            );
        }
    }
    Exit::Complete
}
