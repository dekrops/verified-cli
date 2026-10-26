// SPDX-License-Identifier: Apache-2.0

//! `verified approval verify`: checking a signed contract approval. Every
//! rule is in `verified_verifier::approval`; this reads a file and prints.

use serde_json::json;
use verified_canonical::Limits;
use verified_verifier::approval::verify_approval;

use crate::cli::ApprovalVerify;
use crate::exit::Exit;
use crate::input::{self, InputError};
use crate::render::{Mode, Output, Row, Tone};
use crate::verify::failed;

const TITLE: &str = "Contract approval v1 (draft)";

pub(crate) fn verify(command: &ApprovalVerify, out: &mut Output) -> Exit {
    let path = &command.approval;
    let bytes = match input::read(path, Limits::DEFAULT.max_bytes) {
        Ok(bytes) => bytes,
        Err(InputError::Io(error)) => return failed(out, "INPUT", &format!("{error:#}")),
        Err(InputError::TooLarge(limit)) => {
            return failed(out, "INPUT", &format!("{}: {limit}", path.display()));
        }
    };
    let approved = match verify_approval(&bytes, &command.rp_id, &command.origins) {
        Ok(approved) => approved,
        Err(refusal) => {
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
            return Exit::Refused;
        }
    };
    let s = &approved.statement;
    let algorithm = match approved.algorithm {
        -7 => "ES256",
        -8 => "EdDSA",
        _ => "RS256",
    };
    match out.mode {
        Mode::Quiet => {}
        Mode::Json => out.json(&json!({
            "outcome": "valid",
            "approver": s.approver,
            "contract": s.contract,
            "repository": s.repository,
            "tenant": s.tenant,
            "issuedAt": s.issued_at,
            "shown": s.shown,
            "algorithm": approved.algorithm,
        })),
        Mode::Human => {
            out.heading(TITLE);
            out.rows(&[
                Row::new(
                    "valid",
                    Tone::Established,
                    format!("approved by {}", s.approver),
                ),
                Row::new("contract", Tone::Established, &s.contract),
                Row::new(
                    "repository",
                    Tone::Plain,
                    format!("{} (tenant {})", s.repository, s.tenant),
                ),
                Row::new("shown", Tone::Established, &s.shown),
                Row::new("issued at", Tone::Plain, &s.issued_at),
                Row::new(
                    "passkey",
                    Tone::Established,
                    format!("{algorithm}, for {}", command.rp_id),
                ),
            ]);
            out.line("");
            out.line(
                "This shows that whoever approved held this passkey's authenticator, for this \
                 contract and this snapshot. It does not show whose passkey it is, or what the \
                 authenticator displayed.",
            );
        }
    }
    Exit::Complete
}
