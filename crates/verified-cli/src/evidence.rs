// SPDX-License-Identifier: Apache-2.0

//! `verified evidence`: evidence statements held outside a package, checked
//! as a chain or made and signed. Every rule is in
//! `verified_verifier::evidence`; this reads files, signs with a local key
//! if asked, and prints.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::Signer as _;
use serde_json::json;
use verified_canonical::{Limits, Object, Value, parse};
use verified_verifier::evidence::{
    Anchor, EvidenceRefusal, StatementDraft, Step, authenticate, prepare_statement,
    signed_statement, statement_signing_input, verify_chain,
};

use crate::cli::{EvidenceChain, EvidenceSign};
use crate::exit::Exit;
use crate::issue::{create, private_key, read, trust};
use crate::registration::{lines, object};
use crate::render::{Mode, Output, Row, Tone};
use crate::verify::{failed, json_file, output_json, registry};

const TITLE: &str = "Evidence Statement v1 chain (draft)";
const SIGN_TITLE: &str = "Evidence Statement v1 (draft)";

fn refused(out: &mut Output, code: &str, detail: &str) -> Exit {
    refused_under(out, TITLE, code, detail)
}

fn refused_under(out: &mut Output, title: &str, code: &str, detail: &str) -> Exit {
    match out.mode {
        Mode::Quiet => {}
        Mode::Json => out.json(&json!({
            "outcome": "refused",
            "refusal": { "code": code, "detail": detail },
        })),
        Mode::Human => {
            out.heading(title);
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

/// The members of a statement draft: the stated members and `body`.
const DRAFT_MEMBERS: [&str; 8] = [
    "body",
    "id",
    "issuer",
    "kind",
    "observedAt",
    "source",
    "subject",
    "tenant",
];

/// The stated members and the body of a draft.
fn split_draft(draft: &Value) -> Result<(Value, Value), String> {
    let object = draft
        .as_object()
        .filter(|o| o.has_exactly(&DRAFT_MEMBERS))
        .ok_or_else(|| {
            format!("a draft is an object with exactly the members {DRAFT_MEMBERS:?}")
        })?;
    let stated: Object = object
        .iter()
        .filter(|(name, _)| *name != "body")
        .map(|(name, value)| (name.to_owned(), value.clone()))
        .collect();
    let body = object.get("body").cloned().unwrap_or(Value::Null);
    Ok((Value::Object(stated), body))
}

/// The anchor a statement continues from: the previous step, as verified.
fn anchor_of(previous: &verified_verifier::evidence::Authenticated<'_>) -> Option<Anchor> {
    let statement = previous.statement();
    let link = statement.chain?;
    Some(Anchor {
        tenant: statement.tenant.to_owned(),
        issuer: statement.issuer.to_owned(),
        stream: link.stream.to_owned(),
        sequence: link.sequence,
        digest: statement.digest(),
    })
}

pub(crate) fn sign(command: &EvidenceSign, out: &mut Output) -> Exit {
    let limits = Limits::DEFAULT;
    let read_draft = json_file(&command.draft, "draft", &limits).and_then(|draft| {
        let (stated, body) =
            split_draft(&draft).map_err(|m| format!("{}: {m}", command.draft.display()))?;
        let previous = command
            .after
            .as_deref()
            .map(|path| json_file(path, "previous statement", &limits))
            .transpose()?;
        Ok((stated, body, previous))
    });
    let (stated, body, previous) = match read_draft {
        Ok(read) => read,
        Err(message) => return failed(out, "INPUT", &message),
    };
    let step = match (&command.stream, &previous) {
        (Some(stream), _) => Step::First { stream },
        (None, Some(previous)) => Step::After(previous),
        (None, None) => Step::Unchained,
    };
    let draft = StatementDraft {
        stated: &stated,
        body: &body,
        step,
    };
    let statement = match prepare_statement(&draft) {
        Ok(statement) => statement,
        Err(refusal) => return failed(out, "INPUT", &refusal.to_string()),
    };
    let input = statement_signing_input(&statement);

    if let Some(path) = &command.signing_input_out {
        return wrote_signing_input(out, path, &input);
    }

    // clap requires these unless --signing-input-out was given.
    let (Some(key_id), Some(registry_path), Some(output)) =
        (&command.key_id, &command.trust, &command.output)
    else {
        return failed(out, "USAGE", "give --key-id, --trust and --output");
    };
    let trust = match trust(registry_path) {
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
    let signed = signed_statement(&statement, key_id, &encoded);

    // Written only if a relying party holding this registry would accept it.
    let authentic = match authenticate(&signed, &trust) {
        Ok(authentic) => authentic,
        Err(refusal) => {
            return refused_under(out, SIGN_TITLE, refusal.code.as_str(), &refusal.detail);
        }
    };
    let anchor = match &previous {
        None => None,
        Some(previous) => match authenticate(previous, &trust) {
            Ok(previous) => anchor_of(&previous),
            Err(refusal) => {
                let detail = format!("the previous statement: {}", refusal.detail);
                return refused_under(out, SIGN_TITLE, refusal.code.as_str(), &detail);
            }
        },
    };
    if (command.stream.is_some() || anchor.is_some())
        && let Err(refusal) = verify_chain(&[authentic], anchor.as_ref())
    {
        return refused_under(out, SIGN_TITLE, refusal.code.as_str(), &refusal.detail);
    }
    if let Err(message) = create(output, signed.to_canonical_string().as_bytes()) {
        return failed(out, "IO_ERROR", &message);
    }

    reported(out, authentic.statement(), key_id, output)
}

fn wrote_signing_input(out: &mut Output, path: &std::path::Path, input: &[u8]) -> Exit {
    if let Err(message) = create(path, input) {
        return failed(out, "IO_ERROR", &message);
    }
    match out.mode {
        Mode::Quiet => {}
        Mode::Json => {
            out.json(&json!({ "outcome": "signing_input", "output": path, "bytes": input.len() }));
        }
        Mode::Human => out.line(&format!(
            "Wrote the {} bytes to sign to {}. Sign them with the source's Ed25519 key, write the \
             signature as base64 to a file, and give it with --signature-file (with the same \
             draft, --stream or --after).",
            input.len(),
            path.display()
        )),
    }
    Exit::Complete
}

/// Reports a statement that was signed and written.
fn reported(
    out: &mut Output,
    read: &verified_protocol::SignedStatement<'_>,
    key_id: &str,
    output: &std::path::Path,
) -> Exit {
    let chain = read
        .chain
        .map(|link| json!({ "stream": link.stream, "sequence": link.sequence }));
    match out.mode {
        Mode::Quiet => {}
        Mode::Json => out.json(&json!({
            "outcome": "signed",
            "output": output,
            "id": read.id,
            "statementDigest": crate::verify::digest_json(&read.digest()),
            "chain": chain,
        })),
        Mode::Human => {
            out.heading(SIGN_TITLE);
            let observed = read
                .member("observedAt")
                .as_object()
                .and_then(|o| o.get("value"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            let place = read.chain.map_or_else(
                || "not chained".to_owned(),
                |link| format!("step {} of {}", link.sequence, link.stream),
            );
            out.rows(&[
                Row::new("statement", Tone::Plain, read.id),
                Row::new("kind", Tone::Plain, read.kind),
                Row::new(
                    "observed",
                    Tone::Plain,
                    format!("{} at {observed}", read.source_system),
                ),
                Row::new(
                    "body",
                    Tone::Plain,
                    format!("sha-256:{}", out.short(read.payload.hex)),
                ),
                Row::new("chain", Tone::Plain, place),
                Row::new(
                    "signature",
                    Tone::Established,
                    format!("by key {key_id}, authentic under your registry"),
                ),
            ]);
            out.line("");
            out.line(&format!(
                "Written to {}. A signature shows who said this, not that it is true.",
                output.display()
            ));
        }
    }
    Exit::Complete
}
