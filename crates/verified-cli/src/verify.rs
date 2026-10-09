//! `verified verify`.

use serde_json::json;
use verified_canonical::LimitExceeded;
use verified_verifier::{
    Finding, NotChecked, Options, ProtocolSelection, Refusal, Rejection, Report,
};

use crate::cli::Verify;
use crate::exit::Exit;
use crate::input::{self, InputError};
use crate::render::{Mode, Output, Row, Tone};

const TITLE: &str = "Work Verification Protocol package";
const NO_TRUTH: &str = "no check can establish it";
const INCOMPLETE: &str = "this version runs protocol steps 1 to 6 of 13; \
     the package was not refused and is not verified";

pub(crate) fn run(command: &Verify, out: &mut Output) -> Exit {
    let options = Options {
        protocol: command
            .protocol
            .map_or(ProtocolSelection::Detect, ProtocolSelection::Require),
        ..Options::default()
    };
    let bytes = match input::read(&command.package, options.limits.max_bytes) {
        Ok(bytes) => bytes,
        Err(InputError::Io(error)) => return failed(out, "IO_ERROR", &format!("{error:#}")),
        Err(InputError::TooLarge(limit)) => return not_examined(out, limit),
    };
    match verified_verifier::verify(&bytes, &options) {
        Ok(report) => incomplete(out, &report),
        Err(Rejection::Refused(refusal)) => refused(out, &refusal),
        Err(Rejection::Limit(limit)) => not_examined(out, limit),
    }
}

/// The command could not run. Nothing is said about the package.
fn failed(out: &mut Output, code: &str, message: &str) -> Exit {
    if out.mode == Mode::Json {
        out.json(&json!({ "outcome": "error", "error": { "code": code, "message": message } }));
    }
    out.error(message);
    Exit::Failed
}

fn not_examined(out: &mut Output, limit: LimitExceeded) -> Exit {
    failed(out, "RESOURCE_LIMIT", &Rejection::Limit(limit).to_string())
}

fn refused(out: &mut Output, refusal: &Refusal) -> Exit {
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

fn finding_json(finding: Finding) -> serde_json::Value {
    match finding {
        Finding::Established => json!({ "status": "established" }),
        Finding::NotChecked(reason) => {
            json!({ "status": "not_checked", "reason": reason_code(reason) })
        }
        // `Finding` is non-exhaustive: an unknown case claims nothing.
        _ => json!({ "status": "not_checked", "reason": "unknown" }),
    }
}

fn reason_code(reason: NotChecked) -> &'static str {
    match reason {
        NotChecked::NotImplemented => "not_implemented",
        _ => "unknown",
    }
}

fn finding_row(label: &'static str, finding: Finding, established: &str, note: &str) -> Row {
    match finding {
        Finding::Established => Row::new(label, Tone::Established, established),
        Finding::NotChecked(NotChecked::NotImplemented) => Row::new(
            label,
            Tone::Unknown,
            format!("not checked: not implemented in this version{note}"),
        ),
        _ => Row::new(label, Tone::Unknown, format!("not checked{note}")),
    }
}

/// The package was not refused, and not every check ran.
fn incomplete(out: &mut Output, report: &Report) -> Exit {
    match out.mode {
        Mode::Quiet => {}
        Mode::Json => out.json(&json!({
            "outcome": "incomplete",
            "protocol": report.protocol.identifier(),
            "protocolStatus": "draft",
            "packageId": report.package_id.to_string(),
            "components": report.components.iter().map(|c| json!({
                "path": c.path.as_str(),
                "digest": { "algorithm": "sha-256", "hex": c.digest.to_hex() },
            })).collect::<Vec<_>>(),
            "issuerSignaturesCarried": report.issuer_signatures_carried,
            "properties": {
                "container": finding_json(report.container),
                "componentShapes": finding_json(report.component_shapes),
                "packageIntegrity": finding_json(report.integrity()),
                "evidenceSignatures": finding_json(report.evidence_signatures),
                "signerAuthority": finding_json(report.signer_authority),
                "decisionReproduced": finding_json(report.decision_reproduced),
                "issuerSignature": finding_json(report.issuer_signature),
                "sourceTruthfulness": { "status": "not_established", "reason": "no_check_can_establish_it" },
            },
            "note": INCOMPLETE,
        })),
        Mode::Human => {
            let carried = match report.issuer_signatures_carried {
                0 => String::new(),
                n => format!(" ({n} carried)"),
            };
            let integrity = match report.integrity() {
                Finding::Established => Row::new("package integrity", Tone::Established, "established"),
                _ => Row::new(
                    "package integrity",
                    Tone::Negative,
                    "NOT established: component shapes were not checked",
                ),
            };
            out.heading(&format!("{TITLE} ({}, draft)", report.protocol));
            out.rows(&[
                Row::new(
                    "package",
                    Tone::Plain,
                    format!("wvp:sha-256:{}", out.short(&report.package_id.commitment().to_hex())),
                ),
                finding_row(
                    "container",
                    report.container,
                    "consistent: canonical text, versions, component set, digests, commitment",
                    "",
                ),
            ]);
            if out.verbose {
                let rows: Vec<Row> = report
                    .components
                    .iter()
                    .map(|c| Row::new("", Tone::Plain, format!("{:<26}sha-256:{}", c.path.as_str(), c.digest)))
                    .collect();
                out.rows(&rows);
            }
            out.rows(&[
                finding_row("component shapes", report.component_shapes, "well formed", ""),
                integrity,
                finding_row("evidence signatures", report.evidence_signatures, "established", ""),
                finding_row("signer authority", report.signer_authority, "established", ""),
                finding_row("decision reproduced", report.decision_reproduced, "established", ""),
                finding_row("issuer signature", report.issuer_signature, "established", &carried),
                Row::new("source truthfulness", Tone::Negative, format!("NOT established: {NO_TRUTH}")),
            ]);
            out.line("");
            out.line(&format!("incomplete: {INCOMPLETE}"));
        }
    }
    Exit::Incomplete
}
