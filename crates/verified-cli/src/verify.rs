// SPDX-License-Identifier: Apache-2.0

//! `verified verify`.

use serde_json::json;
use verified_canonical::{LimitExceeded, Limits, Sha256Digest, parse};
use verified_protocol::Decision;
use verified_verifier::{
    DecisionFinding, Evaluation, Expectations, Finding, IssuerSignature, NotChecked, Options,
    ProtocolSelection, Refusal, Rejection, Report, Reproduced, Trust,
};

use crate::cli::Verify;
use crate::exit::Exit;
use crate::input::{self, InputError};
use crate::render::{Mode, Output, Row, Tone};

const TITLE: &str = "Work Verification Protocol package";
const NO_TRUTH: &str = "no check can establish it";
const NO_REGISTRY: &str = "no trust registry was supplied (--trust), so no signature was checked \
     and the decision was not reproduced; the decision the package carries is its issuer's claim";

pub(crate) fn run(command: &Verify, out: &mut Output) -> Exit {
    let limits = Limits::DEFAULT;
    let stdin = std::path::Path::new("-");
    if command.package == stdin && command.trust.as_deref() == Some(stdin) {
        return failed(
            out,
            "USAGE",
            "the package and the trust registry cannot both be read from standard input",
        );
    }
    let trust = match command.trust.as_deref().map(|path| registry(path, &limits)) {
        None => None,
        Some(Ok(trust)) => Some(trust),
        Some(Err(message)) => return failed(out, "TRUST_REGISTRY", &message),
    };
    let options = Options {
        limits,
        protocol: command
            .protocol
            .map_or(ProtocolSelection::Detect, ProtocolSelection::Require),
        trust: trust.as_ref(),
        expectations: Expectations {
            tenant: command.expect_tenant.clone(),
            contract: command.expect_contract,
            claim: command.expect_claim.clone(),
        },
    };
    let bytes = match input::read(&command.package, options.limits.max_bytes) {
        Ok(bytes) => bytes,
        Err(InputError::Io(error)) => return failed(out, "IO_ERROR", &format!("{error:#}")),
        Err(InputError::TooLarge(limit)) => return not_examined(out, limit),
    };
    match verified_verifier::verify(package_text(&bytes), &options) {
        Ok(report) => reported(out, &report),
        Err(Rejection::Refused(refusal)) => refused(out, &refusal),
        Err(Rejection::Limit(limit)) => not_examined(out, limit),
        Err(error @ Rejection::ExpectationsUndefined(_)) => {
            failed(out, "EXPECTATIONS_UNDEFINED", &error.to_string())
        }
    }
}

/// The package text inside a file's bytes.
///
/// A package is canonical text, which has no trailing line end; a file
/// conventionally has one. Exactly one final line end (`\n` or `\r\n`) is
/// therefore the file's, not the package's. Anything else, a second line end
/// included, is left for the canonical-text check to refuse.
fn package_text(bytes: &[u8]) -> &[u8] {
    let text = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if text.len() == bytes.len() {
        bytes
    } else {
        text.strip_suffix(b"\r").unwrap_or(text)
    }
}

/// Reads the relying party's registry. It is configuration, so it need not
/// be canonical text, but it must be exactly a registry.
fn registry(path: &std::path::Path, limits: &Limits) -> Result<Trust, String> {
    let name = path.display();
    let bytes = match input::read(path, limits.max_bytes) {
        Ok(bytes) => bytes,
        Err(InputError::Io(error)) => return Err(format!("{error:#}")),
        Err(InputError::TooLarge(limit)) => {
            return Err(format!("trust registry {name}: {limit}"));
        }
    };
    let value = parse(&bytes, limits).map_err(|error| format!("trust registry {name}: {error}"))?;
    Trust::from_value(&value).map_err(|error| format!("trust registry {name}: {error}"))
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

fn reason_code(reason: NotChecked) -> &'static str {
    match reason {
        NotChecked::NoTrustRegistry => "no_trust_registry",
        // `NotChecked` is non-exhaustive: an unknown case claims nothing.
        _ => "unknown",
    }
}

fn digest_json(digest: &Sha256Digest) -> serde_json::Value {
    json!({ "algorithm": Sha256Digest::ALGORITHM, "hex": digest.to_hex() })
}

fn finding_json(finding: Finding) -> serde_json::Value {
    match finding {
        Finding::Established => json!({ "status": "established" }),
        Finding::NotChecked(reason) => {
            json!({ "status": "not_checked", "reason": reason_code(reason) })
        }
        _ => json!({ "status": "not_checked", "reason": "unknown" }),
    }
}

fn decision_json(finding: &DecisionFinding) -> serde_json::Value {
    let DecisionFinding::Reproduced(Reproduced {
        decision,
        evaluation,
    }) = finding
    else {
        let reason = match finding {
            DecisionFinding::NotChecked(reason) => reason_code(*reason),
            _ => "unknown",
        };
        return json!({ "status": "not_checked", "reason": reason });
    };
    let mut reproduced = json!({ "status": "established", "decision": decision.as_str() });
    match evaluation {
        Evaluation::OrderTransition { conditions } => {
            reproduced["conditions"] = conditions
                .iter()
                .map(|c| json!({ "id": c.id, "holds": c.holds, "evidence": c.evidence }))
                .collect();
        }
        Evaluation::WorkContract {
            requirements,
            ignored,
            conflicts,
        } => {
            reproduced["requirements"] = requirements
                .iter()
                .map(|r| json!({ "id": r.id, "value": r.value.as_str() }))
                .collect();
            reproduced["ignored"] = json!(ignored);
            reproduced["conflicts"] = conflicts
                .iter()
                .map(|c| json!({ "kind": c.kind, "facts": c.facts, "resolvedTo": c.resolved_to }))
                .collect();
        }
        _ => {}
    }
    reproduced
}

fn issuer_json(issuer: IssuerSignature) -> serde_json::Value {
    match issuer {
        IssuerSignature::Established { count } => {
            json!({ "status": "established", "count": count })
        }
        IssuerSignature::Absent => json!({ "status": "absent" }),
        IssuerSignature::NotChecked { carried, reason } => {
            json!({ "status": "not_checked", "reason": reason_code(reason), "carried": carried })
        }
        _ => json!({ "status": "not_checked", "reason": "unknown" }),
    }
}

fn report_json(report: &Report, complete: bool) -> serde_json::Value {
    let met = &report.expectations_met;
    let mut result = json!({
        "outcome": if complete { "complete" } else { "incomplete" },
        "protocol": report.protocol.identifier(),
        "protocolStatus": "draft",
        "packageId": report.package_id.to_string(),
        "tenant": report.tenant,
        "claim": report.claim,
        "statements": report.statements,
        "components": report.components.iter().map(|c| json!({
            "path": c.path.as_str(),
            "digest": digest_json(&c.digest),
        })).collect::<Vec<_>>(),
        "properties": {
            "packageIntegrity": finding_json(report.integrity),
            "evidenceSignatures": finding_json(report.evidence_signatures),
            "signerAuthority": finding_json(report.signer_authority),
            "decisionReproduced": decision_json(&report.decision),
            "issuerSignature": issuer_json(report.issuer_signature),
            "sourceTruthfulness": { "status": "not_established", "reason": "no_check_can_establish_it" },
        },
        "expectationsMet": {
            "tenant": met.tenant,
            "contract": met.contract.as_ref().map(digest_json),
            "claim": met.claim,
        },
    });
    if let Some(contract) = &report.contract {
        result["contract"] = json!({
            "id": contract.id,
            "version": contract.version,
            "digest": digest_json(&contract.digest),
        });
    }
    if !complete {
        result["note"] = json!(NO_REGISTRY);
    }
    result
}

fn finding_row(label: &'static str, finding: Finding, established: &str) -> Row {
    match finding {
        Finding::Established => Row::new(label, Tone::Established, established),
        Finding::NotChecked(NotChecked::NoTrustRegistry) => Row::new(
            label,
            Tone::Unknown,
            "not checked: no trust registry supplied",
        ),
        _ => Row::new(label, Tone::Unknown, "not checked"),
    }
}

fn decision_rows(finding: &DecisionFinding) -> Vec<Row> {
    const LABEL: &str = "decision reproduced";
    let DecisionFinding::Reproduced(Reproduced {
        decision,
        evaluation,
    }) = finding
    else {
        return vec![Row::new(
            LABEL,
            Tone::Unknown,
            "not checked: no trust registry supplied",
        )];
    };
    // A reproduced decision is established whatever it is; the tone says
    // what it means for the claim.
    let tone = match decision {
        Decision::Supported => Tone::Established,
        Decision::Contradicted => Tone::Negative,
        Decision::Undetermined => Tone::Unknown,
    };
    let mut rows = vec![Row::new(
        LABEL,
        tone,
        format!("{decision}, matches the package"),
    )];
    let truth = |holds: bool| {
        if holds {
            Tone::Established
        } else {
            Tone::Plain
        }
    };
    match evaluation {
        Evaluation::OrderTransition { conditions } => {
            rows.extend(conditions.iter().map(|c| {
                let holds = if c.holds { "holds" } else { "does not hold" };
                Row::new("", truth(c.holds), format!("  {:<28}{holds}", c.id))
            }));
        }
        Evaluation::WorkContract {
            requirements,
            ignored,
            conflicts,
        } => {
            rows.extend(requirements.iter().map(|r| {
                let tone = match r.value.as_str() {
                    "TRUE" => Tone::Established,
                    "FALSE" => Tone::Negative,
                    _ => Tone::Unknown,
                };
                Row::new("", tone, format!("  {:<28}{}", r.id, r.value))
            }));
            if !ignored.is_empty() {
                rows.push(Row::new(
                    "",
                    Tone::Plain,
                    format!(
                        "  {} authentic record(s) ignored: source not accepted by the contract",
                        ignored.len()
                    ),
                ));
            }
            if !conflicts.is_empty() {
                let open = conflicts.iter().filter(|c| c.resolved_to.is_none()).count();
                rows.push(Row::new(
                    "",
                    Tone::Unknown,
                    format!(
                        "  {} conflict(s) among accepted records, {open} unresolved",
                        conflicts.len()
                    ),
                ));
            }
        }
        _ => {}
    }
    rows
}

fn issuer_row(issuer: IssuerSignature) -> Row {
    const LABEL: &str = "issuer signature";
    match issuer {
        IssuerSignature::Established { count } => Row::new(
            LABEL,
            Tone::Established,
            format!("established ({count} of {count})"),
        ),
        IssuerSignature::Absent => Row::new(LABEL, Tone::Plain, "absent"),
        IssuerSignature::NotChecked { carried, .. } => Row::new(
            LABEL,
            Tone::Unknown,
            format!("not checked: no trust registry supplied ({carried} carried)"),
        ),
        _ => Row::new(LABEL, Tone::Unknown, "not checked"),
    }
}

/// The package was not refused. Whether every check ran is the report's to
/// say, and decides the exit code.
fn reported(out: &mut Output, report: &Report) -> Exit {
    let complete = report.is_complete();
    match out.mode {
        Mode::Quiet => {}
        Mode::Json => out.json(&report_json(report, complete)),
        Mode::Human => human(out, report, complete),
    }
    if complete {
        Exit::Complete
    } else {
        Exit::Incomplete
    }
}

fn human(out: &mut Output, report: &Report, complete: bool) {
    let statements = report.statements;
    out.heading(&format!("{TITLE} ({}, draft)", report.protocol));
    out.rows(&[
        Row::new(
            "package",
            Tone::Plain,
            format!(
                "wvp:sha-256:{}",
                out.short(&report.package_id.commitment().to_hex())
            ),
        ),
        Row::new("tenant", Tone::Plain, &report.tenant),
        Row::new("claim", Tone::Plain, &report.claim),
        finding_row("package integrity", report.integrity, "established"),
    ]);
    if out.verbose {
        let rows: Vec<Row> = report
            .components
            .iter()
            .map(|c| {
                Row::new(
                    "",
                    Tone::Plain,
                    format!("  {:<26}sha-256:{}", c.path.as_str(), c.digest),
                )
            })
            .collect();
        out.rows(&rows);
    }
    if let Some(contract) = &report.contract {
        out.rows(&[Row::new(
            "contract",
            Tone::Plain,
            format!(
                "{} {}, sha-256:{}",
                contract.id,
                contract.version,
                out.short(&contract.digest.to_hex())
            ),
        )]);
    }
    out.rows(&[
        finding_row(
            "evidence signatures",
            report.evidence_signatures,
            &format!("established ({statements} of {statements})"),
        ),
        finding_row(
            "signer authority",
            report.signer_authority,
            "established under the supplied registry",
        ),
    ]);
    out.rows(&decision_rows(&report.decision));
    out.rows(&[
        issuer_row(report.issuer_signature),
        Row::new(
            "source truthfulness",
            Tone::Negative,
            format!("NOT established: {NO_TRUTH}"),
        ),
    ]);
    if !report.expectations_met.is_empty() {
        let met = &report.expectations_met;
        let given: Vec<&str> = [
            met.tenant.as_ref().map(|_| "tenant"),
            met.contract.as_ref().map(|_| "contract"),
            met.claim.as_ref().map(|_| "claim"),
        ]
        .into_iter()
        .flatten()
        .collect();
        out.rows(&[Row::new(
            "expectations",
            Tone::Established,
            format!("met ({})", given.join(", ")),
        )]);
    }
    out.line("");
    match (&report.decision, complete) {
        (
            DecisionFinding::Reproduced(Reproduced {
                decision: Decision::Supported,
                ..
            }),
            true,
        ) => {
            out.line("complete: every protocol check ran; the decision SUPPORTED was reproduced");
        }
        (DecisionFinding::Reproduced(Reproduced { decision, .. }), true) => {
            out.line(&format!(
                "complete: every protocol check ran; the reproduced decision is {decision}, \
                 so the claim is not supported"
            ));
        }
        _ => out.line(&format!("incomplete: {NO_REGISTRY}")),
    }
}

#[cfg(test)]
mod tests {
    use super::package_text;

    #[test]
    fn one_final_line_end_belongs_to_the_file() {
        assert_eq!(package_text(b"{}"), b"{}");
        assert_eq!(package_text(b"{}\n"), b"{}");
        assert_eq!(package_text(b"{}\r\n"), b"{}");
        assert_eq!(package_text(b"{}\n\n"), b"{}\n");
        assert_eq!(package_text(b"{}\r"), b"{}\r");
        assert_eq!(package_text(b"{} \n"), b"{} ");
        assert_eq!(package_text(b"\n"), b"");
        assert_eq!(package_text(b""), b"");
    }
}
