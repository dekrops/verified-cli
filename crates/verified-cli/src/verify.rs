// SPDX-License-Identifier: Apache-2.0

//! `verified verify`.

use serde_json::json;
use verified_canonical::{LimitExceeded, Limits, Sha256Digest, Value, parse};
use verified_protocol::Decision;
use verified_verifier::{
    DecisionFinding, Evaluation, Expectations, Finding, IssuerSignature, NotChecked, Options,
    ProtocolSelection, Refusal, Rejection, Report, Reproduced, Trust,
};

use crate::cli::Verify;
use crate::exit::Exit;
use crate::input::{self, InputError};
use crate::render::{Mode, Output, Row, Tone};

pub(crate) const TITLE: &str = "Work Verification Protocol package";
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
    let record = match command
        .record
        .as_deref()
        .map(|path| json_file(path, "work record", &limits))
    {
        None => None,
        Some(Ok(record)) => Some(record),
        Some(Err(message)) => return failed(out, "WORK_RECORD", &message),
    };
    let options = Options {
        limits,
        record: record.as_ref(),
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
    // A stored package is named by an identifier, which no file name this
    // tool would be given starts with.
    let stored = command.package.to_str().filter(|name| {
        name.starts_with(verified_protocol::PackageId::PREFIX)
            || name.starts_with(verified_workspace::ObjectId::PREFIX)
    });
    let bytes = match stored {
        Some(name) => match crate::workspace::load(name, &options.limits) {
            Ok((_, bytes)) => bytes,
            Err(message) => return failed(out, "WORKSPACE", &message),
        },
        None => match input::read(&command.package, options.limits.max_bytes) {
            Ok(bytes) => bytes,
            Err(InputError::Io(error)) => return failed(out, "IO_ERROR", &format!("{error:#}")),
            Err(InputError::TooLarge(limit)) => return not_examined(out, limit),
        },
    };
    match verified_verifier::verify(package_text(&bytes), &options) {
        Ok(report) => reported(out, &report, command.require_decision, command.any_contract),
        Err(Rejection::Refused(refusal)) => refused(out, &refusal),
        Err(Rejection::Limit(limit)) => not_examined(out, limit),
        Err(error @ Rejection::ExpectationsUndefined(_)) => {
            failed(out, "EXPECTATIONS_UNDEFINED", &error.to_string())
        }
        Err(error @ Rejection::RecordUndefined(_)) => {
            failed(out, "RECORD_UNDEFINED", &error.to_string())
        }
    }
}

/// The package text inside a file's bytes.
///
/// A package is canonical text, which has no trailing line end; a file
/// conventionally has one. Exactly one final line end (`\n` or `\r\n`) is
/// therefore the file's, not the package's. Anything else, a second line end
/// included, is left for the canonical-text check to refuse.
pub(crate) fn package_text(bytes: &[u8]) -> &[u8] {
    let text = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if text.len() == bytes.len() {
        bytes
    } else {
        text.strip_suffix(b"\r").unwrap_or(text)
    }
}

/// Reads a JSON file the relying party supplies. It is configuration, so it
/// need not be canonical text.
pub(crate) fn json_file(
    path: &std::path::Path,
    what: &str,
    limits: &Limits,
) -> Result<Value, String> {
    let name = path.display();
    let bytes = match input::read(path, limits.max_bytes) {
        Ok(bytes) => bytes,
        Err(InputError::Io(error)) => return Err(format!("{error:#}")),
        Err(InputError::TooLarge(limit)) => return Err(format!("{what} {name}: {limit}")),
    };
    parse(&bytes, limits).map_err(|error| format!("{what} {name}: {error}"))
}

/// Reads the relying party's registry. It must be exactly a registry.
pub(crate) fn registry(path: &std::path::Path, limits: &Limits) -> Result<Trust, String> {
    let value = json_file(path, "trust registry", limits)?;
    Trust::from_value(&value).map_err(|error| format!("trust registry {}: {error}", path.display()))
}

/// A canonical value as `serde_json` has it, for output.
pub(crate) fn output_json(value: &Value) -> serde_json::Value {
    // Canonical text is JSON; this cannot fail.
    serde_json::from_str(&value.to_canonical_string()).unwrap_or(serde_json::Value::Null)
}

/// The command could not run. Nothing is said about the package.
pub(crate) fn failed(out: &mut Output, code: &str, message: &str) -> Exit {
    if out.mode == Mode::Json {
        out.json(&json!({ "outcome": "error", "error": { "code": code, "message": message } }));
    }
    out.error(message);
    Exit::Failed
}

pub(crate) fn not_examined(out: &mut Output, limit: LimitExceeded) -> Exit {
    failed(out, "RESOURCE_LIMIT", &Rejection::Limit(limit).to_string())
}

pub(crate) fn refused(out: &mut Output, refusal: &Refusal) -> Exit {
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

pub(crate) fn digest_json(digest: &Sha256Digest) -> serde_json::Value {
    json!({ "algorithm": Sha256Digest::ALGORITHM, "hex": digest.to_hex() })
}

/// The JSON of a decision finding, as the library defines it.
pub(crate) fn decision_json(finding: &DecisionFinding) -> serde_json::Value {
    output_json(&finding.to_value())
}

/// The JSON of an issuer-signature finding, as the library defines it.
pub(crate) fn issuer_json(issuer: IssuerSignature) -> serde_json::Value {
    output_json(&issuer.to_value())
}

/// The `verify` JSON: the library's form of the report, and the note the
/// command line adds to an incomplete one.
fn report_json(report: &Report, complete: bool) -> serde_json::Value {
    let mut result = output_json(&report.to_value());
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

pub(crate) fn decision_rows(finding: &DecisionFinding) -> Vec<Row> {
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
            let width = column(conditions.iter().map(|c| &c.id));
            rows.extend(conditions.iter().map(|c| {
                let holds = if c.holds { "holds" } else { "does not hold" };
                Row::new("", truth(c.holds), format!("  {:<width$}{holds}", c.id))
            }));
        }
        Evaluation::WorkContract {
            requirements,
            ignored,
            conflicts,
        } => {
            let width = column(requirements.iter().map(|r| &r.id));
            rows.extend(requirements.iter().map(|r| {
                let tone = match r.value.as_str() {
                    "TRUE" => Tone::Established,
                    "FALSE" => Tone::Negative,
                    _ => Tone::Unknown,
                };
                Row::new("", tone, format!("  {:<width$}{}", r.id, r.value))
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

pub(crate) fn issuer_row(issuer: IssuerSignature) -> Row {
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
fn reported(
    out: &mut Output,
    report: &Report,
    required: Option<Decision>,
    any_contract: bool,
) -> Exit {
    let complete = report.is_complete();
    // A requirement is met only by a decision this run reproduced. The
    // decision a package carries never meets one.
    let reproduced = match &report.decision {
        DecisionFinding::Reproduced(reproduced) => Some(reproduced.decision),
        _ => None,
    };
    // Nor does one reproduced under a contract the caller did not pin,
    // unless the caller said that any contract will do.
    let pinned = report.contract_pinned() || any_contract;
    let met = required.map(|required| reproduced == Some(required) && pinned);
    match out.mode {
        Mode::Quiet => {}
        Mode::Json => {
            let mut result = report_json(report, complete);
            if let (Some(required), Some(met)) = (required, met) {
                result["requiredDecision"] = json!({
                    "decision": required.as_str(),
                    "met": met,
                    "anyContract": any_contract,
                });
            }
            out.json(&result);
        }
        Mode::Human => {
            human(out, report, complete);
            match (required, met, reproduced) {
                (Some(required), Some(false), Some(reproduced)) if reproduced != required => {
                    out.line(&format!(
                        "required decision {required} not met: the reproduced decision is {reproduced}"
                    ));
                }
                (Some(required), Some(false), Some(_)) => out.line(&format!(
                    "required decision {required} not met: the contract is not pinned; give \
                     --expect-contract with the digest you agreed, or --any-contract"
                )),
                (Some(required), Some(false), None) => out.line(&format!(
                    "required decision {required} not met: no decision was reproduced"
                )),
                (Some(required), Some(true), _) if !report.contract_pinned() => {
                    out.line(&format!(
                        "required decision {required} met, under the contract the package carries \
                         (--any-contract)"
                    ));
                }
                (Some(required), Some(true), _) => {
                    out.line(&format!("required decision {required} met"));
                }
                _ => {}
            }
        }
    }
    match (complete, met) {
        // Incomplete stays incomplete: without a reproduced decision there
        // is nothing a requirement could be measured against.
        (false, _) => Exit::Incomplete,
        (true, Some(false)) => Exit::DecisionNotRequired,
        (true, _) => Exit::Complete,
    }
}

/// What the relying party supplied from outside the package, and that it
/// was met: a work record, expectations.
fn binding_rows(report: &Report) -> Vec<Row> {
    let mut rows = Vec::new();
    if report.record_matched {
        rows.push(Row::new(
            "work record",
            Tone::Established,
            "the supplied record is about this package",
        ));
    }
    if !report.contract_pinned() {
        rows.push(Row::new(
            "contract pinned",
            Tone::Unknown,
            "NO: the decision is about the contract the package carries; \
             pin yours with --expect-contract",
        ));
    }
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
        rows.push(Row::new(
            "expectations",
            Tone::Established,
            format!("met ({})", given.join(", ")),
        ));
    }
    rows
}

pub(crate) fn human(out: &mut Output, report: &Report, complete: bool) {
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
    out.rows(&binding_rows(report));
    out.line("");
    match (&report.decision, complete) {
        (
            DecisionFinding::Reproduced(Reproduced {
                decision: Decision::Supported,
                ..
            }),
            true,
        ) if report.contract_pinned() => {
            out.line("complete: every protocol check ran; the decision SUPPORTED was reproduced");
        }
        (
            DecisionFinding::Reproduced(Reproduced {
                decision: Decision::Supported,
                ..
            }),
            true,
        ) => out.line(
            "complete: every protocol check ran; the decision SUPPORTED was reproduced under \
             the contract the package carries, which you did not pin",
        ),
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

/// The width of an identifier column: 28, or wider so that the longest identifier still leaves two
/// spaces before its value.
fn column<S: AsRef<str>>(ids: impl Iterator<Item = S>) -> usize {
    ids.map(|id| id.as_ref().chars().count() + 2)
        .max()
        .unwrap_or(0)
        .max(28)
}

#[cfg(test)]
mod column_tests {
    use super::column;

    #[test]
    fn short_identifiers_keep_the_usual_column_and_long_ones_widen_it() {
        assert_eq!(column(["POSTED", "APPROVED"].into_iter()), 28);
        assert_eq!(column(["S_DB_SECURITY_OWNER_APPROVED"].into_iter()), 30);
        assert_eq!(column(std::iter::empty::<&str>()), 28);
    }
}
