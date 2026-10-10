// SPDX-License-Identifier: Apache-2.0

//! `verified trace`: how the parts of one package relate.
//!
//! A trace draws only what the package contains. Without a registry every
//! link is the package's own statement; with one, the package is verified
//! first and the links are the ones verification checked.

use serde_json::json;
use verified_canonical::Limits;
use verified_verifier::{
    DecisionFinding, Evaluation, Inspection, Options, Rejection, Reproduced, inspect,
};

use crate::cli::Trace;
use crate::exit::Exit;
use crate::render::{Mode, Output, Row, Tone};
use crate::verify::{
    decision_json, decision_rows, failed, issuer_json, issuer_row, not_examined, refused, registry,
};
use crate::workspace::load;

const SCOPE: &str = "Only what this package contains is shown. It links to no other package and \
     carries no acceptance, finalization or ledger history.";
const STATED: &str = "stated by the package, not checked (no trust registry)";
const CHECKED: &str = "checked: the package verified completely under the supplied registry";

/// The facts the contract set aside, when a `wvp-0.2` decision was
/// reproduced. A fact is named `e-` followed by its statement's identifier.
fn ignored(inspection: &Inspection) -> Option<&[String]> {
    match &inspection.report.decision {
        DecisionFinding::Reproduced(Reproduced {
            evaluation: Evaluation::WorkContract { ignored, .. },
            ..
        }) => Some(ignored),
        _ => None,
    }
}

pub(crate) fn run(command: &Trace, out: &mut Output) -> Exit {
    let limits = Limits::DEFAULT;
    let trust = match command.trust.as_deref().map(|path| registry(path, &limits)) {
        None => None,
        Some(Ok(trust)) => Some(trust),
        Some(Err(message)) => return failed(out, "TRUST_REGISTRY", &message),
    };
    let (stored, bytes) = match load(&command.package, &limits) {
        Ok(loaded) => loaded,
        Err(message) => return failed(out, "WORKSPACE", &message),
    };
    let options = Options {
        limits,
        trust: trust.as_ref(),
        ..Options::default()
    };
    let inspection = match inspect(&bytes, &options) {
        Ok(inspection) => inspection,
        // Under a registry a package can be refused. There is then nothing
        // checked to trace, and an unchecked trace was not what was asked.
        Err(Rejection::Refused(refusal)) => return refused(out, &refusal),
        Err(Rejection::Limit(limit)) => return not_examined(out, limit),
        Err(error) => return failed(out, "WORKSPACE", &error.to_string()),
    };
    let checked = inspection.report.is_complete();
    match out.mode {
        Mode::Quiet => {}
        Mode::Json => out.json(&trace_json(
            &stored.package.to_string(),
            &inspection,
            checked,
        )),
        Mode::Human => human(
            out,
            &stored.package.commitment().to_hex(),
            &inspection,
            checked,
        ),
    }
    Exit::Complete
}

fn trace_json(package: &str, inspection: &Inspection, checked: bool) -> serde_json::Value {
    let report = &inspection.report;
    let ignored = ignored(inspection);
    json!({
        "outcome": "traced",
        "package": package,
        "protocol": report.protocol.identifier(),
        "protocolStatus": "draft",
        "links": if checked { "checked" } else { "stated_not_checked" },
        "scope": SCOPE,
        "claim": {
            "id": report.claim,
            "tenant": report.tenant,
            "namesContract": inspection.contract_reference,
            "evidenceNotCarried": inspection.claimed_but_absent,
        },
        "contract": report.contract.as_ref().map(|contract| json!({
            "id": contract.id,
            "version": contract.version,
            "digest": format!("sha-256:{}", contract.digest),
        })),
        "evidence": inspection.statements.iter().map(|s| json!({
            "statement": s.id,
            "kind": s.kind,
            "source": s.source,
            "issuer": s.issuer,
            "keyId": s.key_id,
            "observedAt": s.observed_at,
            "commitsTo": s.body,
            "listedByClaim": s.claimed,
            "ignoredByContract": ignored.map(|ids| ids.contains(&format!("e-{}", s.id))),
        })).collect::<Vec<_>>(),
        "decision": {
            "recorded": inspection.recorded_decision,
            "reproduced": decision_json(&report.decision),
            "issuerSignature": issuer_json(report.issuer_signature),
            "issuerSignatureKeys": inspection.issuer_signature_keys,
        },
    })
}

fn human(out: &mut Output, commitment: &str, inspection: &Inspection, checked: bool) {
    let report = &inspection.report;
    let ignored = ignored(inspection);
    out.heading(&format!(
        "Trace of wvp:sha-256:{} ({}, draft)",
        out.short(commitment),
        report.protocol
    ));
    out.line(SCOPE);
    out.rows(&[Row::new(
        "links",
        if checked {
            Tone::Established
        } else {
            Tone::Unknown
        },
        if checked { CHECKED } else { STATED },
    )]);
    out.line("");

    let contract = match &report.contract {
        Some(contract) => format!(
            "contract {} {}, sha-256:{}",
            contract.id,
            contract.version,
            out.short(&contract.digest.to_hex())
        ),
        None => format!("contract {}", inspection.contract_reference),
    };
    out.rows(&[
        Row::new(
            "claim",
            Tone::Plain,
            format!("{} (tenant {})", report.claim, report.tenant),
        ),
        Row::new("  made against", Tone::Plain, contract),
        Row::new(
            "  relies on",
            Tone::Plain,
            format!(
                "{} evidence statement(s)",
                inspection.statements.iter().filter(|s| s.claimed).count()
            ),
        ),
    ]);
    for statement in &inspection.statements {
        let mut rows = vec![
            Row::new("  statement", Tone::Plain, &statement.id),
            Row::new(
                "    asserts",
                Tone::Plain,
                format!(
                    "{} observed in {} at {}",
                    statement.kind, statement.source, statement.observed_at
                ),
            ),
            Row::new(
                "    signed with",
                Tone::Plain,
                format!("key {} of issuer {}", statement.key_id, statement.issuer),
            ),
            Row::new("    commits to", Tone::Plain, &statement.body),
        ];
        if !statement.claimed {
            rows.push(Row::new(
                "    note",
                Tone::Negative,
                "carried, but the claim does not list it",
            ));
        }
        if ignored.is_some_and(|ids| ids.contains(&format!("e-{}", statement.id))) {
            rows.push(Row::new(
                "    note",
                Tone::Unknown,
                "authentic, and ignored: the contract does not accept this source for this kind",
            ));
        }
        out.rows(&rows);
    }
    for id in &inspection.claimed_but_absent {
        out.rows(&[Row::new(
            "  not carried",
            Tone::Negative,
            format!("{id}: listed by the claim, absent from the package"),
        )]);
    }

    out.line("");
    out.rows(&[Row::new(
        "decision recorded",
        Tone::Plain,
        format!("{} (the issuer's claim)", inspection.recorded_decision),
    )]);
    out.rows(&decision_rows(&report.decision));
    out.rows(&[issuer_row(report.issuer_signature)]);
    out.rows(&[Row::new(
        "source truthfulness",
        Tone::Negative,
        "NOT established: no check can establish it",
    )]);
}
