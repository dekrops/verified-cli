// SPDX-License-Identifier: Apache-2.0

//! `verified export`, `diff` and `replay`.
//!
//! Export adds nothing to a package. Diff compares what two packages say.
//! Replay recomputes; it never reuses a result.

use std::io::Write as _;
use std::path::Path;

use serde_json::json;
use verified_canonical::Limits;
use verified_protocol::Decision;
use verified_verifier::{
    DecisionFinding, Expectations, Inspection, Options, Rejection, inspect, verify,
};
use verified_workspace::{Stored, Workspace};

use crate::cli::{Diff, Export, Replay};
use crate::exit::Exit;
use crate::input::{self, InputError};
use crate::render::{Mode, Output, Row, Tone};
use crate::verify::{failed, package_text, registry};
use crate::workspace::{discover, load};

pub(crate) fn export(command: &Export, out: &mut Output) -> Exit {
    let (stored, bytes) = match load(&command.package, &Limits::DEFAULT) {
        Ok(loaded) => loaded,
        Err(message) => return failed(out, "WORKSPACE", &message),
    };
    let Some(path) = &command.output else {
        if out.mode == Mode::Json {
            return failed(
                out,
                "USAGE",
                "--json needs --output: standard output carries the package itself",
            );
        }
        // The package and nothing else: no line end, no decoration.
        let mut stdout = std::io::stdout().lock();
        return match stdout.write_all(&bytes).and_then(|()| stdout.flush()) {
            Ok(()) => Exit::Complete,
            Err(error) => failed(
                out,
                "IO_ERROR",
                &format!("cannot write standard output: {error}"),
            ),
        };
    };
    // Never overwrite: an export must not silently replace another file.
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut file| file.write_all(&bytes).and_then(|()| file.sync_all()));
    if let Err(error) = written {
        // A file this run created and could not finish is not left behind;
        // one that already existed was never opened.
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            let _ = std::fs::remove_file(path);
        }
        return failed(
            out,
            "IO_ERROR",
            &format!("cannot write {}: {error}", path.display()),
        );
    }
    match out.mode {
        Mode::Quiet => {}
        Mode::Json => out.json(&json!({
            "outcome": "exported",
            "package": stored.package.to_string(),
            "object": stored.object.to_string(),
            "bytes": bytes.len(),
            "output": path.display().to_string(),
            "note": "the exact imported text; nothing was added and nothing beyond integrity was checked",
        })),
        Mode::Human => {
            out.line(&format!(
                "Exported {} to {} ({} bytes).",
                stored.package,
                path.display(),
                bytes.len()
            ));
            out.line(
                "It is the exact text that was imported. Nothing was added, and nothing beyond \
                 its integrity was checked: the recipient verifies it under their own registry.",
            );
        }
    }
    Exit::Complete
}

/// One side of a comparison: a file, or a stored package.
struct Side {
    name: String,
    bytes: Vec<u8>,
    inspection: Inspection,
}

fn side(name: &str, limits: &Limits) -> Result<Side, (Exit, &'static str, String)> {
    let trouble = |code, message: String| (Exit::Failed, code, message);
    let path = Path::new(name);
    let bytes = if path.is_file() {
        match input::read(path, limits.max_bytes) {
            Ok(bytes) => package_text(&bytes).to_vec(),
            Err(InputError::Io(error)) => return Err(trouble("IO_ERROR", format!("{error:#}"))),
            Err(InputError::TooLarge(limit)) => {
                return Err(trouble(
                    "RESOURCE_LIMIT",
                    Rejection::Limit(limit).to_string(),
                ));
            }
        }
    } else {
        load(name, limits)
            .map_err(|message| trouble("WORKSPACE", message))?
            .1
    };
    let options = Options {
        limits: *limits,
        ..Options::default()
    };
    match inspect(&bytes, &options) {
        Ok(inspection) => Ok(Side {
            name: name.to_owned(),
            bytes,
            inspection,
        }),
        Err(Rejection::Refused(refusal)) => Err((
            Exit::Failed,
            "NOT_COMPARABLE",
            format!("{name} is refused ({refusal}); only packages with integrity are compared"),
        )),
        Err(other) => Err(trouble("NOT_COMPARABLE", format!("{name}: {other}"))),
    }
}

/// What two packages state differently: `(what, a, b)`.
fn stated_differences(a: &Inspection, b: &Inspection) -> Vec<(&'static str, String, String)> {
    let contract = |i: &Inspection| {
        i.report.contract.as_ref().map_or_else(
            || i.contract_reference.clone(),
            |c| format!("{} {}, sha-256:{}", c.id, c.version, c.digest),
        )
    };
    let signers = |i: &Inspection| match i.issuer_signature_keys.as_slice() {
        [] => "none".to_owned(),
        keys => keys.join(", "),
    };
    let rows = [
        (
            "protocol",
            a.report.protocol.to_string(),
            b.report.protocol.to_string(),
        ),
        ("tenant", a.report.tenant.clone(), b.report.tenant.clone()),
        ("claim", a.claim.id.clone(), b.claim.id.clone()),
        (
            "claimant",
            a.claim.claimant.clone(),
            b.claim.claimant.clone(),
        ),
        ("contract", contract(a), contract(b)),
        (
            "recorded decision",
            a.recorded_decision.clone(),
            b.recorded_decision.clone(),
        ),
        ("issuer signatures", signers(a), signers(b)),
    ];
    rows.into_iter().filter(|(_, a, b)| a != b).collect()
}

fn diff_human(
    out: &mut Output,
    a: &Side,
    b: &Side,
    components: &[(&str, bool)],
    stated: &[(&'static str, String, String)],
    [only_a, only_b]: [&Vec<String>; 2],
    (identical, same_package): (bool, bool),
) {
    let id = |i: &Inspection| {
        format!(
            "wvp:sha-256:{}",
            out.short(&i.report.package_id.commitment().to_hex())
        )
    };
    out.rows(&[
        Row::new(
            "a",
            Tone::Plain,
            format!("{} ({})", id(&a.inspection), a.name),
        ),
        Row::new(
            "b",
            Tone::Plain,
            format!("{} ({})", id(&b.inspection), b.name),
        ),
    ]);
    out.line("");
    if identical {
        out.line("identical: the two texts are the same, byte for byte");
        return;
    }
    let rows: Vec<Row> = components
        .iter()
        .map(|(path, same)| {
            let (tone, text) = if *same {
                (Tone::Plain, "same")
            } else {
                (Tone::Unknown, "differs")
            };
            Row::new("", tone, format!("{path:<26}{text}"))
        })
        .collect();
    out.line("components");
    out.rows(&rows);
    if !stated.is_empty() {
        out.line("");
        out.line("stated differently (checked by nobody)");
        for (what, a, b) in stated {
            out.rows(&[
                Row::new(what, Tone::Plain, format!("a: {a}")),
                Row::new("", Tone::Plain, format!("b: {b}")),
            ]);
        }
    }
    for (label, only) in [
        ("statements only in a", only_a),
        ("statements only in b", only_b),
    ] {
        if !only.is_empty() {
            out.rows(&[Row::new(label, Tone::Plain, only.join(", "))]);
        }
    }
    out.line("");
    if same_package {
        out.line(
            "different texts of one package: the identifier is the same, so they differ \
             only outside what it commits to (issuer signatures)",
        );
    } else {
        out.line("different packages");
    }
}

pub(crate) fn diff(command: &Diff, out: &mut Output) -> Exit {
    let limits = Limits::DEFAULT;
    let load = |name: &str, out: &mut Output| {
        side(name, &limits).map_err(|(exit, code, message)| {
            failed(out, code, &message);
            exit
        })
    };
    let (a, b) = match (load(&command.a, out), load(&command.b, out)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(exit), _) | (_, Err(exit)) => return exit,
    };
    let identical = a.bytes == b.bytes;
    let same_package = a.inspection.report.package_id == b.inspection.report.package_id;
    let components: Vec<(&str, bool)> = a
        .inspection
        .report
        .components
        .iter()
        .zip(&b.inspection.report.components)
        .map(|(x, y)| (x.path.as_str(), x.digest == y.digest))
        .collect();
    let stated = stated_differences(&a.inspection, &b.inspection);
    let ids = |i: &Inspection| {
        i.statements
            .iter()
            .map(|s| s.id.clone())
            .collect::<Vec<_>>()
    };
    let (ids_a, ids_b) = (ids(&a.inspection), ids(&b.inspection));
    let only_a: Vec<String> = ids_a
        .iter()
        .filter(|id| !ids_b.contains(id))
        .cloned()
        .collect();
    let only_b: Vec<String> = ids_b
        .iter()
        .filter(|id| !ids_a.contains(id))
        .cloned()
        .collect();

    match out.mode {
        Mode::Quiet => {}
        Mode::Json => out.json(&json!({
            "outcome": if identical { "identical" } else { "different" },
            "a": { "name": a.name, "package": a.inspection.report.package_id.to_string() },
            "b": { "name": b.name, "package": b.inspection.report.package_id.to_string() },
            "samePackageIdentifier": same_package,
            "components": components.iter().map(|(path, same)| json!({ "path": path, "same": same })).collect::<Vec<_>>(),
            "stated": stated.iter().map(|(what, a, b)| json!({ "what": what, "a": a, "b": b })).collect::<Vec<_>>(),
            "statementsOnlyInA": only_a,
            "statementsOnlyInB": only_b,
            "note": "integrity of both packages only; every difference is between what two packages state",
        })),
        Mode::Human => diff_human(
            out,
            &a,
            &b,
            &components,
            &stated,
            [&only_a, &only_b],
            (identical, same_package),
        ),
    }
    // As `diff` does: 0 the same, 1 different, 2 trouble.
    if identical {
        Exit::Complete
    } else {
        Exit::Refused
    }
}

/// What verifying one stored package now concluded.
enum Replayed {
    /// The decision reproduced, and whether its contract was pinned.
    Reproduced(Decision, bool),
    Refused(String),
    Damaged(String),
}

fn replay_one(workspace: &Workspace, stored: &Stored, options: &Options<'_>) -> Replayed {
    let bytes = match workspace.read(stored, &options.limits) {
        Ok(bytes) => bytes,
        Err(error) => return Replayed::Damaged(error.to_string()),
    };
    match verify(&bytes, options) {
        Ok(report) => match &report.decision {
            DecisionFinding::Reproduced(reproduced) if report.is_complete() => {
                Replayed::Reproduced(reproduced.decision, report.contract_pinned())
            }
            // A registry was supplied, so a report is complete; anything
            // else is not something to call a success.
            _ => Replayed::Refused("verification did not complete".to_owned()),
        },
        Err(Rejection::Refused(refusal)) => Replayed::Refused(refusal.code.to_string()),
        Err(other) => Replayed::Refused(other.to_string()),
    }
}

/// One package's line in `replay --json`.
fn replayed_json(stored: &Stored, result: &Replayed) -> serde_json::Value {
    let (status, detail, pinned) = match result {
        Replayed::Reproduced(decision, pinned) => {
            ("reproduced", decision.to_string(), Some(*pinned))
        }
        Replayed::Refused(code) => ("refused", code.clone(), None),
        Replayed::Damaged(detail) => ("damaged", detail.clone(), None),
    };
    let mut entry = json!({
        "package": stored.package.to_string(),
        "object": stored.object.to_string(),
        "status": status,
        "detail": detail,
    });
    if let Some(pinned) = pinned {
        entry["contractPinned"] = json!(pinned);
    }
    entry
}

pub(crate) fn replay(command: &Replay, out: &mut Output) -> Exit {
    let limits = Limits::DEFAULT;
    let trust = match registry(&command.trust, &limits) {
        Ok(trust) => trust,
        Err(message) => return failed(out, "TRUST_REGISTRY", &message),
    };
    let workspace = match discover() {
        Ok(workspace) => workspace,
        Err(message) => return failed(out, "WORKSPACE", &message),
    };
    let selected: Result<Vec<Stored>, String> = if command.packages.is_empty() {
        workspace.stored().map_err(|error| error.to_string())
    } else {
        command
            .packages
            .iter()
            .map(|name| workspace.resolve(name).map_err(|error| error.to_string()))
            .collect()
    };
    let selected = match selected {
        Ok(selected) => selected,
        Err(message) => return failed(out, "WORKSPACE", &message),
    };
    let options = Options {
        limits,
        trust: Some(&trust),
        expectations: Expectations {
            contract: command.expect_contract,
            ..Expectations::default()
        },
        ..Options::default()
    };
    let results: Vec<(Stored, Replayed)> = selected
        .into_iter()
        .map(|stored| (stored, replay_one(&workspace, &stored, &options)))
        .collect();

    let failed_count = results
        .iter()
        .filter(|(_, r)| !matches!(r, Replayed::Reproduced(..)))
        .count();
    let unmet = command.require_decision.map_or(0, |required| {
        results
            .iter()
            .filter(|(_, r)| {
                matches!(r, Replayed::Reproduced(d, pinned)
                    if *d != required || !(*pinned || command.any_contract))
            })
            .count()
    });
    match out.mode {
        Mode::Quiet => {}
        Mode::Json => out.json(&json!({
            "outcome": if failed_count > 0 { "failed" } else if unmet > 0 { "decision_not_required" } else { "replayed" },
            "packages": results.iter().map(|(stored, result)| replayed_json(stored, result)).collect::<Vec<_>>(),
            "requiredDecision": command.require_decision.map(Decision::as_str),
            "note": "every result was computed in this run under the supplied registry; nothing was reused",
        })),
        Mode::Human => {
            for (stored, result) in &results {
                let id = format!("wvp:sha-256:{}", out.short(&stored.package.commitment().to_hex()));
                let (tone, text) = match result {
                    Replayed::Reproduced(Decision::Supported, true) => (Tone::Established, "SUPPORTED reproduced".to_owned()),
                    Replayed::Reproduced(decision, true) => (Tone::Unknown, format!("{decision} reproduced")),
                    Replayed::Reproduced(decision, false) => (Tone::Unknown, format!("{decision} reproduced, contract not pinned")),
                    Replayed::Refused(code) => (Tone::Negative, format!("refused: {code}")),
                    Replayed::Damaged(detail) => (Tone::Negative, format!("damaged: {detail}")),
                };
                out.rows(&[Row::new("", tone, format!("{id}  {text}"))]);
            }
            out.line("");
            out.line(&format!(
                "{} package(s) verified now under the supplied registry; {failed_count} refused or damaged. \
                 Nothing was reused from an earlier run.",
                results.len()
            ));
            if let Some(required) = command.require_decision {
                out.line(&format!(
                    "required decision {required}: {unmet} package(s) reproduced another, or under a contract not pinned"
                ));
            }
        }
    }
    if failed_count > 0 {
        Exit::Refused
    } else if unmet > 0 {
        Exit::DecisionNotRequired
    } else {
        Exit::Complete
    }
}
