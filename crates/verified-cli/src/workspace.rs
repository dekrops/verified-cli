// SPDX-License-Identifier: Apache-2.0

//! `verified init`, `import`, `show` and `log`: the local workspace.
//!
//! Nothing here verifies anything beyond package integrity, and every
//! command says so in its output.

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;
use verified_canonical::Limits;
use verified_verifier::{Inspection, Options, Rejection, inspect};
use verified_workspace::{ImportError, Problem, ResolveError, Stored, Workspace};

use crate::cli::{Import, Init, Show};
use crate::exit::Exit;
use crate::input::{self, InputError};
use crate::render::{Mode, Output, Row, Tone};
use crate::verify::{TITLE, digest_json, failed, not_examined, package_text, refused};

const NOT_ACCEPTED: &str = "imported, not verified: importing is not accepting. No signature was \
     checked and the decision was not reproduced";
const LOCAL_HISTORY: &str = "local and unauthenticated: this workspace's own note of what it \
     imported, by this machine's clock; not a history of work";

fn current_directory() -> Result<std::path::PathBuf, String> {
    std::env::current_dir().map_err(|error| format!("cannot find the current directory: {error}"))
}

pub(crate) fn discover() -> Result<Workspace, String> {
    Workspace::discover(&current_directory()?).map_err(|error| error.to_string())
}

/// Resolves a name in the current workspace and reads the package it names,
/// checked against its identifiers.
pub(crate) fn load(name: &str, limits: &Limits) -> Result<(Stored, Vec<u8>), String> {
    let workspace = discover()?;
    let stored = workspace.resolve(name).map_err(|error| match error {
        // Say which texts there are, so that one can be named.
        ResolveError::Variants { ref objects, .. } => {
            let listed: Vec<String> = objects.iter().map(ToString::to_string).collect();
            format!("{error}: {}", listed.join(", "))
        }
        ResolveError::Ambiguous { ref packages, .. } => {
            let listed: Vec<String> = packages.iter().map(ToString::to_string).collect();
            format!("{error}: {}", listed.join(", "))
        }
        other => other.to_string(),
    })?;
    let bytes = workspace
        .read(&stored, limits)
        .map_err(|error| error.to_string())?;
    Ok((stored, bytes))
}

/// Seconds since 1970-01-01T00:00:00Z as `YYYY-MM-DDTHH:MM:SSZ`.
pub(crate) fn utc(unix: u64) -> String {
    let days = unix / 86_400;
    let (hour, minute, second) = ((unix % 86_400) / 3_600, (unix % 3_600) / 60, unix % 60);
    // Days to a civil date, by eras of 400 years starting on 1 March.
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

pub(crate) fn init(command: &Init, out: &mut Output) -> Exit {
    let parent = match &command.directory {
        Some(directory) => directory.clone(),
        None => match current_directory() {
            Ok(directory) => directory,
            Err(message) => return failed(out, "WORKSPACE", &message),
        },
    };
    let (workspace, created) = match Workspace::init(&parent) {
        Ok(result) => result,
        Err(error) => return failed(out, "WORKSPACE", &error.to_string()),
    };
    let path = workspace.directory().display().to_string();
    match out.mode {
        Mode::Quiet => {}
        Mode::Json => out.json(&json!({
            "outcome": if created { "initialized" } else { "exists" },
            "workspace": path,
        })),
        Mode::Human => {
            if created {
                out.line(&format!(
                    "Initialized an empty Verified workspace in {path}"
                ));
            } else {
                out.line(&format!("A Verified workspace already exists in {path}"));
            }
            out.line("It is a cache for inspection, and authoritative for nothing.");
        }
    }
    Exit::Complete
}

pub(crate) fn import(command: &Import, out: &mut Output) -> Exit {
    let limits = Limits::DEFAULT;
    let workspace = match discover() {
        Ok(workspace) => workspace,
        Err(message) => return failed(out, "WORKSPACE", &message),
    };
    let bytes = match input::read(&command.package, limits.max_bytes) {
        Ok(bytes) => bytes,
        Err(InputError::Io(error)) => return failed(out, "IO_ERROR", &format!("{error:#}")),
        Err(InputError::TooLarge(limit)) => return not_examined(out, limit),
    };
    // The clock is read here and nowhere else: for the local import history.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let imported = match workspace.import(package_text(&bytes), now, &limits) {
        Ok(imported) => imported,
        Err(ImportError::Rejected(Rejection::Refused(refusal))) => return refused(out, &refusal),
        Err(ImportError::Rejected(Rejection::Limit(limit))) => return not_examined(out, limit),
        Err(error) => return failed(out, "WORKSPACE", &error.to_string()),
    };
    let stored = imported.stored;
    match out.mode {
        Mode::Quiet => {}
        Mode::Json => out.json(&json!({
            "outcome": "imported",
            "package": stored.package.to_string(),
            "object": stored.object.to_string(),
            "protocol": imported.protocol.identifier(),
            "alreadyPresent": imported.already_present,
            "properties": {
                "packageIntegrity": { "status": "established" },
                "evidenceSignatures": { "status": "not_checked", "reason": "import_does_not_verify" },
                "decisionReproduced": { "status": "not_checked", "reason": "import_does_not_verify" },
            },
            "note": NOT_ACCEPTED,
        })),
        Mode::Human => {
            let what = if imported.already_present {
                "already stored"
            } else {
                "stored"
            };
            out.rows(&[
                Row::new(
                    "package",
                    Tone::Plain,
                    format!(
                        "wvp:sha-256:{} ({}, draft), {what}",
                        out.short(&stored.package.commitment().to_hex()),
                        imported.protocol
                    ),
                ),
                Row::new("package integrity", Tone::Established, "established"),
            ]);
            out.line("");
            out.line(&format!(
                "{NOT_ACCEPTED}. To check it: verified verify {} --trust <registry>",
                stored.package
            ));
        }
    }
    Exit::Complete
}

pub(crate) fn show(command: &Show, out: &mut Output) -> Exit {
    let limits = Limits::DEFAULT;
    let (stored, bytes) = match load(&command.package, &limits) {
        Ok(loaded) => loaded,
        Err(message) => return failed(out, "WORKSPACE", &message),
    };
    let options = Options {
        limits,
        ..Options::default()
    };
    let inspection = match inspect(&bytes, &options) {
        Ok(inspection) => inspection,
        // `load` has just verified the same bytes; this cannot differ.
        Err(error) => return failed(out, "WORKSPACE", &error.to_string()),
    };
    let imports: Vec<u64> = discover()
        .and_then(|workspace| workspace.history().map_err(|error| error.to_string()))
        .map(|history| {
            let records = history
                .records
                .iter()
                .filter(|record| record.stored == stored);
            records.map(|record| record.imported_at_unix).collect()
        })
        .unwrap_or_default();
    match out.mode {
        Mode::Quiet => {}
        Mode::Json => show_json(out, &stored, bytes.len(), &inspection, &imports),
        Mode::Human => show_human(out, &stored, bytes.len(), &inspection, &imports),
    }
    Exit::Complete
}

fn show_json(
    out: &mut Output,
    stored: &Stored,
    size: usize,
    inspection: &Inspection,
    imports: &[u64],
) {
    let report = &inspection.report;
    let mut result = json!({
        "outcome": "shown",
        "package": stored.package.to_string(),
        "object": stored.object.to_string(),
        "bytes": size,
        "protocol": report.protocol.identifier(),
        "protocolStatus": "draft",
        "packageIntegrity": { "status": "established" },
        "stated": {
            "tenant": report.tenant,
            "claim": report.claim,
            "decision": inspection.recorded_decision,
            "statements": inspection.statements.iter().map(|s| json!({
                "id": s.id, "kind": s.kind, "source": s.source, "issuer": s.issuer,
                "keyId": s.key_id, "observedAt": s.observed_at,
            })).collect::<Vec<_>>(),
            "issuerSignatureKeys": inspection.issuer_signature_keys,
            "status": "stated_by_the_package_not_verified",
        },
        "importedAtUnix": imports,
    });
    if let Some(contract) = &report.contract {
        result["stated"]["contract"] = json!({
            "id": contract.id,
            "version": contract.version,
            "digest": digest_json(&contract.digest),
        });
    }
    out.json(&result);
}

fn show_human(
    out: &mut Output,
    stored: &Stored,
    size: usize,
    inspection: &Inspection,
    imports: &[u64],
) {
    let report = &inspection.report;
    out.heading(&format!("{TITLE} ({}, draft)", report.protocol));
    out.rows(&[
        Row::new(
            "package",
            Tone::Plain,
            format!(
                "wvp:sha-256:{}",
                out.short(&stored.package.commitment().to_hex())
            ),
        ),
        Row::new(
            "object",
            Tone::Plain,
            format!(
                "object:sha-256:{}, {} bytes",
                out.short(&stored.object.digest().to_hex()),
                size
            ),
        ),
        Row::new("package integrity", Tone::Established, "established"),
    ]);
    out.line("");
    out.line("Stated by the package, and checked by nobody:");
    out.rows(&[
        Row::new("tenant", Tone::Plain, &report.tenant),
        Row::new("claim", Tone::Plain, &report.claim),
    ]);
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
    out.rows(&[Row::new(
        "recorded decision",
        Tone::Unknown,
        format!(
            "{} (the issuer's claim, not reproduced)",
            inspection.recorded_decision
        ),
    )]);
    out.rows(&[Row::new(
        "evidence statements",
        Tone::Plain,
        format!("{} (signatures not checked)", inspection.statements.len()),
    )]);
    let statements: Vec<Row> = inspection
        .statements
        .iter()
        .map(|s| {
            Row::new(
                "",
                Tone::Plain,
                format!(
                    "  {}  {}  from {}  key {}  {}",
                    s.id, s.kind, s.source, s.key_id, s.observed_at
                ),
            )
        })
        .collect();
    out.rows(&statements);
    let signers = match inspection.issuer_signature_keys.as_slice() {
        [] => "none".to_owned(),
        keys => format!(
            "{} carried, by key {} (not checked)",
            keys.len(),
            keys.join(", ")
        ),
    };
    out.rows(&[Row::new("issuer signatures", Tone::Plain, signers)]);
    if !imports.is_empty() {
        let times: Vec<String> = imports.iter().map(|at| utc(*at)).collect();
        out.rows(&[Row::new(
            "imported here",
            Tone::Plain,
            format!("{} (this machine's clock)", times.join(", ")),
        )]);
    }
    out.line("");
    out.line(&format!(
        "not verified. To check it: verified verify {} --trust <registry>",
        stored.package
    ));
}

pub(crate) fn log(out: &mut Output) -> Exit {
    let history = match discover().and_then(|w| w.history().map_err(|error| error.to_string())) {
        Ok(history) => history,
        Err(message) => return failed(out, "WORKSPACE", &message),
    };
    match out.mode {
        Mode::Quiet => {}
        Mode::Json => out.json(&json!({
            "imports": history.records.iter().rev().map(|record| json!({
                "importedAtUnix": record.imported_at_unix,
                "importedAt": utc(record.imported_at_unix),
                "package": record.stored.package.to_string(),
                "object": record.stored.object.to_string(),
                "protocol": record.protocol.identifier(),
            })).collect::<Vec<_>>(),
            "damagedRecords": history.damaged,
            "note": LOCAL_HISTORY,
        })),
        Mode::Human => {
            out.heading("Import history");
            out.line(&format!("({LOCAL_HISTORY})"));
            out.line("");
            if history.records.is_empty() {
                out.line("nothing imported yet");
            }
            for record in history.records.iter().rev() {
                out.line(&format!(
                    "{}  wvp:sha-256:{}  {}",
                    utc(record.imported_at_unix),
                    out.short(&record.stored.package.commitment().to_hex()),
                    record.protocol
                ));
            }
            if history.damaged > 0 {
                out.line("");
                out.line(&format!(
                    "{} record(s) of the history are damaged and were not shown",
                    history.damaged
                ));
            }
        }
    }
    Exit::Complete
}

/// One finding as a short tag and a sentence.
fn describe(problem: &Problem) -> (&'static str, String) {
    match problem {
        Problem::Damaged { stored, detail } => (
            "damaged",
            format!("{} of {}: {detail}", stored.object, stored.package),
        ),
        Problem::Foreign { path } => (
            "foreign",
            format!("{}: not something this tool writes", path.display()),
        ),
        Problem::DamagedHistory { lines } => (
            "history",
            format!("{lines} line(s) of the import history cannot be read"),
        ),
        Problem::UnreadableHistory { detail } => (
            "history",
            format!("{detail}; it was not compared with the stored packages"),
        ),
        Problem::MissingObject { record } => (
            "missing",
            format!(
                "{} of {}: imported {}, and no longer stored",
                record.stored.object,
                record.stored.package,
                utc(record.imported_at_unix)
            ),
        ),
        Problem::Leftover { path } => (
            "leftover",
            format!(
                "{}: temporary file of an interrupted import (harmless)",
                path.display()
            ),
        ),
        Problem::Unrecorded { stored } => (
            "unrecorded",
            format!(
                "{} of {}: stored, with no import recorded (harmless)",
                stored.object, stored.package
            ),
        ),
    }
}

pub(crate) fn fsck(out: &mut Output) -> Exit {
    let checked = discover().and_then(|workspace| {
        workspace
            .check(&Limits::DEFAULT)
            .map_err(|error| error.to_string())
    });
    let check = match checked {
        Ok(check) => check,
        Err(message) => return failed(out, "WORKSPACE", &message),
    };
    let damaged = check.has_damage();
    match out.mode {
        Mode::Quiet => {}
        Mode::Json => out.json(&json!({
            "outcome": if damaged { "damaged" } else { "clean" },
            "objects": check.objects,
            "records": check.records,
            "problems": check.problems.iter().map(|problem| {
                let (kind, detail) = describe(problem);
                json!({ "kind": kind, "damage": problem.is_damage(), "detail": detail })
            }).collect::<Vec<_>>(),
            "note": "integrity of the stored bytes only; no signature was checked and no decision reproduced",
        })),
        Mode::Human => {
            out.line(&format!(
                "Checked {} stored package(s) and {} import record(s).",
                check.objects, check.records
            ));
            for problem in &check.problems {
                let (kind, detail) = describe(problem);
                let tone = if problem.is_damage() { Tone::Negative } else { Tone::Unknown };
                out.rows(&[Row::new(kind, tone, detail)]);
            }
            out.line("");
            if damaged {
                let count = check.problems.iter().filter(|p| p.is_damage()).count();
                out.line(&format!("damage found: {count} problem(s). Nothing was changed."));
            } else {
                out.line(
                    "no damage found. Every stored package is the content its names commit to; \
                     that says nothing about its signatures or its decision.",
                );
            }
        }
    }
    if damaged {
        Exit::Refused
    } else {
        Exit::Complete
    }
}

#[cfg(test)]
mod tests {
    use super::utc;

    #[test]
    fn unix_seconds_as_utc() {
        assert_eq!(utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc(951_825_600), "2000-02-29T12:00:00Z");
        assert_eq!(utc(1_767_225_599), "2025-12-31T23:59:59Z");
        assert_eq!(utc(1_772_359_200), "2026-03-01T10:00:00Z");
        assert_eq!(utc(4_102_444_800), "2100-01-01T00:00:00Z");
    }
}
