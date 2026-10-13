// SPDX-License-Identifier: Apache-2.0

//! `verified derivation`: replay, inspect and compare a recomputed
//! authorization (draft). Every rule is in `verified_derivation`; this reads
//! files, bounds them and prints.

use serde_json::json;
use verified_canonical::{Limits, Value};
use verified_derivation::{Failure, Replayed, replay};

use crate::cli::{DerivationCompare, DerivationInspect, DerivationReplay};
use crate::exit::Exit;
use crate::render::{Mode, Output, Row, Tone, printable};
use crate::verify::{failed, json_file, output_json, registry};

const TITLE: &str = "Recomputed authorization (draft, not a WVP verification)";
const NOTICE: &str =
    "Draft and experimental: this is not a WVP verification and not a Work Record.";

fn member<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    value.as_object()?.get(name)
}

/// A package, or an example case that carries one under `package`.
fn package(path: &std::path::Path) -> Result<Value, String> {
    let value = json_file(path, "package", &Limits::DEFAULT)?;
    let inner = member(&value, "package")
        .filter(|inner| inner.as_object().is_some())
        .cloned();
    Ok(inner.unwrap_or(value))
}

fn reproduced(out: &mut Output, replayed: &Replayed) {
    let authorization: Vec<serde_json::Value> = replayed
        .derivations
        .iter()
        .map(|d| {
            json!({
                "correlation": d.correlation,
                "outcome": d.outcome,
                "reasons": d.reasons,
                "commitment": { "algorithm": "sha-256", "hex": d.commitment.to_hex() },
                "diagnostics": output_json(&d.diagnostics),
            })
        })
        .collect();
    match out.mode {
        Mode::Quiet => {}
        Mode::Json => out.json(&json!({
            "outcome": "reproduced",
            "draft": true,
            "commitment": { "algorithm": "sha-256", "hex": replayed.commitment.to_hex() },
            "decision": replayed.decision,
            "authorization": authorization,
            "bindings": member(&replayed.core, "bindings").map(output_json),
        })),
        Mode::Human => {
            out.heading(TITLE);
            let mut rows = vec![
                Row::new(
                    "replay",
                    Tone::Established,
                    "every commitment was computed again and is the one presented",
                ),
                Row::new("decision", Tone::Plain, replayed.decision.clone()),
            ];
            for d in &replayed.derivations {
                let reasons = if d.reasons.is_empty() {
                    String::new()
                } else {
                    format!(": {}", d.reasons.join(", "))
                };
                let text = format!("{} {}{reasons}", printable(&d.correlation), d.outcome);
                rows.push(Row::new("authorization", Tone::Plain, text));
            }
            let bound = member(&replayed.core, "bindings")
                .and_then(Value::as_array)
                .unwrap_or(&[]);
            for binding in bound {
                let name = member(binding, "requirement")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let text = format!("{} depends on the derived records", printable(name));
                rows.push(Row::new("requirement", Tone::Plain, text));
            }
            rows.push(Row::new(
                "commitment",
                Tone::Plain,
                out.short(&replayed.commitment.to_hex()),
            ));
            out.rows(&rows);
            out.line(NOTICE);
            out.line("It rests on your trust registry and on what its sources signed, not on the package.");
        }
    }
}

fn not_reproduced(out: &mut Output, failure: &Failure) {
    let detail: Vec<&str> = failure.detail.lines().collect();
    match out.mode {
        Mode::Quiet => {}
        Mode::Json => out.json(&json!({
            "outcome": "not-reproduced",
            "draft": true,
            "stage": failure.stage,
            "code": failure.code,
            "detail": detail,
        })),
        Mode::Human => {
            out.heading(TITLE);
            let mut rows = vec![Row::new(
                "replay",
                Tone::Negative,
                format!("not reproduced at {}, {}", failure.stage, failure.code),
            )];
            rows.extend(
                detail
                    .iter()
                    .map(|line| Row::new("differs", Tone::Negative, printable(line).into_owned())),
            );
            out.rows(&rows);
            out.line(NOTICE);
        }
    }
}

pub(crate) fn run_replay(command: &DerivationReplay, out: &mut Output) -> Exit {
    let loaded = registry(&command.trust, &Limits::DEFAULT)
        .and_then(|trust| Ok((package(&command.package)?, trust)));
    let (package, trust) = match loaded {
        Ok(loaded) => loaded,
        Err(message) => return failed(out, "INPUT", &message),
    };
    match replay(&package, &trust) {
        Ok(replayed) => {
            reproduced(out, &replayed);
            Exit::Complete
        }
        Err(failure) => {
            not_reproduced(out, &failure);
            Exit::Refused
        }
    }
}

pub(crate) fn run_inspect(command: &DerivationInspect, out: &mut Output) -> Exit {
    let package = match package(&command.package) {
        Ok(package) => package,
        Err(message) => return failed(out, "INPUT", &message),
    };
    let Some(presented) = member(&package, "presented") else {
        return failed(out, "INPUT", "the package presents no result");
    };
    let statements = member(&package, "statements")
        .and_then(Value::as_array)
        .map_or(0, <[Value]>::len);
    match out.mode {
        Mode::Quiet => {}
        Mode::Json => out.json(&json!({
            "outcome": "inspected",
            "draft": true,
            "checked": "nothing",
            "format": member(&package, "package").map(output_json),
            "profile": member(&package, "profile").map(output_json),
            "statements": statements,
            "presented": output_json(presented),
        })),
        Mode::Human => {
            out.heading(TITLE);
            let claims = |path: &[&str]| {
                path.iter()
                    .try_fold(presented, |value, name| member(value, name))
                    .and_then(Value::as_str)
                    .map_or_else(
                        || "not stated".to_owned(),
                        |text| printable(text).into_owned(),
                    )
            };
            out.rows(&[
                Row::new(
                    "checked",
                    Tone::Unknown,
                    "nothing: this is what the package claims",
                ),
                Row::new("statements", Tone::Plain, statements.to_string()),
                Row::new("contract", Tone::Plain, claims(&["core", "contract", "id"])),
                Row::new(
                    "decision",
                    Tone::Unknown,
                    claims(&["core", "result", "decision"]),
                ),
            ]);
            out.line("Replay it against your trust registry: verified derivation replay.");
        }
    }
    Exit::Complete
}

/// The core of a derived evaluation, wherever the file carries it.
fn core(value: &Value) -> Option<&Value> {
    member(member(value, "presented").unwrap_or(value), "core")
}

pub(crate) fn run_compare(command: &DerivationCompare, out: &mut Output) -> Exit {
    let loaded = package(&command.expected).and_then(|a| Ok((a, package(&command.actual)?)));
    let (expected, actual) = match loaded {
        Ok(loaded) => loaded,
        Err(message) => return failed(out, "INPUT", &message),
    };
    let (Some(Value::Object(expected)), Some(Value::Object(actual))) =
        (core(&expected), core(&actual))
    else {
        return failed(out, "NOT_COMPARABLE", "a file carries no core to compare");
    };
    // Only the cores are compared. Diagnostics are each implementation's own.
    let mut differing: Vec<&str> = expected
        .keys()
        .chain(actual.keys())
        .filter(|key| expected.get(key) != actual.get(key))
        .collect();
    differing.sort_unstable();
    differing.dedup();
    let equal = differing.is_empty();
    match out.mode {
        Mode::Quiet => {}
        Mode::Json => out.json(&json!({
            "outcome": if equal { "equal" } else { "different" },
            "draft": true,
            "differing": differing,
        })),
        Mode::Human => {
            out.heading(TITLE);
            let row = if equal {
                Row::new(
                    "cores",
                    Tone::Plain,
                    "equal. Nothing was checked: neither was replayed",
                )
            } else {
                Row::new(
                    "cores",
                    Tone::Negative,
                    format!("differ in {}", differing.join(", ")),
                )
            };
            out.rows(&[row]);
        }
    }
    if equal { Exit::Complete } else { Exit::Refused }
}
