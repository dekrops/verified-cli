// SPDX-License-Identifier: Apache-2.0

//! `verified history read`: what authorities say about the records of one
//! unit of work, read against the records given. Every rule is in
//! `verified_history`; this reads files, bounds them and prints.

use serde_json::json;
use verified_canonical::{Limits, Value};
use verified_history::{Carried, Offered, Reading, Standing, read};

use crate::cli::HistoryRead;
use crate::exit::Exit;
use crate::render::{Mode, Output, Row, Tone, printable};
use crate::verify::{failed, json_file, output_json, registry};

const TITLE: &str = "Work relation v1 (draft)";

/// The most relations, and the most records, one history may hold. The
/// reader compares each relation with each record, so the work grows with
/// their product; a history is one unit of work, not a ledger.
const MAX_ITEMS: usize = 1024;

fn list<'a>(history: &'a Value, name: &str) -> Result<&'a [Value], String> {
    let items = history
        .as_object()
        .filter(|o| o.has_exactly(&["records", "relations"]))
        .and_then(|o| o.get(name))
        .and_then(Value::as_array)
        .ok_or("a history is { \"relations\": [...], \"records\": [...] }")?;
    if items.len() > MAX_ITEMS {
        return Err(format!(
            "the history has {} {name}; at most {MAX_ITEMS} are read",
            items.len()
        ));
    }
    Ok(items)
}

fn relations(history: &Value) -> Result<Vec<Carried<'_>>, String> {
    let shape = "a relation is { \"statement\": {...}, \"body\": {...} }";
    list(history, "relations")?
        .iter()
        .map(|item| {
            let o = item
                .as_object()
                .filter(|o| o.has_exactly(&["body", "statement"]));
            let member = |name| o.and_then(|o| o.get(name));
            Some(Carried {
                statement: member("statement")?,
                body: member("body")?,
            })
        })
        .collect::<Option<_>>()
        .ok_or_else(|| shape.to_owned())
}

fn records(history: &Value) -> Result<Vec<Offered<'_>>, String> {
    let shape = "a record is { \"kind\": \"...\", \"text\": \"...\" }";
    list(history, "records")?
        .iter()
        .map(|item| {
            let o = item
                .as_object()
                .filter(|o| o.has_exactly(&["kind", "text"]));
            let member = |name| o.and_then(|o| o.get(name)).and_then(Value::as_str);
            Some(Offered {
                kind: member("kind")?,
                text: member("text")?,
            })
        })
        .collect::<Option<_>>()
        .ok_or_else(|| shape.to_owned())
}

/// What the run concludes. A reading has no single result; the exit code is
/// the least favourable thing found, and the output says each thing.
fn conclude(reading: &Reading) -> (Exit, &'static str) {
    let contradicted = reading
        .relations
        .iter()
        .any(|r| matches!(r.standing, Standing::Refused(_) | Standing::Contradicted(_)));
    let malformed = reading.records.contains(&Err("MALFORMED_RECORD"));
    let another_claim = reading.same_claims.iter().any(|s| s.result != "SAME_CLAIM");
    let broken = reading
        .streams
        .iter()
        .any(|s| !matches!(s.completeness, "UNINTERRUPTED" | "UNKNOWN"));
    if contradicted || malformed || another_claim || broken {
        return (Exit::Refused, "refused");
    }
    let stated = reading
        .relations
        .iter()
        .any(|r| matches!(r.standing, Standing::Stated(_)));
    let unknown = reading.records.iter().any(Result::is_err);
    if stated || unknown || reading.relations.is_empty() {
        return (Exit::Incomplete, "stated");
    }
    (Exit::Complete, "checked")
}

fn human(out: &mut Output, reading: &Reading) {
    out.heading(TITLE);
    let mut rows = Vec::new();
    if reading.relations.is_empty() {
        rows.push(Row::new(
            "relations",
            Tone::Unknown,
            "none: nobody says anything about these records",
        ));
    }
    for read in &reading.relations {
        let name = read.relation.unwrap_or("not read");
        let by = match (&read.source, &read.key_id) {
            (Some(source), Some(key)) => {
                format!(", said by {} (key {})", printable(source), printable(key))
            }
            _ => String::new(),
        };
        let (tone, text) = match &read.standing {
            Standing::Checked => (
                Tone::Established,
                format!("{name}: consistent with the records given{by}"),
            ),
            Standing::Stated(absent) => {
                let kinds: Vec<&str> = absent.iter().map(|r| r.kind.as_str()).collect();
                (
                    Tone::Unknown,
                    format!(
                        "{name}: stated, not checked; not given: {}{by}",
                        kinds.join(", ")
                    ),
                )
            }
            Standing::Contradicted(code) => (
                Tone::Negative,
                format!("{name}: a record given states otherwise, {code}{by}"),
            ),
            Standing::Refused(code) => (Tone::Negative, format!("{name}: refused, {code}{by}")),
        };
        rows.push(Row::new("relation", tone, text));
    }
    let held = reading.records.iter().filter(|r| r.is_ok()).count();
    rows.push(Row::new(
        "records",
        Tone::Plain,
        format!(
            "{held} of {} held; none was verified by this command",
            reading.records.len()
        ),
    ));
    for code in reading.records.iter().filter_map(|r| r.as_ref().err()) {
        let tone = if *code == "MALFORMED_RECORD" {
            Tone::Negative
        } else {
            Tone::Unknown
        };
        rows.push(Row::new("record", tone, format!("not held, {code}")));
    }
    for same in &reading.same_claims {
        let package = out.short(&same.package.to_hex());
        let (tone, text) = if same.result == "SAME_CLAIM" {
            (
                Tone::Established,
                format!("the registered claim is the claim of package {package}"),
            )
        } else {
            (
                Tone::Negative,
                format!(
                    "the registered claim is not the claim of package {package}, {}",
                    same.result
                ),
            )
        };
        rows.push(Row::new("claim", tone, text));
    }
    for stream in &reading.streams {
        let name = printable(&stream.stream);
        let (tone, text) = match (stream.completeness, stream.last) {
            ("UNINTERRUPTED", Some(last)) => (
                Tone::Established,
                format!(
                    "{name}: nothing missing from step 0 to step {last}; nothing is known after it"
                ),
            ),
            ("UNKNOWN", _) => (
                Tone::Unknown,
                format!("{name}: other statements of this stream may exist"),
            ),
            (code, _) => (Tone::Negative, format!("{name}: {code}")),
        };
        rows.push(Row::new("stream", tone, text));
    }
    out.rows(&rows);
    out.line("A relation shows that its authority said so, not that it is true.");
    out.line("Verify each record with its own command: verify, registration verify.");
}

pub(crate) fn run(command: &HistoryRead, out: &mut Output) -> Exit {
    let limits = Limits::DEFAULT;
    let loaded = registry(&command.trust, &limits)
        .and_then(|trust| Ok((json_file(&command.history, "history", &limits)?, trust)));
    let (history, trust) = match loaded {
        Ok(loaded) => loaded,
        Err(message) => return failed(out, "INPUT", &message),
    };
    let parts = relations(&history).and_then(|relations| Ok((relations, records(&history)?)));
    let (relations, records) = match parts {
        Ok(parts) => parts,
        Err(message) => {
            let message = format!("history {}: {message}", command.history.display());
            return failed(out, "INPUT", &message);
        }
    };

    let reading = read(&relations, &records, &trust);
    let (exit, outcome) = conclude(&reading);
    match out.mode {
        Mode::Quiet => {}
        Mode::Json => out.json(&json!({
            "outcome": outcome,
            "recordsVerified": false,
            "reading": output_json(&reading.to_value()),
        })),
        Mode::Human => human(out, &reading),
    }
    exit
}
