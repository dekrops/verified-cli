// SPDX-License-Identifier: Apache-2.0

//! `verified trust`: writing and checking the registry `--trust` reads.
//!
//! The registry's rules are `verified_protocol::TrustRegistry`'s and
//! `verified_verifier::Trust`'s. Every registry written here is read back
//! with them before it replaces the file, so this module can only write a
//! registry `verify` accepts.

use std::io::Write as _;
use std::path::Path;

use serde_json::{Value as Json, json};
use verified_canonical::{Limits, parse};
use verified_protocol::{Instant, TrustedKey};
use verified_verifier::Trust;

use crate::cli::{TrustAdd, TrustInit, TrustRevoke, TrustShow};
use crate::exit::Exit;
use crate::input::{self, InputError};
use crate::render::{Mode, Output, Row, Tone};
use crate::verify::{failed, output_json};

const TITLE: &str = "Trust registry";

/// The source a key lists to sign decisions as an issuer.
const DECISION_SOURCE: &str = "wvp-decision";

/// Reads a registry file as `verify` would.
fn read(path: &Path) -> Result<(Json, Trust), String> {
    let name = path.display();
    let bytes = match input::read(path, Limits::DEFAULT.max_bytes) {
        Ok(bytes) => bytes,
        Err(InputError::Io(error)) => return Err(format!("{error:#}")),
        Err(InputError::TooLarge(limit)) => return Err(format!("{name}: {limit}")),
    };
    let value = parse(&bytes, &Limits::DEFAULT).map_err(|error| format!("{name}: {error}"))?;
    let trust = Trust::from_value(&value).map_err(|error| format!("{name}: {error}"))?;
    Ok((output_json(&value), trust))
}

/// The registry's text, after checking it as `verify` would.
fn checked(registry: &Json) -> Result<(String, Trust), String> {
    let text = serde_json::to_string_pretty(registry).map_err(|error| error.to_string())? + "\n";
    let value = parse(text.as_bytes(), &Limits::DEFAULT).map_err(|error| error.to_string())?;
    let trust = Trust::from_value(&value).map_err(|error| error.to_string())?;
    Ok((text, trust))
}

/// Checks `registry` as `verify` would and replaces the file at `path` with
/// it, whole or not at all, keeping the file's permissions.
fn write(path: &Path, registry: &Json) -> Result<Trust, String> {
    let (text, trust) = checked(registry)?;
    let file_name = path.file_name().map_or_else(
        || "registry".to_owned(),
        |name| name.to_string_lossy().into_owned(),
    );
    let temporary = path.with_file_name(format!(".{file_name}.tmp-{}", std::process::id()));
    // Only a file this run created is ever removed.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    let written = (|| {
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        if let Ok(metadata) = std::fs::metadata(path) {
            std::fs::set_permissions(&temporary, metadata.permissions())?;
        }
        std::fs::rename(&temporary, path)
    })();
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temporary);
        return Err(format!("cannot write {}: {error}", path.display()));
    }
    Ok(trust)
}

/// The text of an instant, if it is one in the protocol's spelling.
fn instant(text: &str, what: &str) -> Result<String, String> {
    Instant::parse(text)
        .map(|_| text.to_owned())
        .ok_or_else(|| format!("{what} {text:?} is not an instant such as 2026-01-01T00:00:00Z"))
}

/// The times of a key, as its record spells them. `Instant` keeps no
/// spelling, and the registry's is the one a person recognizes.
struct Times {
    valid_from: String,
    valid_until: Option<String>,
    revoked_at: Option<String>,
}

fn times(registry: &Json, key_id: &str) -> Times {
    let record = registry
        .get("keys")
        .and_then(Json::as_array)
        .and_then(|keys| {
            keys.iter()
                .find(|k| k.get("keyId").and_then(Json::as_str) == Some(key_id))
        });
    let at = |member: &str| {
        record
            .and_then(|r| r.get(member))
            .and_then(|m| m.get("value"))
            .and_then(Json::as_str)
            .map(str::to_owned)
    };
    Times {
        valid_from: at("validFrom").unwrap_or_default(),
        valid_until: at("validUntil"),
        revoked_at: at("revokedAt"),
    }
}

/// The base64 of a PEM public key file.
fn pem_public_key(path: &Path) -> Result<String, String> {
    let name = path.display();
    let bytes = match input::read(path, 64 * 1024) {
        Ok(bytes) => bytes,
        Err(InputError::Io(error)) => return Err(format!("{error:#}")),
        Err(InputError::TooLarge(limit)) => return Err(format!("{name}: {limit}")),
    };
    let text = String::from_utf8_lossy(&bytes);
    // Never echo the file: a private key given by mistake must not be
    // printed.
    if text.contains("PRIVATE KEY-----") {
        return Err(format!(
            "{name} holds a private key; give the public key (openssl pkey -pubout)"
        ));
    }
    let body = text
        .split_once("-----BEGIN PUBLIC KEY-----")
        .and_then(|(_, rest)| rest.split_once("-----END PUBLIC KEY-----"))
        .map(|(body, _)| body.split_whitespace().collect::<String>())
        .filter(|body| !body.is_empty());
    body.ok_or_else(|| format!("{name} is not a PEM public key (-----BEGIN PUBLIC KEY-----)"))
}

fn wrapped(text: &str) -> Json {
    json!({ "value": text })
}

fn keys(registry: &mut Json) -> &mut Vec<Json> {
    // `read` checked the shape: an object whose `keys` is a list.
    match registry.get_mut("keys") {
        Some(Json::Array(keys)) => keys,
        _ => unreachable!("a registry that was read is {{ keys: [ … ] }}"),
    }
}

pub(crate) fn init(command: &TrustInit, out: &mut Output) -> Exit {
    let path = &command.registry;
    // Created exclusively: a file that exists, or appears meanwhile, is
    // never overwritten.
    let created = checked(&json!({ "keys": [] })).and_then(|(text, _)| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::AlreadyExists => {
                    format!("{} exists; nothing was changed", path.display())
                }
                _ => format!("cannot create {}: {error}", path.display()),
            })?;
        file.write_all(text.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("cannot write {}: {error}", path.display()))
    });
    if let Err(message) = created {
        return failed(out, "TRUST_REGISTRY", &message);
    }
    match out.mode {
        Mode::Quiet => {}
        Mode::Json => out.json(&json!({ "outcome": "created", "registry": path, "keys": 0 })),
        Mode::Human => {
            out.line(&format!(
                "Created an empty trust registry in {}.",
                path.display()
            ));
            out.line("It trusts no key: add the keys you accept with `verified trust add`.");
        }
    }
    Exit::Complete
}

pub(crate) fn add(command: &TrustAdd, out: &mut Output) -> Exit {
    match added(command) {
        Ok((key, times)) => {
            match out.mode {
                Mode::Quiet => {}
                Mode::Json => out.json(&json!({
                    "outcome": "added",
                    "registry": command.registry,
                    "key": key_json(&key, &times),
                })),
                Mode::Human => {
                    out.line(&format!(
                        "Added {} to {}.",
                        key.key_id,
                        command.registry.display()
                    ));
                    out.rows(&key_rows(&key, &times));
                }
            }
            Exit::Complete
        }
        Err(message) => failed(out, "TRUST_REGISTRY", &message),
    }
}

fn added(command: &TrustAdd) -> Result<(TrustedKey, Times), String> {
    let (mut registry, _) = read(&command.registry)?;
    let public_key = match (&command.public_key_file, &command.public_key) {
        (Some(path), _) => pem_public_key(path)?,
        (None, Some(key)) => key.clone(),
        (None, None) => return Err("give --public-key-file or --public-key".to_owned()),
    };
    let valid_until = command
        .valid_until
        .as_deref()
        .map(|t| instant(t, "--valid-until"))
        .transpose()?;
    keys(&mut registry).push(json!({
        "algorithm": "Ed25519",
        "issuer": wrapped(&command.issuer),
        "keyId": command.key_id,
        "publicKey": public_key,
        "revokedAt": null,
        "sources": command.sources,
        "tenant": wrapped(&command.tenant),
        "validFrom": wrapped(&instant(&command.valid_from, "--valid-from")?),
        "validUntil": valid_until.as_deref().map(wrapped),
    }));
    let trust = write(&command.registry, &registry)?;
    let key = trust
        .registry()
        .find(&command.key_id)
        .cloned()
        .ok_or_else(|| "the key was written but cannot be read back".to_owned())?;
    Ok((key, times(&registry, &command.key_id)))
}

pub(crate) fn revoke(command: &TrustRevoke, out: &mut Output) -> Exit {
    match revoked(command) {
        Ok((key, times)) => {
            match out.mode {
                Mode::Quiet => {}
                Mode::Json => out.json(&json!({
                    "outcome": "revoked",
                    "registry": command.registry,
                    "key": key_json(&key, &times),
                })),
                Mode::Human => {
                    out.line(&format!(
                        "Revoked {} in {}.",
                        key.key_id,
                        command.registry.display()
                    ));
                    out.rows(&key_rows(&key, &times));
                    out.line("");
                    out.line(
                        "Statements it signed before then still verify. A statement's time is \
                         chosen by its signer, so a holder of the key can backdate one.",
                    );
                }
            }
            Exit::Complete
        }
        Err(message) => failed(out, "TRUST_REGISTRY", &message),
    }
}

fn revoked(command: &TrustRevoke) -> Result<(TrustedKey, Times), String> {
    let (mut registry, trust) = read(&command.registry)?;
    let at = instant(&command.at, "--at")?;
    let Some(existing) = trust.registry().find(&command.key_id) else {
        return Err(format!(
            "{} has no key {:?}",
            command.registry.display(),
            command.key_id
        ));
    };
    if existing.revoked_at.is_some() {
        let when = times(&registry, &command.key_id)
            .revoked_at
            .unwrap_or_default();
        return Err(format!(
            "{:?} was already revoked at {when}; nothing was changed",
            command.key_id
        ));
    }
    for key in keys(&mut registry).iter_mut() {
        if key.get("keyId").and_then(Json::as_str) == Some(command.key_id.as_str()) {
            key["revokedAt"] = wrapped(&at);
        }
    }
    let trust = write(&command.registry, &registry)?;
    let key = trust
        .registry()
        .find(&command.key_id)
        .cloned()
        .ok_or_else(|| "the key was written but cannot be read back".to_owned())?;
    Ok((key, times(&registry, &command.key_id)))
}

pub(crate) fn show(command: &TrustShow, out: &mut Output) -> Exit {
    let (registry, trust) = match read(&command.registry) {
        Ok(read) => read,
        Err(message) => {
            match out.mode {
                Mode::Quiet => {}
                Mode::Json => out.json(&json!({ "outcome": "unusable", "problem": message })),
                Mode::Human => {
                    out.heading(TITLE);
                    out.rows(&[
                        Row::new("unusable", Tone::Negative, "verify would not run with it"),
                        Row::new("", Tone::Plain, &message),
                    ]);
                }
            }
            return Exit::Refused;
        }
    };
    let keys = trust.registry().keys();
    match out.mode {
        Mode::Quiet => {}
        Mode::Json => out.json(&json!({
            "outcome": "usable",
            "registry": command.registry,
            "keys": keys
                .iter()
                .map(|key| key_json(key, &times(&registry, &key.key_id)))
                .collect::<Vec<_>>(),
        })),
        Mode::Human => {
            out.heading(&format!("{TITLE} {}", command.registry.display()));
            out.rows(&[Row::new(
                "usable",
                Tone::Established,
                format!(
                    "by verify: {} key(s), each well formed and decoding to an Ed25519 key",
                    keys.len()
                ),
            )]);
            for key in keys {
                out.line("");
                out.rows(&key_rows(key, &times(&registry, &key.key_id)));
            }
            if keys.is_empty() {
                out.line("");
                out.line("It trusts no key: every signature would be refused.");
            }
        }
    }
    Exit::Complete
}

fn key_json(key: &TrustedKey, times: &Times) -> Json {
    json!({
        "keyId": key.key_id,
        "issuer": key.issuer,
        "tenant": key.tenant,
        "sources": key.sources,
        "maySignDecisions": key.speaks_for(DECISION_SOURCE),
        "validFrom": times.valid_from,
        "validUntil": times.valid_until,
        "revokedAt": times.revoked_at,
    })
}

fn key_rows(key: &TrustedKey, times: &Times) -> Vec<Row> {
    let mut speaks = key.sources.join(", ");
    if key.speaks_for(DECISION_SOURCE) {
        speaks.push_str(" (may sign decisions as an issuer)");
    }
    let valid = match &times.valid_until {
        Some(until) => format!("from {} until {until}", times.valid_from),
        None => format!("from {}, no end", times.valid_from),
    };
    let revoked = match &times.revoked_at {
        Some(at) => Row::new("revoked", Tone::Negative, format!("at {at}")),
        None => Row::new("revoked", Tone::Plain, "no"),
    };
    vec![
        Row::new("key", Tone::Plain, &key.key_id),
        Row::new("issuer", Tone::Plain, &key.issuer),
        Row::new("tenant", Tone::Plain, &key.tenant),
        Row::new("speaks for", Tone::Plain, speaks),
        Row::new("valid", Tone::Plain, valid),
        revoked,
    ]
}
