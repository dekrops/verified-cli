// SPDX-License-Identifier: Apache-2.0

//! A registry's log: checking a run of its entries, and an entry someone
//! holds against that run.
//!
//! A registry publishes its log as signed entries: receipts, closures and
//! dispute records. A relying party can check a run of them without
//! trusting the registry, and without the claims.
//!
//! # What a verified segment establishes
//!
//! Its entries are consecutive entries of one registry's log, in order,
//! with nothing inserted, removed or altered between the first and the
//! last. Nothing is established about entries after the last: a registry
//! can always withhold the end of its log.
//!
//! # What a held entry adds
//!
//! A registry can remove an entry, renumber the rest and present a log that
//! verifies on its own. Whoever holds a signed entry from before the change
//! can show it: the log has another entry at that position, and the
//! registry signed both ([`Inclusion::Equivocation`]).
//!
//! Whether the registry applied its own rules (one open claim per unit, the
//! agreement's limit) is not checked here. That needs the log from its
//! start, with the agreements and claims: [`super::audit`].

use std::collections::{BTreeMap, BTreeSet};

use verified_canonical::{Sha256Digest, Value};
use verified_protocol::registration::{
    EntryKind, LogEntry, REGISTRATION_PROTOCOL, RegistrationCode as Code,
};

use super::{
    Checked, RegistrationRefusal, RegistrationTrust, Signing, canonical, is_hex_digest, refuse,
    signed,
};

/// A verified run of consecutive entries of one registry's log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    /// The registry whose log it is.
    pub registry: String,
    /// The position of the first entry of the run.
    pub first: i64,
    /// The position of the last.
    pub last: i64,
    /// The digest of the last entry, which the next entry of the log names.
    pub head: Sha256Digest,
}

/// How an entry someone holds relates to a verified segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inclusion {
    /// The entry at its position is this entry.
    Included,
    /// The segment does not reach its position.
    NotCovered,
    /// The segment has another entry at its position. The registry signed
    /// both: together they show that it rewrote its log.
    Equivocation {
        /// The digest of the entry held.
        held: Sha256Digest,
        /// The digest of the entry the segment has there.
        logged: Sha256Digest,
    },
}

/// What [`check_log`] found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogCheck {
    /// The verified segment.
    pub segment: Segment,
    /// How the held entry relates to it, if one was given.
    pub inclusion: Option<Inclusion>,
}

/// One entry on its own: structure, protocol, commitments, position, and
/// the signature of a key of the registry it names.
fn entry<'a>(value: &'a Value, trust: &RegistrationTrust, what: &str) -> Checked<LogEntry<'a>> {
    let fail = |code, problem: &str| refuse(code, format!("{what}: {problem}"));
    let entry =
        LogEntry::from_value(value).or_else(|shape| fail(Code::Malformed, &shape.to_string()))?;
    if entry.protocol != REGISTRATION_PROTOCOL {
        return fail(Code::UnsupportedProtocol, "is not of claim registration v1");
    }
    if !entry
        .commitments()
        .all(|d| d.algorithm == Sha256Digest::ALGORITHM && is_hex_digest(d))
    {
        return fail(
            Code::MalformedCommitment,
            "states a commitment that is not a SHA-256 digest",
        );
    }
    if entry.sequence < 0 || entry.previous.is_none() != (entry.sequence == 0) {
        return fail(
            Code::ChainInvalid,
            "only entry 0 of a log has no predecessor",
        );
    }
    let signing = Signing {
        signature: entry.signature,
        domain: entry.domain(),
        object: entry.entry,
        what,
    };
    signed(
        &trust.registries,
        entry.registry,
        Code::RegistryMismatch,
        entry.at.at,
        &signing,
    )?;
    Ok(entry)
}

/// Steps 3 to 9, on entries that each verified on their own.
fn segment(entries: &[LogEntry<'_>], anchor: Option<&LogEntry<'_>>) -> Checked<Segment> {
    let first = &entries[0];
    let all = || anchor.into_iter().chain(entries);

    if all().any(|e| e.registry != first.registry) {
        return refuse(
            Code::MixedRegistries,
            "the entries, or the anchor, are not all from one registry",
        );
    }
    let digests: Vec<Sha256Digest> = entries.iter().map(|e| e.entry.digest()).collect();
    // Linear in the number of entries: a log is untrusted input.
    let mut at_position = BTreeMap::new();
    let forked = entries
        .iter()
        .zip(&digests)
        .any(|(e, digest)| *at_position.entry(e.sequence).or_insert(digest) != digest);
    if forked {
        return refuse(
            Code::Equivocation,
            "two different entries are at one position",
        );
    }
    if !entries.windows(2).all(|w| w[0].sequence < w[1].sequence) {
        return refuse(
            Code::Reordered,
            "the entries are not in ascending order of position",
        );
    }
    if anchor.is_none() && first.sequence != 0 {
        return refuse(
            Code::GenesisInvalid,
            "without an anchor, a segment starts at position 0",
        );
    }

    // Each entry follows a predecessor: the anchor, then the entry before.
    let anchor_digest = anchor.map(|a| a.entry.digest());
    let before = |i: usize| match i {
        0 => anchor.zip(anchor_digest.as_ref()),
        _ => Some((&entries[i - 1], &digests[i - 1])),
    };
    for (i, entry) in entries.iter().enumerate() {
        let Some((predecessor, digest)) = before(i) else {
            continue;
        };
        if predecessor.sequence + 1 != entry.sequence {
            return refuse(
                Code::Gap,
                format!(
                    "entry {} does not follow entry {}",
                    entry.sequence, predecessor.sequence
                ),
            );
        }
        if !entry.previous.is_some_and(|p| p.states(digest)) {
            return refuse(
                Code::PreviousMismatch,
                format!("entry {} does not name the entry before it", entry.sequence),
            );
        }
    }
    for (i, entry) in entries.iter().enumerate() {
        if before(i).is_some_and(|(predecessor, _)| entry.at.at < predecessor.at.at) {
            return refuse(
                Code::TimeReversed,
                format!(
                    "entry {} is earlier than the entry before it",
                    entry.sequence
                ),
            );
        }
    }

    // A claim is registered once. Closures and dispute records name the
    // claim again and are not counted.
    let mut registered = BTreeSet::new();
    let twice = all()
        .filter(|e| matches!(e.kind, EntryKind::Receipt { .. }))
        .any(|e| !registered.insert(e.claim.hex));
    if twice {
        return refuse(
            Code::DuplicateClaim,
            "a claim is registered at two positions",
        );
    }

    let last = entries.len() - 1;
    Ok(Segment {
        registry: first.registry.to_owned(),
        first: first.sequence,
        last: entries[last].sequence,
        head: digests[last],
    })
}

/// Verifies a run of a registry's log from the text of its entries, in the
/// order received, and optionally checks an entry someone holds against it.
///
/// `anchor` is an entry the caller verified before, which the run continues;
/// without one the run must start at the log's first entry. It is the
/// caller's own, like the keys: never take it from whoever supplies the
/// entries.
///
/// # Errors
///
/// The first of the protocol's checks that fails: for the entries and the
/// anchor, then for the segment, then for the held entry.
pub fn check_log(
    entries: &[&[u8]],
    anchor: Option<&[u8]>,
    held: Option<&[u8]>,
    trust: &RegistrationTrust,
) -> Result<LogCheck, RegistrationRefusal> {
    if entries.is_empty() {
        return refuse(Code::Malformed, "a segment has at least one entry");
    }
    // An entry's text and its other checks are one step, so the first entry
    // that fails either is the one reported. The text is read first only so
    // that the entries can borrow from the parsed values.
    let what = |i: usize| format!("entry {i} of the segment");
    let values: Vec<Checked<Value>> = entries
        .iter()
        .enumerate()
        .map(|(i, text)| canonical(text, &what(i)))
        .collect();
    let mut read = Vec::with_capacity(entries.len());
    for (i, value) in values.iter().enumerate() {
        match value {
            Ok(value) => read.push(entry(value, trust, &what(i))?),
            Err(refusal) => return Err(refusal.clone()),
        }
    }
    let anchor_value = anchor
        .map(|text| canonical(text, "the anchor"))
        .transpose()?;
    let anchor = anchor_value
        .as_ref()
        .map(|value| entry(value, trust, "the anchor"))
        .transpose()?;

    let segment = segment(&read, anchor.as_ref())?;

    let held_value = held
        .map(|text| canonical(text, "the held entry"))
        .transpose()?;
    let inclusion = held_value
        .as_ref()
        .map(|value| {
            let held = entry(value, trust, "the held entry")?;
            if held.registry != segment.registry {
                return refuse(
                    Code::RegistryMismatch,
                    "the held entry is from another registry than the segment",
                );
            }
            let digest = held.entry.digest();
            let logged = anchor
                .iter()
                .chain(&read)
                .find(|e| e.sequence == held.sequence)
                .map(|e| e.entry.digest());
            Ok(match logged {
                None => Inclusion::NotCovered,
                Some(logged) if logged == digest => Inclusion::Included,
                Some(logged) => Inclusion::Equivocation {
                    held: digest,
                    logged,
                },
            })
        })
        .transpose()?;
    Ok(LogCheck { segment, inclusion })
}
