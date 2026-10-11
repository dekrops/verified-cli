// SPDX-License-Identifier: Apache-2.0

//! What presented statements show about their streams, from chain positions
//! only: never from the order received or from asserted times.

use std::collections::BTreeMap;

use verified_canonical::Sha256Digest;
use verified_protocol::WireDigest;
use verified_verifier::evidence::Authenticated;

/// What the presented statements of one stream show.
///
/// `UNINTERRUPTED` says that position 0 and every position up to `last` was
/// presented. It says nothing about what follows: a stream cut short is
/// indistinguishable from one that stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamRead {
    /// The stream's tenant.
    pub tenant: String,
    /// The stream's issuer (a UUID).
    pub issuer: String,
    /// The stream's name.
    pub stream: String,
    /// `UNINTERRUPTED`, `UNKNOWN`, or the chain code the stream fails with.
    pub completeness: &'static str,
    /// The last position presented, when the stream is uninterrupted.
    pub last: Option<i64>,
}

struct Step<'a> {
    digest: Sha256Digest,
    previous: Option<WireDigest<'a>>,
}

fn completeness(steps: &BTreeMap<i64, Vec<Step<'_>>>) -> (&'static str, Option<i64>) {
    if steps.values().any(|at| at.len() > 1) {
        return ("CHAIN_EQUIVOCATION", None);
    }
    let ordered: Vec<(i64, &Step<'_>)> = steps
        .iter()
        .filter_map(|(sequence, at)| Some((*sequence, at.first()?)))
        .collect();
    let Some((first, genesis)) = ordered.first() else {
        return ("UNKNOWN", None);
    };
    if *first == 0 && genesis.previous.is_some() {
        return ("CHAIN_GENESIS_INVALID", None);
    }
    let consecutive = |pair: &&[(i64, &Step<'_>)]| pair[0].0.checked_add(1) == Some(pair[1].0);
    let named = ordered.windows(2).filter(consecutive).all(|pair| {
        pair[1]
            .1
            .previous
            .is_some_and(|previous| previous.states(&pair[0].1.digest))
    });
    if !named {
        return ("CHAIN_PREVIOUS_MISMATCH", None);
    }
    let whole = *first == 0 && ordered.windows(2).all(|pair| consecutive(&pair));
    match ordered.last() {
        Some((last, _)) if whole => ("UNINTERRUPTED", Some(*last)),
        _ => ("UNKNOWN", None),
    }
}

/// Every stream the verified statements belong to, ordered by tenant, then
/// issuer, then name. A statement without a chain position belongs to none,
/// and one presented more than once counts once.
pub(crate) fn read(authentic: &[Authenticated<'_>]) -> Vec<StreamRead> {
    let mut streams: BTreeMap<(&str, &str, &str), BTreeMap<i64, Vec<Step<'_>>>> = BTreeMap::new();
    for statement in authentic.iter().map(Authenticated::statement) {
        let Some(link) = statement.chain else {
            continue;
        };
        let digest = statement.statement.digest();
        let at = streams
            .entry((statement.tenant, statement.issuer, link.stream))
            .or_default()
            .entry(link.sequence)
            .or_default();
        if !at.iter().any(|step| step.digest == digest) {
            at.push(Step {
                digest,
                previous: link.previous,
            });
        }
    }
    streams
        .into_iter()
        .map(|((tenant, issuer, stream), steps)| {
            let (completeness, last) = completeness(&steps);
            StreamRead {
                tenant: tenant.to_owned(),
                issuer: issuer.to_owned(),
                stream: stream.to_owned(),
                completeness,
                last,
            }
        })
        .collect()
}
