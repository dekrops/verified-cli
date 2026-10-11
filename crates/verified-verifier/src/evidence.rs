// SPDX-License-Identifier: Apache-2.0

//! Evidence statements on their own, outside a package: authenticating one,
//! verifying that a list of them is a run of an issuer's stream, and
//! admitting them as the evidence of a claim.
//!
//! These are the rules of Evidence Statement v1 (a **draft**). Inside a
//! package, [`crate::verify`] applies authentication and admission itself;
//! it does not verify chains.
//!
//! Each step takes what the step before it produced: only an
//! [`Authenticated`] statement can be chained or admitted, and the only way
//! to obtain one is [`authenticate`].

use std::fmt;

use verified_canonical::{Sha256Digest, Value};
use verified_protocol::{ChainLink, Evidence, RefusalCode, SignedStatement};

use crate::container::Refusal;
use crate::json::{digest, object, text, wrapped};
use crate::statement;
use crate::trust::Trust;

/// The code of a refused statement, chain or admission. Stable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EvidenceCode {
    /// Not a signed statement of the protocol's structure.
    Malformed,
    /// A statement or admission check that packages share, under the code
    /// a package would be refused with.
    Shared(RefusalCode),
    /// No statements, or a statement without a chain link.
    ChainMissing,
    /// Statements of more than one tenant, issuer or stream, or an anchor
    /// of another.
    ChainMixedStreams,
    /// Two different statements with the same sequence number.
    ChainEquivocation,
    /// Statements not in ascending order of sequence number.
    ChainReordered,
    /// Without an anchor, a first statement that is not a stream's first
    /// step.
    ChainGenesisInvalid,
    /// A sequence number that is not the one after its predecessor's.
    ChainGap,
    /// A statement that does not name its predecessor's digest.
    ChainPreviousMismatch,
}

impl EvidenceCode {
    /// The protocol's spelling of the code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "MALFORMED",
            Self::Shared(code) => code.as_str(),
            Self::ChainMissing => "CHAIN_MISSING",
            Self::ChainMixedStreams => "CHAIN_MIXED_STREAMS",
            Self::ChainEquivocation => "CHAIN_EQUIVOCATION",
            Self::ChainReordered => "CHAIN_REORDERED",
            Self::ChainGenesisInvalid => "CHAIN_GENESIS_INVALID",
            Self::ChainGap => "CHAIN_GAP",
            Self::ChainPreviousMismatch => "CHAIN_PREVIOUS_MISMATCH",
        }
    }
}

impl fmt::Display for EvidenceCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a statement, a chain or an admission was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {detail}")]
pub struct EvidenceRefusal {
    /// The protocol's code for the failed check. Stable.
    pub code: EvidenceCode,
    /// A description for people. Not stable; do not match on it.
    pub detail: String,
}

impl From<Refusal> for EvidenceRefusal {
    fn from(refusal: Refusal) -> Self {
        Self {
            code: EvidenceCode::Shared(refusal.code),
            detail: refusal.detail,
        }
    }
}

fn refuse<T>(code: EvidenceCode, detail: impl Into<String>) -> Result<T, EvidenceRefusal> {
    Err(EvidenceRefusal {
        code,
        detail: detail.into(),
    })
}

/// A statement whose signature verified under a key the relying party's
/// registry trusts for the statement's tenant, issuer and source.
///
/// It establishes who made the statement and that it was not altered. It
/// does not establish that the statement is true, and its asserted time is
/// not authenticated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Authenticated<'a>(SignedStatement<'a>);

impl<'a> Authenticated<'a> {
    /// The statement.
    #[must_use]
    pub const fn statement(&self) -> &SignedStatement<'a> {
        &self.0
    }
}

/// Reads a signed statement and applies the protocol's ten checks, in order,
/// under the relying party's registry.
///
/// # Errors
///
/// The first check that fails: `MALFORMED` for a value that is not a signed
/// statement, otherwise the statement's code.
pub fn authenticate<'a>(
    signed: &'a Value,
    trust: &Trust,
) -> Result<Authenticated<'a>, EvidenceRefusal> {
    let read = SignedStatement::from_value(signed)
        .or_else(|shape| refuse(EvidenceCode::Malformed, shape.to_string()))?;
    statement::authenticate(&read, trust)?;
    Ok(Authenticated(read))
}

/// A step of a stream that the relying party has verified before and now
/// continues from. It is configuration, like the registry: never take one
/// from the party whose statements are being checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchor {
    /// The stream's tenant.
    pub tenant: String,
    /// The stream's issuer.
    pub issuer: String,
    /// The stream's name.
    pub stream: String,
    /// The step's sequence number.
    pub sequence: i64,
    /// The step's statement digest.
    pub digest: Sha256Digest,
}

/// Why a value is not an anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "an anchor is exactly {{ tenant: {{ value }}, issuer: {{ value }}, stream, sequence, digest: {{ algorithm: \"sha-256\", hex }} }}, with a sequence number of at least 0"
)]
pub struct MalformedAnchor;

impl Anchor {
    /// Reads an anchor in the form the protocol's corpus writes it, and
    /// [`Anchor::to_value`] produces: `{ tenant: { value }, issuer:
    /// { value }, stream, sequence, digest: { algorithm, hex } }`. Any
    /// missing, extra or mistyped member is refused.
    ///
    /// An anchor is the relying party's own record. Reading one checks its
    /// form only; it authenticates nothing.
    pub fn from_value(anchor: &Value) -> Result<Self, MalformedAnchor> {
        let object = anchor
            .as_object()
            .filter(|o| o.has_exactly(&["digest", "issuer", "sequence", "stream", "tenant"]))
            .ok_or(MalformedAnchor)?;
        let wrapped = |name| {
            let wrapper = object.get(name)?.as_object()?;
            wrapper
                .has_exactly(&["value"])
                .then(|| wrapper.get("value")?.as_str())
                .flatten()
        };
        let digest = object
            .get("digest")
            .and_then(Value::as_object)
            .filter(|d| d.has_exactly(&["algorithm", "hex"]))
            .filter(|d| d.get("algorithm").and_then(Value::as_str) == Some(Sha256Digest::ALGORITHM))
            .and_then(|d| d.get("hex")?.as_str()?.parse().ok())
            .ok_or(MalformedAnchor)?;
        let sequence = object
            .get("sequence")
            .and_then(Value::as_integer)
            .and_then(verified_canonical::Integer::to_i64)
            .filter(|sequence| *sequence >= 0)
            .ok_or(MalformedAnchor)?;
        Ok(Self {
            tenant: wrapped("tenant").ok_or(MalformedAnchor)?.to_owned(),
            issuer: wrapped("issuer").ok_or(MalformedAnchor)?.to_owned(),
            stream: object
                .get("stream")
                .and_then(Value::as_str)
                .ok_or(MalformedAnchor)?
                .to_owned(),
            sequence,
            digest,
        })
    }

    /// The anchor in the form [`Anchor::from_value`] reads: what to keep to
    /// continue a stream from this step.
    #[must_use]
    pub fn to_value(&self) -> Value {
        object([
            ("digest", digest(&self.digest)),
            ("issuer", wrapped(&self.issuer)),
            ("sequence", Value::Integer(self.sequence.into())),
            ("stream", text(&self.stream)),
            ("tenant", wrapped(&self.tenant)),
        ])
    }
}

/// A verified run of consecutive steps of one stream.
///
/// Nothing was inserted, removed or altered between the first step and the
/// last. Nothing is established about steps after the last: an issuer, or
/// whoever passes the statements on, can always leave off the end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    /// Whether the run starts at the stream's first step, not at an anchor.
    pub from_genesis: bool,
    /// The sequence number of the first statement of the run.
    pub first: i64,
    /// The last step of the run. It is the anchor to continue from.
    pub head: Anchor,
}

/// Verifies that `statements`, in the order received, are consecutive steps
/// of one issuer's stream: from the stream's first step, or from the step
/// after `anchor`.
///
/// # Errors
///
/// The first chain check that fails.
pub fn verify_chain(
    statements: &[Authenticated<'_>],
    anchor: Option<&Anchor>,
) -> Result<Segment, EvidenceRefusal> {
    let links: Option<Vec<(&SignedStatement<'_>, ChainLink<'_>)>> = statements
        .iter()
        .map(|a| a.0.chain.map(|link| (&a.0, link)))
        .collect();
    let Some(links) = links.filter(|links| !links.is_empty()) else {
        return refuse(
            EvidenceCode::ChainMissing,
            "there is no statement, or one has no chain link",
        );
    };
    let (first, first_link) = links[0];
    let stream = (first.tenant, first.issuer, first_link.stream);

    let same_stream = links
        .iter()
        .all(|(s, link)| (s.tenant, s.issuer, link.stream) == stream)
        && anchor
            .is_none_or(|a| (a.tenant.as_str(), a.issuer.as_str(), a.stream.as_str()) == stream);
    if !same_stream {
        return refuse(
            EvidenceCode::ChainMixedStreams,
            "the statements, or the anchor, are not all of one tenant, issuer and stream",
        );
    }

    let digests: Vec<Sha256Digest> = links.iter().map(|(s, _)| s.digest()).collect();
    let forked = links.iter().enumerate().any(|(i, (_, link))| {
        links[..i]
            .iter()
            .zip(&digests)
            .any(|((_, earlier), digest)| {
                earlier.sequence == link.sequence && *digest != digests[i]
            })
    });
    if forked {
        return refuse(
            EvidenceCode::ChainEquivocation,
            "two different statements carry the same sequence number",
        );
    }
    if !links.windows(2).all(|w| w[0].1.sequence < w[1].1.sequence) {
        return refuse(
            EvidenceCode::ChainReordered,
            "the statements are not in ascending order of sequence number",
        );
    }

    // Each step follows a predecessor: the anchor, then the step before it.
    let follows = |link: &ChainLink<'_>, sequence: i64, digest: &Sha256Digest| {
        if sequence.checked_add(1) != Some(link.sequence) {
            refuse(
                EvidenceCode::ChainGap,
                format!("step {} does not follow step {sequence}", link.sequence),
            )
        } else if link.previous.is_some_and(|p| p.hex == digest.to_hex()) {
            Ok(())
        } else {
            refuse(
                EvidenceCode::ChainPreviousMismatch,
                format!(
                    "step {} does not name the digest of step {sequence}",
                    link.sequence
                ),
            )
        }
    };
    match anchor {
        Some(anchor) => follows(&first_link, anchor.sequence, &anchor.digest)?,
        None if first_link.sequence == 0 && first_link.previous.is_none() => {}
        None => {
            return refuse(
                EvidenceCode::ChainGenesisInvalid,
                "without an anchor, the first statement must be step 0 and name no predecessor",
            );
        }
    }
    for (i, (_, link)) in links.iter().enumerate().skip(1) {
        follows(link, links[i - 1].1.sequence, &digests[i - 1])?;
    }

    let last = links.len() - 1;
    Ok(Segment {
        from_genesis: anchor.is_none(),
        first: first_link.sequence,
        head: Anchor {
            tenant: stream.0.to_owned(),
            issuer: stream.1.to_owned(),
            stream: stream.2.to_owned(),
            sequence: links[last].1.sequence,
            digest: digests[last],
        },
    })
}

/// Authenticated statements admitted as the evidence of one claim.
///
/// Admission is not a decision about the claim: authentic, admitted evidence
/// can support it, contradict it or settle nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admitted<'a> {
    /// In ascending order of evidence identifier.
    statements: Vec<SignedStatement<'a>>,
}

impl<'a> Admitted<'a> {
    /// The admitted statements, in ascending order of evidence identifier.
    #[must_use]
    pub fn statements(&self) -> &[SignedStatement<'a>] {
        &self.statements
    }

    /// The evidence manifest of these statements
    /// (`verified-evidence-manifest-v1`). The identifiers and times are the
    /// caller's, in wire form, and are not checked.
    #[must_use]
    pub fn manifest(
        &self,
        package_id: &Value,
        claim_id: &Value,
        ingested_at: &Value,
        assembled_at: &Value,
    ) -> Value {
        statement::manifest(
            self.statements.iter(),
            package_id,
            claim_id,
            ingested_at,
            assembled_at,
        )
    }
}

/// Admits statements, each with the body it is said to commit to, as the
/// evidence of a claim of `tenant` that names the evidence `claimed`.
///
/// The tenant must come from the relying party, never from the statements.
///
/// # Errors
///
/// The first admission check that fails.
pub fn admit<'a>(
    tenant: &str,
    claimed: &[&str],
    evidence: &[(Authenticated<'a>, &'a Value)],
) -> Result<Admitted<'a>, EvidenceRefusal> {
    let evidence: Vec<Evidence<'a, ()>> = evidence
        .iter()
        .map(|(authenticated, body)| Evidence {
            statement: authenticated.0,
            body_value: body,
            body: (),
        })
        .collect();
    statement::admit(tenant, claimed, &evidence)?;
    let mut statements: Vec<SignedStatement<'a>> =
        evidence.into_iter().map(|e| e.statement).collect();
    statements.sort_by_key(|s| s.id);
    Ok(Admitted { statements })
}
