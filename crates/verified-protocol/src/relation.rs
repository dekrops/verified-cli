// SPDX-License-Identifier: Apache-2.0

//! Work relation v1: the structure of a relation body.
//!
//! A work relation is a signed statement by which an authority says how
//! records it knows are related. This module reads the body such a
//! statement commits to. It checks structure only: who said it, and whether
//! the records it names say the same, is the reader's work.
//!
//! The specification is a draft, and this module is outside the crate's
//! compatibility promise until it is not.

use std::cmp::Ordering;

use verified_canonical::{Sha256Digest, Value};

use crate::shape::{self, At};

/// The protocol identifier a relation body states.
pub const RELATION_PROTOCOL: &str = "verified-work-relation-v1";
/// The evidence kind of a statement that carries a relation.
pub const RELATION_STATEMENT_KIND: &str = "SignedAttestation";
/// The `kind` of the subject of a statement that carries a relation.
pub const RELATION_SUBJECT_KIND: &str = "work-relation";

/// The kinds of record a reference can name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecordKind {
    /// A WVP v0.2 package, by its package commitment.
    Package,
    /// A work record, by the digest of its canonical text.
    WorkRecord,
    /// A claim registration agreement, by the digest of the agreement.
    Agreement,
    /// A claim registration claim, by the digest of the claim.
    ClaimCommitment,
    /// A claim registration receipt, by the digest of the receipt.
    Receipt,
}

impl RecordKind {
    /// Every kind this version defines.
    pub const ALL: [Self; 5] = [
        Self::Package,
        Self::WorkRecord,
        Self::Agreement,
        Self::ClaimCommitment,
        Self::Receipt,
    ];

    /// The kind's name on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Package => "package",
            Self::WorkRecord => "work-record",
            Self::Agreement => "agreement",
            Self::ClaimCommitment => "claim-commitment",
            Self::Receipt => "receipt",
        }
    }

    /// The kind with this wire name, if this version defines one.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == name)
    }
}

/// A record, named by its kind and that kind's own digest.
///
/// Two references are the same only if both are equal: a reference of one
/// kind never names a record of another, whatever the bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Reference {
    /// What kind of record is named.
    pub kind: RecordKind,
    /// The record's digest, as its own specification defines it.
    pub digest: Sha256Digest,
}

impl Reference {
    /// The one order a group's members have: by kind name, then by the
    /// digest's hexadecimal text, both as byte strings.
    #[must_use]
    pub fn wire_order(&self, other: &Self) -> Ordering {
        self.kind
            .as_str()
            .cmp(other.kind.as_str())
            .then_with(|| self.digest.to_hex().cmp(&other.digest.to_hex()))
    }
}

/// Why a body is not a relation of this version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RelationCode {
    /// The body does not have a relation's structure.
    #[error("the body is not a well-formed relation")]
    Malformed,
    /// The body states another protocol.
    #[error("the body states another protocol")]
    UnsupportedProtocol,
    /// The body names a relation this version does not define.
    #[error("the body names a relation this version does not define")]
    UnknownRelation,
}

impl RelationCode {
    /// The code on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "MALFORMED",
            Self::UnsupportedProtocol => "UNSUPPORTED_PROTOCOL",
            Self::UnknownRelation => "UNKNOWN_RELATION",
        }
    }
}

/// What an authority says about records it knows.
///
/// It shows that the authority said so within its scope, never that the
/// thing is true: `Recorded` is not an acceptance, `Linked` is not the
/// claim's state at the registry, and `Groups` is not completeness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Relation<'a> {
    /// A ledger holds this work record.
    Recorded {
        /// The work record.
        record: Reference,
        /// The claim the record is of (a UUID). An attribute, not a name.
        claim_id: &'a str,
    },
    /// A ledger holds this registration for this work record.
    Linked {
        /// The work record.
        record: Reference,
        /// The agreement the claim was registered under.
        agreement: Reference,
        /// The registered claim.
        claim: Reference,
        /// The registry's receipt.
        receipt: Reference,
        /// The claim (a UUID).
        claim_id: &'a str,
        /// The registry's name, as the receipt has it.
        registry: &'a str,
        /// The receipt's position in the registry's log.
        sequence: i64,
    },
    /// An application says these records belong to one group.
    Groups {
        /// The group's name.
        group: &'a str,
        /// The members, distinct and in [`Reference::wire_order`].
        members: Vec<Reference>,
    },
}

fn reference(value: &Value, at: &At<'_>, allowed: &[RecordKind]) -> Option<Reference> {
    let object = shape::object(value, at, &["digest", "kind"]).ok()?;
    let kind = shape::text(shape::get(object, "kind"), &at.member("kind")).ok()?;
    let kind = RecordKind::from_name(kind).filter(|kind| allowed.contains(kind))?;
    let stated = shape::digest(shape::get(object, "digest"), &at.member("digest")).ok()?;
    let digest: Sha256Digest = stated.hex.parse().ok()?;
    (stated.algorithm == Sha256Digest::ALGORITHM).then_some(Reference { kind, digest })
}

impl<'a> Relation<'a> {
    /// The relation's name on the wire.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Recorded { .. } => "recorded",
            Self::Linked { .. } => "linked",
            Self::Groups { .. } => "groups",
        }
    }

    /// What the relation is about, as the carrying statement's subject key
    /// states it: the claim, or the group.
    #[must_use]
    pub const fn key(&self) -> &'a str {
        match self {
            Self::Recorded { claim_id, .. } | Self::Linked { claim_id, .. } => claim_id,
            Self::Groups { group, .. } => group,
        }
    }

    /// The references the relation makes, in the order its members are
    /// specified.
    #[must_use]
    pub fn references(&self) -> Vec<Reference> {
        match self {
            Self::Recorded { record, .. } => vec![*record],
            Self::Linked {
                record,
                agreement,
                claim,
                receipt,
                ..
            } => vec![*record, *agreement, *claim, *receipt],
            Self::Groups { members, .. } => members.clone(),
        }
    }

    /// Reads a relation body, in the specification's order: an object with
    /// a text `protocol`; this protocol; exactly one other member; a
    /// relation of this version; and exactly that relation's content.
    ///
    /// # Errors
    ///
    /// The first of those that does not hold.
    pub fn from_value(body: &'a Value) -> Result<Self, RelationCode> {
        let object = body.as_object().ok_or(RelationCode::Malformed)?;
        let protocol = object
            .get("protocol")
            .and_then(Value::as_str)
            .ok_or(RelationCode::Malformed)?;
        if protocol != RELATION_PROTOCOL {
            return Err(RelationCode::UnsupportedProtocol);
        }
        let mut others = object.iter().filter(|(name, _)| *name != "protocol");
        let (Some((name, content)), None) = (others.next(), others.next()) else {
            return Err(RelationCode::Malformed);
        };
        let at = At::root(name);
        let read = match name {
            "recorded" => Self::recorded(content, &at),
            "linked" => Self::linked(content, &at),
            "groups" => Self::groups(content, &at),
            _ => return Err(RelationCode::UnknownRelation),
        };
        read.ok_or(RelationCode::Malformed)
    }

    fn recorded(content: &'a Value, at: &At<'_>) -> Option<Self> {
        let o = shape::object(content, at, &["claimId", "record"]).ok()?;
        Some(Self::Recorded {
            record: reference(
                shape::get(o, "record"),
                &at.member("record"),
                &[RecordKind::WorkRecord],
            )?,
            claim_id: shape::uuid(shape::get(o, "claimId"), &at.member("claimId")).ok()?,
        })
    }

    fn linked(content: &'a Value, at: &At<'_>) -> Option<Self> {
        let o = shape::object(
            content,
            at,
            &[
                "agreement",
                "claim",
                "claimId",
                "receipt",
                "record",
                "registry",
                "sequence",
            ],
        )
        .ok()?;
        let named =
            |name: &'static str, kind| reference(shape::get(o, name), &at.member(name), &[kind]);
        let registry = shape::text(shape::get(o, "registry"), &at.member("registry")).ok()?;
        let sequence = shape::int64(shape::get(o, "sequence"), &at.member("sequence")).ok()?;
        (!registry.is_empty() && sequence >= 0).then_some(())?;
        Some(Self::Linked {
            record: named("record", RecordKind::WorkRecord)?,
            agreement: named("agreement", RecordKind::Agreement)?,
            claim: named("claim", RecordKind::ClaimCommitment)?,
            receipt: named("receipt", RecordKind::Receipt)?,
            claim_id: shape::uuid(shape::get(o, "claimId"), &at.member("claimId")).ok()?,
            registry,
            sequence,
        })
    }

    fn groups(content: &'a Value, at: &At<'_>) -> Option<Self> {
        let o = shape::object(content, at, &["group", "members"]).ok()?;
        let group = shape::text(shape::get(o, "group"), &at.member("group")).ok()?;
        let listed = shape::list(shape::get(o, "members"), &at.member("members")).ok()?;
        let allowed = [RecordKind::Package, RecordKind::WorkRecord];
        let members = listed
            .iter()
            .map(|member| reference(member, at, &allowed))
            .collect::<Option<Vec<_>>>()?;
        let ordered = members
            .windows(2)
            .all(|pair| pair[0].wire_order(&pair[1]) == Ordering::Less);
        (!group.is_empty() && !members.is_empty() && ordered)
            .then_some(Self::Groups { group, members })
    }
}
