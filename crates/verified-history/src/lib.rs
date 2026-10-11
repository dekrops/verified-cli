// SPDX-License-Identifier: Apache-2.0

//! Work relation v1: reading what authorities say about records.
//!
//! One unit of work leaves several records: a package, a work record in a
//! ledger, a registration at a claim registry. A work relation is a signed
//! statement by which an authority says how records it knows are related.
//! [`read`] takes relations, record texts and the relying party's registry,
//! and reports, for each relation on its own, how it stands.
//!
//! What a reading establishes is narrow, and the names say so:
//!
//! - A relation shows that an authority said something within its scope. It
//!   does not show that the thing is true.
//! - [`Standing::Checked`] means the statement is consistent with the
//!   records in hand. It is not a verification result. Whether a package or
//!   a registration verifies is still decided by those specifications:
//!   **holding a record is not verifying it**.
//! - A record that was not given never makes a reading fail. It makes the
//!   relations to it [`Standing::Stated`]: read, and not checked.
//! - Nothing is known about relations that were not presented, unless their
//!   authority chained them, and never about what follows the last one.
//!
//! There is no single result for a set of relations, as there is no single
//! `valid` for a package.
//!
//! This crate does no I/O. The specification is a draft, and the crate is
//! outside the workspace's compatibility promise until it is not.

mod records;
mod streams;
mod value;

use verified_canonical::{Sha256Digest, Value};
use verified_protocol::relation::{
    RELATION_STATEMENT_KIND, RELATION_SUBJECT_KIND, Reference, Relation,
};
use verified_verifier::Trust;
use verified_verifier::evidence::{Authenticated, authenticate};

use records::Held;
pub use streams::StreamRead;

/// A record text, offered as one kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Offered<'a> {
    /// The kind the text is offered as. It is held only as that kind.
    pub kind: &'a str,
    /// The record's text.
    pub text: &'a str,
}

/// A relation as it travels: the signed statement, and the body its payload
/// commits to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Carried<'a> {
    /// The signed evidence statement.
    pub statement: &'a Value,
    /// The relation body.
    pub body: &'a Value,
}

/// How one relation stands, given the records in hand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Standing {
    /// Not a relation the reader accepts. Carries the code.
    Refused(&'static str),
    /// Authentic, and a held record states otherwise. Carries the first code.
    Contradicted(&'static str),
    /// Authentic, every reference is held, and every comparison agrees.
    Checked,
    /// Authentic, nothing held contradicts it, and these references are
    /// absent.
    Stated(Vec<Reference>),
}

impl Standing {
    /// The standing's name on the wire.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Refused(_) => "REFUSED",
            Self::Contradicted(_) => "CONTRADICTED",
            Self::Checked => "CHECKED",
            Self::Stated(_) => "STATED",
        }
    }
}

/// One relation as read: who said it, if anyone the reader trusts did, and
/// how it stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Read {
    /// The relation's name, once its body was read.
    pub relation: Option<&'static str>,
    /// The source the statement speaks as, once the statement verified.
    pub source: Option<String>,
    /// The key that signed, once the statement verified.
    pub key_id: Option<String>,
    /// How the relation stands.
    pub standing: Standing,
}

/// Whether one package claim and one registered claim are the same claim.
/// Nobody signs this: it is computed from the three records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SameClaim {
    /// The package, by its commitment.
    pub package: Sha256Digest,
    /// The claim commitment.
    pub claim: Sha256Digest,
    /// The agreement the claim commitment names.
    pub agreement: Sha256Digest,
    /// `SAME_CLAIM`, or the first condition that does not hold.
    pub result: &'static str,
}

/// What a set of relations and records shows. Each part stands on its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reading {
    /// Each offered record, in the order given: the reference it is held
    /// under, or why it is not held.
    pub records: Vec<Result<Reference, &'static str>>,
    /// Each relation, in the order given.
    pub relations: Vec<Read>,
    /// Each held package and registered claim that share a claim ID.
    pub same_claims: Vec<SameClaim>,
    /// Each stream the presented statements belong to.
    pub streams: Vec<StreamRead>,
}

/// The first comparison a held record fails, each made only when the
/// records it needs are held.
fn contradiction(
    relation: &Relation<'_>,
    held: &[(Reference, Held)],
    tenant: &str,
) -> Option<&'static str> {
    let find = |reference: &Reference| {
        held.iter()
            .find(|(named, _)| named == reference)
            .map(|(_, record)| record)
    };
    let fails = |code: &'static str, holds: Option<bool>| (holds == Some(false)).then_some(code);
    match relation {
        Relation::Recorded { record, claim_id } => {
            let work = find(record).and_then(Held::as_record);
            fails("CLAIM_MISMATCH", work.map(|w| w.claim_id == *claim_id))
        }
        Relation::Linked {
            record,
            agreement,
            claim,
            receipt,
            claim_id,
            registry,
            sequence,
        } => {
            let work = find(record).and_then(Held::as_record);
            let agreed = find(agreement).and_then(Held::as_agreement);
            let committed = find(claim).and_then(Held::as_claim);
            let received = find(receipt).and_then(Held::as_receipt);
            let both = |a: Option<bool>, b: Option<bool>| a.zip(b).map(|(a, b)| a && b);
            fails("CLAIM_MISMATCH", work.map(|w| w.claim_id == *claim_id))
                .or_else(|| fails("CLAIM_MISMATCH", committed.map(|c| c.id == *claim_id)))
                .or_else(|| {
                    fails(
                        "AGREEMENT_MISMATCH",
                        committed.map(|c| c.agreement.states(&agreement.digest)),
                    )
                })
                .or_else(|| fails("TENANT_MISMATCH", agreed.map(|a| a.tenant == tenant)))
                .or_else(|| {
                    fails(
                        "CONTRACT_MISMATCH",
                        agreed.zip(work).map(|(a, w)| a.contract == w.contract),
                    )
                })
                .or_else(|| {
                    fails(
                        "RECEIPT_MISMATCH",
                        received.map(|r| r.claim.states(&claim.digest)),
                    )
                })
                .or_else(|| {
                    fails(
                        "RECEIPT_MISMATCH",
                        both(
                            received.map(|r| r.registry == *registry),
                            received.map(|r| r.sequence == *sequence),
                        ),
                    )
                })
                .or_else(|| {
                    fails(
                        "REGISTRY_MISMATCH",
                        agreed.zip(received).map(|(a, r)| a.registry == r.registry),
                    )
                })
        }
        Relation::Groups { .. } => None,
    }
}

/// The derived relation, for every held package and claim commitment that
/// share a claim ID, where the agreement the commitment names is held too.
fn same_claims(held: &[(Reference, Held)]) -> Vec<SameClaim> {
    let mut found = Vec::new();
    for (package, made) in held.iter().filter_map(|(r, h)| Some((r, h.as_package()?))) {
        for (claim, committed) in held.iter().filter_map(|(r, h)| Some((r, h.as_claim()?))) {
            if committed.id != made.id {
                continue;
            }
            let named = held.iter().find_map(|(r, h)| {
                let agreement = h.as_agreement()?;
                committed
                    .agreement
                    .states(&r.digest)
                    .then_some((r, agreement))
            });
            let Some((agreement, agreed)) = named else {
                continue;
            };
            let result = if agreed.tenant != made.tenant {
                "TENANT_MISMATCH"
            } else if agreed.contract != made.contract {
                "CONTRACT_MISMATCH"
            } else if agreed.claimant != made.claimant {
                "CLAIMANT_MISMATCH"
            } else if !committed.inputs.states(&made.inputs) {
                "INPUTS_MISMATCH"
            } else {
                "SAME_CLAIM"
            };
            found.push(SameClaim {
                package: package.digest,
                claim: claim.digest,
                agreement: agreement.digest,
                result,
            });
        }
    }
    found.sort_by_key(|same| (same.package.to_hex(), same.claim.to_hex()));
    found.dedup();
    found
}

/// Whether the statement carries `relation` as the specification requires:
/// an attestation whose subject names the source, this kind of subject, and
/// what the relation is about.
fn carries(authentic: &Authenticated<'_>, relation: &Relation<'_>) -> bool {
    let statement = authentic.statement();
    let subject = statement
        .statement
        .as_object()
        .and_then(|o| o.get("subject"))
        .and_then(Value::as_object);
    let member = |name| subject.and_then(|o| o.get(name)).and_then(Value::as_str);
    statement.kind == RELATION_STATEMENT_KIND
        && member("system") == Some(statement.source_system)
        && member("kind") == Some(RELATION_SUBJECT_KIND)
        && member("key") == Some(relation.key())
}

fn read_one(
    carried: &Carried<'_>,
    authentic: &Authenticated<'_>,
    held: &[(Reference, Held)],
) -> Read {
    let statement = authentic.statement();
    let said = |relation, standing| Read {
        relation,
        source: Some(statement.source_system.to_owned()),
        key_id: Some(statement.signature.key_id.to_owned()),
        standing,
    };
    if !statement.payload.states(&carried.body.digest()) {
        return said(None, Standing::Refused("PAYLOAD_MISMATCH"));
    }
    let relation = match Relation::from_value(carried.body) {
        Ok(relation) => relation,
        Err(code) => return said(None, Standing::Refused(code.as_str())),
    };
    let name = Some(relation.name());
    if !carries(authentic, &relation) {
        return said(name, Standing::Refused("CARRIER_MISMATCH"));
    }
    if let Some(code) = contradiction(&relation, held, statement.tenant) {
        return said(name, Standing::Contradicted(code));
    }
    let absent: Vec<Reference> = relation
        .references()
        .into_iter()
        .filter(|reference| !held.iter().any(|(named, _)| named == reference))
        .collect();
    if absent.is_empty() {
        said(name, Standing::Checked)
    } else {
        said(name, Standing::Stated(absent))
    }
}

/// Reads relations against the records in hand, under the relying party's
/// own registry. Offline, and without a clock.
///
/// It resolves references and compares what records state. It verifies no
/// record: do that with each record's own verifier, and report the results
/// beside this reading.
#[must_use]
pub fn read(relations: &[Carried<'_>], records: &[Offered<'_>], trust: &Trust) -> Reading {
    let offered: Vec<Result<(Reference, Held), &'static str>> =
        records.iter().map(records::hold).collect();
    let mut held: Vec<(Reference, Held)> = Vec::new();
    for (reference, record) in offered.iter().flatten() {
        if !held.iter().any(|(named, _)| named == reference) {
            held.push((*reference, record.clone()));
        }
    }
    let mut authentic = Vec::new();
    let relations = relations
        .iter()
        .map(|carried| match authenticate(carried.statement, trust) {
            Err(refusal) => Read {
                relation: None,
                source: None,
                key_id: None,
                standing: Standing::Refused(refusal.code.as_str()),
            },
            Ok(statement) => {
                let read = read_one(carried, &statement, &held);
                authentic.push(statement);
                read
            }
        })
        .collect();
    Reading {
        records: offered
            .into_iter()
            .map(|record| record.map(|(reference, _)| reference))
            .collect(),
        relations,
        same_claims: same_claims(&held),
        streams: streams::read(&authentic),
    }
}
