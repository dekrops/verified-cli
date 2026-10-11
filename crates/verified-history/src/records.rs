// SPDX-License-Identifier: Apache-2.0

//! Records a reader holds: each text parsed as the kind it is offered as,
//! and named by that kind's own digest. Holding is not verifying.

use verified_canonical::CANONICAL_VERSION;
use verified_canonical::{Limits, Sha256Digest, Value, parse_canonical};
use verified_protocol::registration::{SignedAgreement, SignedClaim, SignedReceipt};
use verified_protocol::relation::{RecordKind, Reference};
use verified_protocol::v02::{Claim, WorkRecord};
use verified_protocol::{Container, DeclaredVersion, PACKAGE_VERSION, WireDigest};

use crate::Offered;

/// A digest as a record states it, kept as written: two stated digests are
/// the same only if both the algorithm and the text are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Stated {
    algorithm: String,
    hex: String,
}

impl Stated {
    fn of(digest: WireDigest<'_>) -> Self {
        Self {
            algorithm: digest.algorithm.to_owned(),
            hex: digest.hex.to_owned(),
        }
    }

    /// Whether this states exactly `digest`.
    pub(crate) fn states(&self, digest: &Sha256Digest) -> bool {
        self.algorithm == Sha256Digest::ALGORITHM && self.hex == digest.to_hex()
    }
}

/// What is read of a package: its claim, and nothing else.
#[derive(Clone, Debug)]
pub(crate) struct PackageClaim {
    pub(crate) id: String,
    pub(crate) tenant: String,
    pub(crate) contract: Stated,
    pub(crate) claimant: String,
    /// The digest of the claim's input values.
    pub(crate) inputs: Sha256Digest,
}

#[derive(Clone, Debug)]
pub(crate) struct Record {
    pub(crate) claim_id: String,
    pub(crate) contract: Stated,
}

#[derive(Clone, Debug)]
pub(crate) struct Agreed {
    pub(crate) tenant: String,
    pub(crate) contract: Stated,
    pub(crate) claimant: String,
    pub(crate) registry: String,
}

#[derive(Clone, Debug)]
pub(crate) struct Committed {
    pub(crate) id: String,
    pub(crate) agreement: Stated,
    pub(crate) inputs: Stated,
}

#[derive(Clone, Debug)]
pub(crate) struct Received {
    pub(crate) registry: String,
    pub(crate) sequence: i64,
    pub(crate) claim: Stated,
}

/// A held record, as much of it as a reading compares.
#[derive(Clone, Debug)]
pub(crate) enum Held {
    Package(PackageClaim),
    Record(Record),
    Agreement(Agreed),
    Claim(Committed),
    Receipt(Received),
}

impl Held {
    pub(crate) const fn as_package(&self) -> Option<&PackageClaim> {
        match self {
            Self::Package(package) => Some(package),
            _ => None,
        }
    }

    pub(crate) const fn as_record(&self) -> Option<&Record> {
        match self {
            Self::Record(record) => Some(record),
            _ => None,
        }
    }

    pub(crate) const fn as_agreement(&self) -> Option<&Agreed> {
        match self {
            Self::Agreement(agreement) => Some(agreement),
            _ => None,
        }
    }

    pub(crate) const fn as_claim(&self) -> Option<&Committed> {
        match self {
            Self::Claim(claim) => Some(claim),
            _ => None,
        }
    }

    pub(crate) const fn as_receipt(&self) -> Option<&Received> {
        match self {
            Self::Receipt(receipt) => Some(receipt),
            _ => None,
        }
    }
}

/// A package is held only as what its text commits to: a `wvp-0.2`
/// container whose stated commitment is its manifest's digest, and whose
/// `claim.json` has the digest the manifest names. Nothing else of it is
/// read.
fn package(value: &Value) -> Option<(Sha256Digest, Held)> {
    let declared = DeclaredVersion::of(value);
    let version = declared
        .package_version
        .and_then(verified_canonical::Integer::to_i64);
    (version == Some(PACKAGE_VERSION)
        && declared.protocol == Some("wvp-0.2")
        && declared.canonical_version == Some(CANONICAL_VERSION))
    .then_some(())?;
    let container = Container::from_value(value).ok()?;
    let commitment = container.manifest.digest();
    container
        .package_commitment
        .states(&commitment)
        .then_some(())?;
    let file = container
        .files
        .iter()
        .find(|file| file.path == "claim.json")?;
    let listed = container
        .manifest_files
        .iter()
        .find(|entry| entry.path == "claim.json")?;
    listed.hash.states(&file.content.digest()).then_some(())?;
    let claim = Claim::from_value(file.content).ok()?;
    let held = Held::Package(PackageClaim {
        id: claim.id.to_owned(),
        tenant: claim.tenant.to_owned(),
        contract: Stated::of(claim.contract),
        claimant: claim.claimant().to_owned(),
        inputs: claim.inputs.digest(),
    });
    Some((commitment, held))
}

fn record(value: &Value) -> Option<(Sha256Digest, Held)> {
    let read = WorkRecord::from_value(value).ok()?;
    let held = Held::Record(Record {
        claim_id: read.claim_id.to_owned(),
        contract: Stated::of(read.contract),
    });
    Some((value.digest(), held))
}

fn agreement(value: &Value) -> Option<(Sha256Digest, Held)> {
    let read = SignedAgreement::from_value(value).ok()?;
    let held = Held::Agreement(Agreed {
        tenant: read.tenant.to_owned(),
        contract: Stated::of(read.contract_digest),
        claimant: read.claimant.to_owned(),
        registry: read.registry.to_owned(),
    });
    Some((read.agreement.digest(), held))
}

fn claim(value: &Value) -> Option<(Sha256Digest, Held)> {
    let read = SignedClaim::from_value(value).ok()?;
    let held = Held::Claim(Committed {
        id: read.id.to_owned(),
        agreement: Stated::of(read.agreement),
        inputs: Stated::of(read.inputs),
    });
    Some((read.claim.digest(), held))
}

fn receipt(value: &Value) -> Option<(Sha256Digest, Held)> {
    let read = SignedReceipt::from_value(value).ok()?;
    let held = Held::Receipt(Received {
        registry: read.registry.to_owned(),
        sequence: read.sequence,
        claim: Stated::of(read.claim),
    });
    Some((read.receipt.digest(), held))
}

/// Parses an offered text as its kind and names it, or says why it is not
/// held: a kind this version does not define, or a text that is not the
/// canonical encoding of a record of that kind.
pub(crate) fn hold(offered: &Offered<'_>) -> Result<(Reference, Held), &'static str> {
    let kind = RecordKind::from_name(offered.kind).ok_or("UNKNOWN_KIND")?;
    let value = parse_canonical(offered.text.as_bytes(), &Limits::DEFAULT)
        .map_err(|_| "MALFORMED_RECORD")?;
    let read = match kind {
        RecordKind::Package => package(&value),
        RecordKind::WorkRecord => record(&value),
        RecordKind::Agreement => agreement(&value),
        RecordKind::ClaimCommitment => claim(&value),
        RecordKind::Receipt => receipt(&value),
    };
    let (digest, held) = read.ok_or("MALFORMED_RECORD")?;
    Ok((Reference { kind, digest }, held))
}
