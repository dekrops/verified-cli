//! What a verification established.

use verified_canonical::Sha256Digest;
use verified_contract::{Conflict, RequirementValue};
use verified_protocol::{ComponentPath, Decision, PackageId, ProtocolVersion};

/// Whether one property was established.
///
/// A property that was checked and failed is never a `Finding`: it is a
/// refusal, and there is no report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Finding {
    /// The checks for this property ran and passed.
    Established,
    /// The checks for this property did not run. Nothing is known about it.
    NotChecked(NotChecked),
}

impl Finding {
    /// Whether the property was established.
    #[must_use]
    pub const fn is_established(self) -> bool {
        matches!(self, Self::Established)
    }
}

/// Why a property was not checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NotChecked {
    /// The relying party supplied no trust registry. Nothing in a package
    /// can stand in for one.
    NoTrustRegistry,
}

/// A component and the digest of its canonical content, as computed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComponentCommitment {
    /// Which component.
    pub path: ComponentPath,
    /// The SHA-256 of its canonical content.
    pub digest: Sha256Digest,
}

/// Which agreement a `wvp-0.2` decision is about.
///
/// Whether it is the agreement the relying party has in mind is theirs to
/// check, by digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractSummary {
    /// The contract's identifier.
    pub id: String,
    /// The contract's version.
    pub version: String,
    /// The contract digest: the SHA-256 of its canonical text.
    pub digest: Sha256Digest,
}

/// One condition of the `order-transition` evaluator (`wvp-0.1`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Condition {
    /// The condition's identifier.
    pub id: &'static str,
    /// Whether it holds.
    pub holds: bool,
    /// The statements it holds because of, in ascending order.
    pub evidence: Vec<String>,
}

/// What the evaluator found on the way to its decision.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Evaluation {
    /// `wvp-0.1`: the four conditions of the `order-transition` evaluator.
    OrderTransition {
        /// The conditions, in ascending order of identifier.
        conditions: Vec<Condition>,
    },
    /// `wvp-0.2`: the result of evaluating the Work Contract Language 1
    /// contract.
    WorkContract {
        /// The value of every requirement, in contract order.
        requirements: Vec<RequirementValue>,
        /// Authentic records the contract does not accept.
        ignored: Vec<String>,
        /// The conflicts among accepted records.
        conflicts: Vec<Conflict>,
    },
}

/// A decision this verifier recomputed and found identical, byte for byte,
/// to the one the package carries.
///
/// A reproduced `CONTRADICTED` or `UNDETERMINED` is a successful
/// verification of a package whose claim is not supported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reproduced {
    /// The decision.
    pub decision: Decision,
    /// What it rests on.
    pub evaluation: Evaluation,
}

/// Whether the decision was reproduced.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecisionFinding {
    /// Recomputed from the package's own claim, contract, evidence and
    /// inputs, and equal to the decision it carries.
    Reproduced(Reproduced),
    /// Not recomputed. The decision the package carries is its issuer's
    /// claim and nothing more.
    NotChecked(NotChecked),
}

/// What is known about issuer signatures over the decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IssuerSignature {
    /// Every carried signature counts under the trust registry.
    Established {
        /// How many signatures the package carries.
        count: usize,
    },
    /// The package carries no issuer signature. Nobody stands behind the
    /// decision; it was reproduced regardless.
    Absent,
    /// Not checked.
    NotChecked {
        /// How many signatures the package carries, unverified.
        carried: usize,
        /// Why they were not checked.
        reason: NotChecked,
    },
}

/// What the relying party expected a package to be about. An expectation
/// that is not given is not checked, and nothing in a package can supply one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Expectations {
    /// The tenant the evaluation must be for.
    pub tenant: Option<String>,
    /// The digest of the contract the decision must be about.
    pub contract: Option<Sha256Digest>,
    /// The identifier of the claim the package must carry.
    pub claim: Option<String>,
}

impl Expectations {
    /// Whether no expectation is given.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.tenant.is_none() && self.contract.is_none() && self.claim.is_none()
    }
}

/// What verifying a package that was not refused established.
///
/// Each property stands alone. Read them individually; do not reduce a report
/// to one boolean. No property, here or anywhere, says that a source told the
/// truth.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The protocol version the package declares and was checked as.
    pub protocol: ProtocolVersion,
    /// The package's identifier, recomputed from its manifest.
    pub package_id: PackageId,
    /// The six components with their recomputed digests, in protocol order.
    pub components: [ComponentCommitment; 6],
    /// The tenant the evaluation is for, as `inputs.json` states it.
    pub tenant: String,
    /// The claim's identifier.
    pub claim: String,
    /// `wvp-0.2`: which agreement the decision is about.
    pub contract: Option<ContractSummary>,
    /// How many evidence statements the package carries.
    pub statements: usize,

    /// Package integrity (steps 1 to 7): the components are well formed and
    /// are the ones the package commits to.
    pub integrity: Finding,
    /// Every evidence statement's signature verifies.
    pub evidence_signatures: Finding,
    /// Every signer is authorized, for its statement's tenant, issuer, source
    /// and time, by the registry the relying party supplied.
    pub signer_authority: Finding,
    /// The decision recomputed from the package equals the one it carries.
    pub decision: DecisionFinding,
    /// Issuer signatures over the decision.
    pub issuer_signature: IssuerSignature,
    /// The expectations that were given. All of them were met: an unmet one
    /// is a refusal.
    pub expectations_met: Expectations,
}

impl Report {
    /// Whether every property the protocol defines was checked. A complete
    /// report can still carry a `CONTRADICTED` or `UNDETERMINED` decision,
    /// and never says anything about source truthfulness.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.integrity.is_established()
            && self.evidence_signatures.is_established()
            && self.signer_authority.is_established()
            && matches!(self.decision, DecisionFinding::Reproduced(_))
            && matches!(
                self.issuer_signature,
                IssuerSignature::Established { .. } | IssuerSignature::Absent
            )
    }
}
