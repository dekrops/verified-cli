//! What a verification established.

use verified_canonical::Sha256Digest;
use verified_protocol::{ComponentPath, PackageId, ProtocolVersion};

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
    /// This version of the verifier does not implement the check.
    NotImplemented,
}

/// A component and the digest of its canonical content, as computed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComponentCommitment {
    /// Which component.
    pub path: ComponentPath,
    /// The SHA-256 of its canonical content.
    pub digest: Sha256Digest,
}

/// What verifying a package that was not refused established.
///
/// Each property stands alone. Read them individually; do not reduce a report
/// to one boolean.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The protocol version the package declares and was checked as.
    pub protocol: ProtocolVersion,
    /// The package's identifier, recomputed from its manifest.
    pub package_id: PackageId,
    /// The six components with their recomputed digests, in protocol order.
    pub components: [ComponentCommitment; 6],
    /// How many issuer signatures the package carries. None was verified.
    pub issuer_signatures_carried: usize,

    /// Steps 1 to 6: canonical text, versions, container shape, component
    /// set, component digests, package commitment.
    pub container: Finding,
    /// Step 7: every component well formed at every depth.
    pub component_shapes: Finding,
    /// Every evidence statement's signature verifies.
    pub evidence_signatures: Finding,
    /// Every signer is authorized by the relying party's trust registry.
    pub signer_authority: Finding,
    /// The decision recomputed from the package equals the one it carries.
    pub decision_reproduced: Finding,
    /// Every issuer signature counts under the trust registry.
    pub issuer_signature: Finding,
}

impl Report {
    /// Package integrity (protocol steps 1 to 7): the components are well
    /// formed and are the ones the package commits to.
    #[must_use]
    pub fn integrity(&self) -> Finding {
        match (self.container, self.component_shapes) {
            (Finding::Established, shapes) => shapes,
            (not_checked, _) => not_checked,
        }
    }

    /// Whether every property the protocol defines was checked.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        [
            self.container,
            self.component_shapes,
            self.evidence_signatures,
            self.signer_authority,
            self.decision_reproduced,
            self.issuer_signature,
        ]
        .into_iter()
        .all(Finding::is_established)
    }
}
