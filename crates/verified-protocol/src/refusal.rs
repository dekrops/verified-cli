//! Refusal codes.

use std::fmt;

/// Why a verifier refuses a package.
///
/// Codes are part of the protocol: every conforming verifier reports the same
/// first failure for the same package. The strings are stable and safe to
/// match on in scripts.
///
/// This version defines the codes of the container checks (steps 1 to 7 of
/// the protocol's verification procedure). Later steps add theirs, so the
/// enum is non-exhaustive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RefusalCode {
    /// Step 1: the text is not the canonical encoding of a JSON value.
    NotCanonical,
    /// Step 2: the package, protocol or canonical-encoding version is not the
    /// one being verified.
    UnsupportedVersion,
    /// Steps 3 and 7: the package or a component does not have exactly the
    /// members and types the protocol defines.
    MalformedComponent,
    /// Step 4: the components are not exactly the six the protocol lists, in
    /// order.
    ComponentSet,
    /// Step 5: a component's digest is not the one its manifest entry states.
    ComponentDigest,
    /// Step 6: the package commitment or identifier does not follow from the
    /// manifest.
    CommitmentMismatch,
}

impl RefusalCode {
    /// The code as the protocol spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotCanonical => "NOT_CANONICAL",
            Self::UnsupportedVersion => "UNSUPPORTED_VERSION",
            Self::MalformedComponent => "MALFORMED_COMPONENT",
            Self::ComponentSet => "COMPONENT_SET",
            Self::ComponentDigest => "COMPONENT_DIGEST",
            Self::CommitmentMismatch => "COMMITMENT_MISMATCH",
        }
    }
}

impl fmt::Display for RefusalCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
