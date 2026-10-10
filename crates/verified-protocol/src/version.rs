//! Protocol versions.

use std::fmt;
use std::str::FromStr;

/// The package container version both protocol versions use.
pub const PACKAGE_VERSION: i64 = 2;

/// A version of the Work Verification Protocol.
///
/// The versions have different semantics. A package of one is never a package
/// of the other, and nothing in this workspace converts between them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProtocolVersion {
    /// `wvp-0.1` (draft): the contract names an evaluator.
    V0_1,
    /// `wvp-0.2` (draft): the contract is Work Contract Language 1 data.
    V0_2,
}

impl ProtocolVersion {
    /// Every version this crate knows, oldest first.
    pub const ALL: [Self; 2] = [Self::V0_1, Self::V0_2];

    /// The identifier a manifest carries.
    #[must_use]
    pub const fn identifier(self) -> &'static str {
        match self {
            Self::V0_1 => "wvp-0.1",
            Self::V0_2 => "wvp-0.2",
        }
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.identifier())
    }
}

/// The identifier names no protocol version this crate knows.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unknown protocol {0:?}; known: wvp-0.1, wvp-0.2")]
pub struct UnknownProtocol(pub String);

impl FromStr for ProtocolVersion {
    type Err = UnknownProtocol;

    fn from_str(identifier: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|v| v.identifier() == identifier)
            .ok_or_else(|| UnknownProtocol(identifier.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_round_trip_exactly() {
        for version in ProtocolVersion::ALL {
            assert_eq!(version.identifier().parse(), Ok(version));
        }
        for unknown in ["", "wvp-0.3", "WVP-0.2", "wvp-0.2 ", "0.2"] {
            assert!(unknown.parse::<ProtocolVersion>().is_err(), "{unknown:?}");
        }
    }
}
