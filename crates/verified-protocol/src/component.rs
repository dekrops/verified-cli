// SPDX-License-Identifier: Apache-2.0

//! The components of a package.

use std::fmt;

/// One of the six components a package carries.
///
/// The declaration order is the order the protocol requires them in, both in
/// a package's `files` and in its manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ComponentPath {
    /// `claim.json`
    Claim,
    /// `contract.json`
    Contract,
    /// `decision.json`
    Decision,
    /// `evidence/bodies.json`
    EvidenceBodies,
    /// `evidence/statements.json`
    EvidenceStatements,
    /// `inputs.json`
    Inputs,
}

impl ComponentPath {
    /// The components, in protocol order.
    pub const ALL: [Self; 6] = [
        Self::Claim,
        Self::Contract,
        Self::Decision,
        Self::EvidenceBodies,
        Self::EvidenceStatements,
        Self::Inputs,
    ];

    /// The path as it appears in a package.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claim => "claim.json",
            Self::Contract => "contract.json",
            Self::Decision => "decision.json",
            Self::EvidenceBodies => "evidence/bodies.json",
            Self::EvidenceStatements => "evidence/statements.json",
            Self::Inputs => "inputs.json",
        }
    }
}

impl fmt::Display for ComponentPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_order_is_ascending_path_order() {
        let paths: Vec<_> = ComponentPath::ALL.iter().map(|p| p.as_str()).collect();
        let mut sorted = paths.clone();
        sorted.sort_unstable();
        assert_eq!(paths, sorted);
        assert!(ComponentPath::ALL.is_sorted());
    }
}
