// SPDX-License-Identifier: Apache-2.0

//! Refusal codes.

use std::fmt;

/// Why a verifier refuses a package.
///
/// Codes are part of the protocol: every conforming verifier reports the same
/// first failure for the same package. The strings are stable and safe to
/// match on in scripts.
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
    /// Step 8: the decision does not name this protocol and its evaluator.
    UnsupportedEvaluator,
    /// Step 9: a statement does not have the statement's structure. Inside a
    /// package step 7 reports this as `MALFORMED_COMPONENT` first.
    Malformed,
    /// Step 9: a statement is not of the evidence statement protocol.
    UnsupportedProtocol,
    /// Step 9: a statement's payload or chain commitment is not a well-formed
    /// SHA-256 commitment.
    MalformedCommitment,
    /// Step 9: the trust registry holds no key with the statement's key
    /// identifier.
    UnknownKey,
    /// Step 9: the key or the signature scheme is not Ed25519.
    UnsupportedAlgorithm,
    /// Step 9: the key is not trusted for the statement's tenant.
    TenantMismatch,
    /// Step 9: the key does not belong to the statement's issuer.
    IssuerMismatch,
    /// Step 9: the key is not authorized for the statement's source system.
    SourceNotAuthorized,
    /// Step 9: the key was not valid at the statement's observation time.
    KeyNotValid,
    /// Step 9: the signature does not verify over the signing input.
    SignatureInvalid,
    /// Step 10: a statement belongs to another tenant than the evaluation's.
    ForeignTenantEvidence,
    /// Step 10: an evidence identifier occurs twice.
    DuplicateEvidenceId,
    /// Step 10: a statement is not named by the claim.
    EvidenceNotClaimed,
    /// Step 10: the claim names evidence the package does not carry.
    MissingEvidence,
    /// Step 10: a body's digest is not its statement's payload.
    PayloadMismatch,
    /// Step 11: the inputs do not belong together. This is not a decision
    /// about the claim.
    InputMismatch,
    /// Step 12: the decision recomputed from the package is not the one it
    /// carries.
    DecisionMismatch,
    /// Step 13: an issuer signature does not count under the trust registry.
    IssuerSignatureInvalid,
    /// Expectations (`wvp-0.2`): the evaluation's tenant is not the one the
    /// relying party expected.
    TenantNotExpected,
    /// Expectations (`wvp-0.2`): the contract is not the one the relying party
    /// expected.
    ContractNotExpected,
    /// Expectations (`wvp-0.2`): the claim is not the one the relying party
    /// expected.
    ClaimNotExpected,
    /// Work record (`wvp-0.2`): a record the relying party supplied is not
    /// about this package: at least one member differs from the value
    /// computed from the package.
    RecordMismatch,
}

impl RefusalCode {
    /// Every code this crate defines, in the order the checks run.
    pub const ALL: [Self; 29] = [
        Self::NotCanonical,
        Self::UnsupportedVersion,
        Self::MalformedComponent,
        Self::ComponentSet,
        Self::ComponentDigest,
        Self::CommitmentMismatch,
        Self::UnsupportedEvaluator,
        Self::Malformed,
        Self::UnsupportedProtocol,
        Self::MalformedCommitment,
        Self::UnknownKey,
        Self::UnsupportedAlgorithm,
        Self::TenantMismatch,
        Self::IssuerMismatch,
        Self::SourceNotAuthorized,
        Self::KeyNotValid,
        Self::SignatureInvalid,
        Self::ForeignTenantEvidence,
        Self::DuplicateEvidenceId,
        Self::EvidenceNotClaimed,
        Self::MissingEvidence,
        Self::PayloadMismatch,
        Self::InputMismatch,
        Self::DecisionMismatch,
        Self::IssuerSignatureInvalid,
        Self::TenantNotExpected,
        Self::ContractNotExpected,
        Self::ClaimNotExpected,
        Self::RecordMismatch,
    ];

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
            Self::UnsupportedEvaluator => "UNSUPPORTED_EVALUATOR",
            Self::Malformed => "MALFORMED",
            Self::UnsupportedProtocol => "UNSUPPORTED_PROTOCOL",
            Self::MalformedCommitment => "MALFORMED_COMMITMENT",
            Self::UnknownKey => "UNKNOWN_KEY",
            Self::UnsupportedAlgorithm => "UNSUPPORTED_ALGORITHM",
            Self::TenantMismatch => "TENANT_MISMATCH",
            Self::IssuerMismatch => "ISSUER_MISMATCH",
            Self::SourceNotAuthorized => "SOURCE_NOT_AUTHORIZED",
            Self::KeyNotValid => "KEY_NOT_VALID",
            Self::SignatureInvalid => "SIGNATURE_INVALID",
            Self::ForeignTenantEvidence => "FOREIGN_TENANT_EVIDENCE",
            Self::DuplicateEvidenceId => "DUPLICATE_EVIDENCE_ID",
            Self::EvidenceNotClaimed => "EVIDENCE_NOT_CLAIMED",
            Self::MissingEvidence => "MISSING_EVIDENCE",
            Self::PayloadMismatch => "PAYLOAD_MISMATCH",
            Self::InputMismatch => "INPUT_MISMATCH",
            Self::DecisionMismatch => "DECISION_MISMATCH",
            Self::IssuerSignatureInvalid => "ISSUER_SIGNATURE_INVALID",
            Self::TenantNotExpected => "TENANT_NOT_EXPECTED",
            Self::ContractNotExpected => "CONTRACT_NOT_EXPECTED",
            Self::ClaimNotExpected => "CLAIM_NOT_EXPECTED",
            Self::RecordMismatch => "RECORD_MISMATCH",
        }
    }
}

impl fmt::Display for RefusalCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spellings_are_distinct_upper_snake_case() {
        let spellings: std::collections::BTreeSet<_> =
            RefusalCode::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(spellings.len(), RefusalCode::ALL.len());
        for spelling in spellings {
            assert!(
                spelling
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b == b'_'),
                "{spelling}"
            );
        }
        assert_eq!(RefusalCode::NotCanonical.to_string(), "NOT_CANONICAL");
    }
}
