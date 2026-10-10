// SPDX-License-Identifier: Apache-2.0

//! Claim registration v1 (a **draft**): verifying that a claim was
//! registered.
//!
//! A registration is three signed objects: the agreement two parties made,
//! a claim the claimant made under it, and the receipt of the registry the
//! agreement names. [`verify_registration`] applies the protocol's fourteen
//! checks to them, in order, under keys the relying party trusts
//! ([`RegistrationTrust`]).
//!
//! # What a verified registration establishes
//!
//! The claim with this identifier, committing to these inputs and this
//! unit, was made under an agreement both parties signed. The registry they
//! named received it at a stated time, as a stated entry of its log, and the
//! respondent must answer by a stated time.
//!
//! # What it does not establish
//!
//! - That the claim is true. Whether the work was done is decided later, by
//!   verifying evidence against the contract.
//! - That the registry applied its own rules, or that nothing was removed
//!   from its log. One receipt shows one entry.
//! - That the unit is derived correctly from the claim's inputs. Only
//!   holders of the unit key can check that.
//! - When the claim or the agreement was really made: the times the parties
//!   state are not authenticated. The registry's receipt time is, by a key
//!   the relying party chose to trust for honest time and order.
//!
//! [`log`] checks a run of a registry's log, and a held entry against it.
//!
//! [`audit`] reads a whole log with the documents it names and finds every
//! claim's state.
//!
//! The protocol's unit check verifies no signature and is not here: see
//! `verified_work_unit::registered`.

use ed25519_dalek::VerifyingKey;
use verified_canonical::{Limits, Sha256Digest, SigningDomain, Value, parse_canonical};
use verified_protocol::registration::{
    AGREEMENT_DOMAIN, CLAIM_DOMAIN, NULLIFIER_ALGORITHM, RECEIPT_DOMAIN, REGISTRATION_PROTOCOL,
    RegistrationCode, RegistrationKey, RegistrationKeys, SignedAgreement, SignedClaim,
    SignedReceipt,
};
use verified_protocol::{Instant, IssuerSignature, WireDigest};

use crate::trust::{ED25519, TrustError, decode, verifies};

pub mod audit;
pub mod log;

/// Why a registration was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {detail}")]
pub struct RegistrationRefusal {
    /// The protocol's code for the failed check. Stable.
    pub code: RegistrationCode,
    /// A description for people. Not stable; do not match on it.
    pub detail: String,
}

pub(crate) type Checked<T> = Result<T, RegistrationRefusal>;

pub(crate) fn refuse<T>(code: RegistrationCode, detail: impl Into<String>) -> Checked<T> {
    Err(RegistrationRefusal {
        code,
        detail: detail.into(),
    })
}

/// A key with its decoded material, or `None` for an algorithm this
/// verifier does not support.
pub(crate) type Decoded = (RegistrationKey, Option<VerifyingKey>);

/// The relying party's keys for registrations, ready to verify with.
///
/// Building one is the only way to hand keys to [`verify_registration`], so
/// unusable key material is found when the configuration is loaded.
#[derive(Clone, Debug)]
pub struct RegistrationTrust {
    pub(crate) parties: Vec<Decoded>,
    pub(crate) registries: Vec<Decoded>,
}

impl RegistrationTrust {
    /// Decodes the keys of a configuration.
    ///
    /// A key whose algorithm is not `Ed25519` is kept undecoded: a signature
    /// naming it is refused as `UNSUPPORTED_ALGORITHM`.
    ///
    /// # Errors
    ///
    /// Key material that cannot be used.
    pub fn new(keys: RegistrationKeys) -> Result<Self, TrustError> {
        let decoded = |keys: Vec<RegistrationKey>| {
            let mut list: Vec<Decoded> = Vec::with_capacity(keys.len());
            for key in keys {
                let material = (key.algorithm == ED25519)
                    .then(|| decode(&key.key_id, &key.public_key))
                    .transpose()?;
                // The same key under another spelling of its material would
                // be an alias: a second identifier for one signer.
                if let Some(material) = &material
                    && let Some((earlier, _)) =
                        list.iter().find(|(_, m)| m.as_ref() == Some(material))
                {
                    return Err(TrustError::DuplicateKey(earlier.key_id.clone(), key.key_id));
                }
                list.push((key, material));
            }
            Ok(list)
        };
        Ok(Self {
            parties: decoded(keys.parties)?,
            registries: decoded(keys.registries)?,
        })
    }

    /// Reads and decodes `{ "parties": [ … ], "registries": [ … ] }`.
    ///
    /// # Errors
    ///
    /// A configuration that is not well formed, or key material that cannot
    /// be used.
    pub fn from_value(keys: &Value) -> Result<Self, TrustError> {
        Self::new(RegistrationKeys::from_value(keys)?)
    }
}

/// What a verified registration states. See the module documentation for
/// what that establishes and what it does not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    /// The digest of the agreement the claim was made under.
    pub agreement: Sha256Digest,
    /// The claim's identifier.
    pub claim_id: String,
    /// The claim's digest, which the receipt names.
    pub claim: Sha256Digest,
    /// The receipt's digest, which the next entry of the log names.
    pub receipt: Sha256Digest,
    /// The party that made the claim.
    pub claimant: String,
    /// The party that must answer it.
    pub respondent: String,
    /// The registry that received it.
    pub registry: String,
    /// The receipt's position in the registry's log.
    pub sequence: i64,
    /// When the registry received the claim, as the receipt spells it.
    pub received_at: String,
    /// When the respondent must have answered, as the receipt spells it.
    pub respond_by: String,
}

pub(crate) fn canonical(text: &[u8], what: &str) -> Checked<Value> {
    parse_canonical(text, &Limits::DEFAULT)
        .or_else(|e| refuse(RegistrationCode::Malformed, format!("the {what}: {e}")))
}

pub(crate) fn is_hex_digest(digest: WireDigest<'_>) -> bool {
    digest.hex.parse::<Sha256Digest>().is_ok()
}

/// A signature and what it is over.
pub(crate) struct Signing<'a> {
    pub(crate) signature: IssuerSignature<'a>,
    pub(crate) domain: SigningDomain,
    pub(crate) object: &'a Value,
    pub(crate) what: &'a str,
}

/// One signature: the key is known, is Ed25519, belongs to `holder`, was
/// valid at `at`, and the signature verifies. In that order.
pub(crate) fn signed(
    keys: &[Decoded],
    holder: &str,
    other_holder: RegistrationCode,
    at: Instant,
    signing: &Signing<'_>,
) -> Checked<()> {
    let Signing {
        signature,
        domain,
        object,
        what,
    } = signing;
    let fail = |code, problem: &str| refuse(code, format!("{what}: {problem}"));
    let Some((key, material)) = keys.iter().find(|(key, _)| key.key_id == signature.key_id) else {
        return fail(
            RegistrationCode::UnknownKey,
            &format!("no trusted key {:?}", signature.key_id),
        );
    };
    let (ED25519, ED25519, Some(material)) = (key.algorithm.as_str(), signature.scheme, material)
    else {
        return fail(
            RegistrationCode::UnsupportedAlgorithm,
            "the key or the scheme is not Ed25519",
        );
    };
    if key.holder != holder {
        return fail(other_holder, "the key belongs to someone else");
    }
    if !key.valid_at(at) {
        return fail(
            RegistrationCode::KeyNotValid,
            "the key was not valid at the time that counts",
        );
    }
    if !verifies(material, &domain.signing_input(object), signature.encoded) {
        return fail(
            RegistrationCode::SignatureInvalid,
            "the signature does not verify",
        );
    }
    Ok(())
}

/// Step 3: every commitment is a SHA-256 digest, and the unit is an
/// HMAC-SHA-256 nullifier.
fn commitments(
    agreement: &SignedAgreement<'_>,
    claim: &SignedClaim<'_>,
    receipt: &SignedReceipt<'_>,
) -> Checked<()> {
    let are_commitments = [
        agreement.contract_digest,
        agreement.unit_key,
        claim.agreement,
        claim.inputs,
        receipt.claim,
    ]
    .into_iter()
    .chain(receipt.previous)
    .all(|d| d.algorithm == Sha256Digest::ALGORITHM && is_hex_digest(d));
    if are_commitments && claim.unit.algorithm == NULLIFIER_ALGORITHM && is_hex_digest(claim.unit) {
        Ok(())
    } else {
        refuse(
            RegistrationCode::MalformedCommitment,
            "a commitment is not a SHA-256 digest, or the unit is not an HMAC-SHA-256 nullifier",
        )
    }
}

/// Step 4: the agreement's terms are sound.
fn sound(agreement: &SignedAgreement<'_>) -> Checked<()> {
    let identity = &agreement.identity;
    let problem = if agreement.claimant == agreement.respondent {
        "the claimant and the respondent are the same party"
    } else if agreement.respond_within_seconds <= 0 {
        "the response window is not positive"
    } else if agreement.open_claim_limit <= 0 {
        "the open-claim limit is not positive"
    } else if agreement.registry.is_empty() {
        "the registry has no name"
    } else if agreement.contract_id.is_empty() || agreement.contract_version.is_empty() {
        "the contract has no identifier or no version"
    } else if agreement.operation.is_empty() {
        "the scope has no operation"
    } else if (1..identity.len()).any(|i| identity[..i].contains(&identity[i])) {
        "the scope names an identifying input twice"
    } else if agreement
        .valid_until
        .is_some_and(|until| until <= agreement.valid_from)
    {
        "the agreement ends before it starts"
    } else {
        return Ok(());
    };
    refuse(RegistrationCode::AgreementInvalid, problem)
}

/// Verifies a registration from the text of its three signed objects.
///
/// # Errors
///
/// The first of the protocol's checks that fails.
pub fn verify_registration(
    agreement: &[u8],
    claim: &[u8],
    receipt: &[u8],
    trust: &RegistrationTrust,
) -> Result<Registration, RegistrationRefusal> {
    use RegistrationCode as Code;

    // Step 1: each object is canonical text of the right structure.
    let (agreement, claim, receipt) = (
        canonical(agreement, "agreement")?,
        canonical(claim, "claim")?,
        canonical(receipt, "receipt")?,
    );
    let malformed = |shape: verified_protocol::ShapeError| RegistrationRefusal {
        code: Code::Malformed,
        detail: shape.to_string(),
    };
    let agreement = SignedAgreement::from_value(&agreement).map_err(malformed)?;
    let claim = SignedClaim::from_value(&claim).map_err(malformed)?;
    let receipt = SignedReceipt::from_value(&receipt).map_err(malformed)?;
    check(&agreement, &claim, &receipt, trust)
}

/// Steps 12 to 14: the receipt's times fit the agreement and the claim.
fn times(
    agreement: &SignedAgreement<'_>,
    claim: &SignedClaim<'_>,
    receipt: &SignedReceipt<'_>,
) -> Checked<()> {
    let received_at = receipt.received_at.at;

    // Step 12.
    if received_at < agreement.valid_from || agreement.valid_until.is_some_and(|u| received_at >= u)
    {
        return refuse(
            RegistrationCode::AgreementNotInForce,
            "the claim was received while the agreement was not in force",
        );
    }

    // Step 13.
    if claim.claimed_at > received_at {
        return refuse(
            RegistrationCode::ClaimedAfterReceipt,
            "the claim says it was made after the registry received it",
        );
    }

    // Step 14.
    if received_at.plus_seconds(agreement.respond_within_seconds) != Some(receipt.respond_by.at) {
        return refuse(
            RegistrationCode::DeadlineMismatch,
            "the deadline is not the receipt time plus the agreed response window",
        );
    }
    Ok(())
}

/// Steps 2 to 14, on objects of the right structure.
fn check(
    agreement: &SignedAgreement<'_>,
    claim: &SignedClaim<'_>,
    receipt: &SignedReceipt<'_>,
    trust: &RegistrationTrust,
) -> Checked<Registration> {
    use RegistrationCode as Code;

    // Step 2.
    if [agreement.protocol, claim.protocol, receipt.protocol] != [REGISTRATION_PROTOCOL; 3] {
        return refuse(
            Code::UnsupportedProtocol,
            "an object is not of claim registration v1",
        );
    }

    // Step 3.
    commitments(agreement, claim, receipt)?;

    // Step 4.
    sound(agreement)?;

    // Step 5: both parties signed the agreement.
    for (signature, party, what) in [
        (
            agreement.claimant_signature,
            agreement.claimant,
            "the claimant's signature of the agreement",
        ),
        (
            agreement.respondent_signature,
            agreement.respondent,
            "the respondent's signature of the agreement",
        ),
    ] {
        let signing = Signing {
            signature,
            domain: AGREEMENT_DOMAIN,
            object: agreement.agreement,
            what,
        };
        signed(
            &trust.parties,
            party,
            Code::PartyMismatch,
            agreement.valid_from,
            &signing,
        )?;
    }

    // Step 6.
    let agreement_digest = agreement.agreement.digest();
    if !claim.agreement.states(&agreement_digest) {
        return refuse(
            Code::AgreementMismatch,
            "the claim is made under another agreement",
        );
    }

    // Step 7.
    let signing = Signing {
        signature: claim.signature,
        domain: CLAIM_DOMAIN,
        object: claim.claim,
        what: "the claim's signature",
    };
    signed(
        &trust.parties,
        agreement.claimant,
        Code::PartyMismatch,
        claim.claimed_at,
        &signing,
    )?;

    // Step 8.
    let claim_digest = claim.claim.digest();
    if !receipt.claim.states(&claim_digest) {
        return refuse(Code::ClaimMismatch, "the receipt is for another claim");
    }

    // Step 9.
    if receipt.registry != agreement.registry {
        return refuse(
            Code::RegistryMismatch,
            "the receipt is not from the registry the agreement names",
        );
    }

    // Step 10.
    if receipt.sequence < 0 || receipt.previous.is_none() != (receipt.sequence == 0) {
        return refuse(
            Code::ChainInvalid,
            "only the first entry of a log, entry 0, has no predecessor",
        );
    }

    // Step 11.
    let received_at = receipt.received_at.at;
    let signing = Signing {
        signature: receipt.signature,
        domain: RECEIPT_DOMAIN,
        object: receipt.receipt,
        what: "the receipt's signature",
    };
    signed(
        &trust.registries,
        agreement.registry,
        Code::RegistryMismatch,
        received_at,
        &signing,
    )?;

    // Steps 12 to 14.
    times(agreement, claim, receipt)?;

    Ok(Registration {
        agreement: agreement_digest,
        claim_id: claim.id.to_owned(),
        claim: claim_digest,
        receipt: receipt.receipt.digest(),
        claimant: agreement.claimant.to_owned(),
        respondent: agreement.respondent.to_owned(),
        registry: agreement.registry.to_owned(),
        sequence: receipt.sequence,
        received_at: receipt.received_at.text.to_owned(),
        respond_by: receipt.respond_by.text.to_owned(),
    })
}
