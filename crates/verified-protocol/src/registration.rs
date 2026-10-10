// SPDX-License-Identifier: Apache-2.0

//! Claim registration v1 (`verified-claim-registration-v1`, a **draft**):
//! the objects of a registration and the keys a relying party trusts for
//! them.
//!
//! A claim is registered, before any evidence is asked for, at a registry
//! two parties agreed on. Three signed objects make a registration: the
//! parties' *agreement*, the claimant's *claim* under it, and the registry's
//! *receipt* for that claim.
//!
//! Everything here is structure. Reading one of these objects checks nothing
//! about its protocol identifier, commitments, keys or signatures.

use std::fmt;

use verified_canonical::{SigningDomain, Value};

use crate::container::{IssuerSignature, ShapeError, ShapeProblem, WireDigest};
use crate::registry::RegistryError;
use crate::shape::{self, At, Shape};
use crate::statement::signature;
use crate::time::Instant;

/// The protocol identifier every object of a registration must carry.
pub const REGISTRATION_PROTOCOL: &str = "verified-claim-registration-v1";

const fn domain(prefix: &'static str) -> SigningDomain {
    match SigningDomain::new(prefix) {
        Ok(domain) => domain,
        Err(_) => panic!("a registration signing domain is one line"),
    }
}

/// The domain both parties sign an agreement under.
pub const AGREEMENT_DOMAIN: SigningDomain = domain("verified:claim-agreement:v1\n");
/// The domain a claimant signs a claim under.
pub const CLAIM_DOMAIN: SigningDomain = domain("verified:claim-commitment:v1\n");
/// The domain a registry signs a receipt under.
pub const RECEIPT_DOMAIN: SigningDomain = domain("verified:claim-receipt:v1\n");

/// The algorithm name of a work unit's nullifier.
pub const NULLIFIER_ALGORITHM: &str = "hmac-sha-256";

/// The code of a refused registration. Stable.
///
/// Later parts of the protocol (log segments, audits, unit checks) add
/// codes, so a match on this type needs a wildcard arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RegistrationCode {
    /// An object is not well formed, its text is not canonical, or an
    /// integer or a year is out of range.
    Malformed,
    /// An object names another protocol.
    UnsupportedProtocol,
    /// A commitment is not a SHA-256 digest, or the unit is not an
    /// HMAC-SHA-256 nullifier.
    MalformedCommitment,
    /// The agreement's terms are not sound.
    AgreementInvalid,
    /// A signature names a key the relying party does not trust.
    UnknownKey,
    /// A key or a signature scheme is not Ed25519.
    UnsupportedAlgorithm,
    /// A key does not belong to the party that had to sign.
    PartyMismatch,
    /// A key was not valid at the time that counts for its signature.
    KeyNotValid,
    /// A signature does not verify.
    SignatureInvalid,
    /// The claim names another agreement.
    AgreementMismatch,
    /// The receipt names another claim.
    ClaimMismatch,
    /// The receipt is not from the agreement's registry, or is signed by
    /// another registry's key.
    RegistryMismatch,
    /// The receipt's sequence number and predecessor do not fit together.
    ChainInvalid,
    /// The claim was received outside the agreement's validity.
    AgreementNotInForce,
    /// The claim says it was made after the registry received it.
    ClaimedAfterReceipt,
    /// The deadline is not the receipt time plus the agreed window.
    DeadlineMismatch,
}

impl RegistrationCode {
    /// The protocol's spelling of the code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "MALFORMED",
            Self::UnsupportedProtocol => "UNSUPPORTED_PROTOCOL",
            Self::MalformedCommitment => "MALFORMED_COMMITMENT",
            Self::AgreementInvalid => "AGREEMENT_INVALID",
            Self::UnknownKey => "UNKNOWN_KEY",
            Self::UnsupportedAlgorithm => "UNSUPPORTED_ALGORITHM",
            Self::PartyMismatch => "PARTY_MISMATCH",
            Self::KeyNotValid => "KEY_NOT_VALID",
            Self::SignatureInvalid => "SIGNATURE_INVALID",
            Self::AgreementMismatch => "AGREEMENT_MISMATCH",
            Self::ClaimMismatch => "CLAIM_MISMATCH",
            Self::RegistryMismatch => "REGISTRY_MISMATCH",
            Self::ChainInvalid => "CHAIN_INVALID",
            Self::AgreementNotInForce => "AGREEMENT_NOT_IN_FORCE",
            Self::ClaimedAfterReceipt => "CLAIMED_AFTER_RECEIPT",
            Self::DeadlineMismatch => "DEADLINE_MISMATCH",
        }
    }
}

impl fmt::Display for RegistrationCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A time as an object states it: its text, and the instant that denotes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatedTime<'a> {
    /// The canonical spelling, as carried.
    pub text: &'a str,
    /// The instant.
    pub at: Instant,
}

fn time<'a>(value: &'a Value, at: &At<'_>) -> Shape<StatedTime<'a>> {
    Ok(StatedTime {
        at: shape::instant(value, at)?,
        text: shape::wrapped(value, at)?,
    })
}

/// An agreement with both parties' signatures, of the right structure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedAgreement<'a> {
    /// The `agreement` member, whole: both signatures are over its
    /// canonical text, and a claim names its digest.
    pub agreement: &'a Value,
    /// The stated protocol identifier.
    pub protocol: &'a str,
    /// The agreement's identifier (a UUID).
    pub id: &'a str,
    /// The respondent's tenant.
    pub tenant: &'a str,
    /// The contract's identifier.
    pub contract_id: &'a str,
    /// The contract's version.
    pub contract_version: &'a str,
    /// The stated digest of the compiled contract.
    pub contract_digest: WireDigest<'a>,
    /// The name of the line of work whose units are counted.
    pub scope: &'a str,
    /// The operation that is one unit of that work.
    pub operation: &'a str,
    /// The claim inputs that identify a unit, in order.
    pub identity: Vec<&'a str>,
    /// The stated commitment to the parties' unit key.
    pub unit_key: WireDigest<'a>,
    /// The party that claims (a UUID).
    pub claimant: &'a str,
    /// The party obliged to answer (a UUID).
    pub respondent: &'a str,
    /// The registry that receives claims, by name.
    pub registry: &'a str,
    /// How long the respondent has to answer, from the registry's receipt.
    pub respond_within_seconds: i64,
    /// How many claims may be open at once.
    pub open_claim_limit: i64,
    /// The first instant claims may be received at.
    pub valid_from: Instant,
    /// The first instant they may no longer be, if any.
    pub valid_until: Option<Instant>,
    /// The claimant's signature, as carried.
    pub claimant_signature: IssuerSignature<'a>,
    /// The respondent's signature, as carried.
    pub respondent_signature: IssuerSignature<'a>,
}

impl<'a> SignedAgreement<'a> {
    /// Reads `{ agreement, signatures: { claimant, respondent } }`, refusing
    /// any missing, extra or mistyped member at any depth.
    pub fn from_value(signed: &'a Value) -> Result<Self, ShapeError> {
        let root = At::root("agreement");
        let outer = shape::object(signed, &root, &["agreement", "signatures"])?;
        let signatures_at = root.member("signatures");
        let signatures = shape::object(
            shape::get(outer, "signatures"),
            &signatures_at,
            &["claimant", "respondent"],
        )?;
        let signed_by =
            |party| signature(shape::get(signatures, party), &signatures_at.member(party));

        let agreement = shape::get(outer, "agreement");
        let at = root.member("agreement");
        let o = shape::object(
            agreement,
            &at,
            &[
                "claimant",
                "contract",
                "id",
                "openClaimLimit",
                "protocol",
                "registry",
                "respondWithinSeconds",
                "respondent",
                "scope",
                "tenant",
                "unitKey",
                "validFrom",
                "validUntil",
            ],
        )?;
        let member = |name| shape::get(o, name);

        let contract_at = at.member("contract");
        let contract = shape::object(
            member("contract"),
            &contract_at,
            &["digest", "id", "version"],
        )?;
        let scope_at = at.member("scope");
        let scope = shape::object(
            member("scope"),
            &scope_at,
            &["identity", "operation", "scope"],
        )?;

        Ok(Self {
            agreement,
            protocol: shape::text(member("protocol"), &at.member("protocol"))?,
            id: shape::uuid(member("id"), &at.member("id"))?,
            tenant: shape::wrapped(member("tenant"), &at.member("tenant"))?,
            contract_id: shape::text(shape::get(contract, "id"), &contract_at.member("id"))?,
            contract_version: shape::text(
                shape::get(contract, "version"),
                &contract_at.member("version"),
            )?,
            contract_digest: shape::digest(
                shape::get(contract, "digest"),
                &contract_at.member("digest"),
            )?,
            scope: shape::text(shape::get(scope, "scope"), &scope_at.member("scope"))?,
            operation: shape::text(
                shape::get(scope, "operation"),
                &scope_at.member("operation"),
            )?,
            identity: shape::each(
                shape::get(scope, "identity"),
                &scope_at.member("identity"),
                shape::text,
            )?,
            unit_key: shape::digest(member("unitKey"), &at.member("unitKey"))?,
            claimant: shape::uuid(member("claimant"), &at.member("claimant"))?,
            respondent: shape::uuid(member("respondent"), &at.member("respondent"))?,
            registry: shape::text(member("registry"), &at.member("registry"))?,
            respond_within_seconds: shape::safe_integer(
                member("respondWithinSeconds"),
                &at.member("respondWithinSeconds"),
            )?,
            open_claim_limit: shape::safe_integer(
                member("openClaimLimit"),
                &at.member("openClaimLimit"),
            )?,
            valid_from: shape::instant(member("validFrom"), &at.member("validFrom"))?,
            valid_until: shape::nullable(
                member("validUntil"),
                &at.member("validUntil"),
                shape::instant,
            )?,
            claimant_signature: signed_by("claimant")?,
            respondent_signature: signed_by("respondent")?,
        })
    }
}

/// A claim with its claimant's signature, of the right structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedClaim<'a> {
    /// The `claim` member, whole: the signature is over its canonical text,
    /// and a receipt names its digest.
    pub claim: &'a Value,
    /// The stated protocol identifier.
    pub protocol: &'a str,
    /// The claim's identifier (a UUID).
    pub id: &'a str,
    /// The stated digest of the agreement the claim is made under.
    pub agreement: WireDigest<'a>,
    /// The stated digest of the claim's input values.
    pub inputs: WireDigest<'a>,
    /// The stated nullifier of the work unit.
    pub unit: WireDigest<'a>,
    /// When the claimant says it made the claim. Not authenticated.
    pub claimed_at: Instant,
    /// The signature, as carried.
    pub signature: IssuerSignature<'a>,
}

impl<'a> SignedClaim<'a> {
    /// Reads `{ claim, signature }`, refusing any missing, extra or mistyped
    /// member at any depth.
    pub fn from_value(signed: &'a Value) -> Result<Self, ShapeError> {
        let root = At::root("claim");
        let outer = shape::object(signed, &root, &["claim", "signature"])?;
        let claim = shape::get(outer, "claim");
        let at = root.member("claim");
        let o = shape::object(
            claim,
            &at,
            &["agreement", "claimedAt", "id", "inputs", "protocol", "unit"],
        )?;
        let member = |name| shape::get(o, name);
        Ok(Self {
            claim,
            protocol: shape::text(member("protocol"), &at.member("protocol"))?,
            id: shape::uuid(member("id"), &at.member("id"))?,
            agreement: shape::digest(member("agreement"), &at.member("agreement"))?,
            inputs: shape::digest(member("inputs"), &at.member("inputs"))?,
            unit: shape::digest(member("unit"), &at.member("unit"))?,
            claimed_at: shape::instant(member("claimedAt"), &at.member("claimedAt"))?,
            signature: signature(shape::get(outer, "signature"), &root.member("signature"))?,
        })
    }
}

/// A receipt with its registry's signature, of the right structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedReceipt<'a> {
    /// The `receipt` member, whole: the signature is over its canonical
    /// text, and the next entry of the log names its digest.
    pub receipt: &'a Value,
    /// The stated protocol identifier.
    pub protocol: &'a str,
    /// The registry's name.
    pub registry: &'a str,
    /// The entry's position in the registry's log.
    pub sequence: i64,
    /// The stated digest of the previous entry, if one is stated.
    pub previous: Option<WireDigest<'a>>,
    /// The stated digest of the claim received.
    pub claim: WireDigest<'a>,
    /// When the registry received the claim, by its clock.
    pub received_at: StatedTime<'a>,
    /// When the respondent must have answered.
    pub respond_by: StatedTime<'a>,
    /// The signature, as carried.
    pub signature: IssuerSignature<'a>,
}

impl<'a> SignedReceipt<'a> {
    /// Reads `{ receipt, signature }`, refusing any missing, extra or
    /// mistyped member at any depth.
    pub fn from_value(signed: &'a Value) -> Result<Self, ShapeError> {
        let root = At::root("receipt");
        let outer = shape::object(signed, &root, &["receipt", "signature"])?;
        let receipt = shape::get(outer, "receipt");
        let at = root.member("receipt");
        let o = shape::object(
            receipt,
            &at,
            &[
                "claim",
                "previous",
                "protocol",
                "receivedAt",
                "registry",
                "respondBy",
                "sequence",
            ],
        )?;
        let member = |name| shape::get(o, name);
        Ok(Self {
            receipt,
            protocol: shape::text(member("protocol"), &at.member("protocol"))?,
            registry: shape::text(member("registry"), &at.member("registry"))?,
            sequence: shape::safe_integer(member("sequence"), &at.member("sequence"))?,
            previous: shape::nullable(member("previous"), &at.member("previous"), shape::digest)?,
            claim: shape::digest(member("claim"), &at.member("claim"))?,
            received_at: time(member("receivedAt"), &at.member("receivedAt"))?,
            respond_by: time(member("respondBy"), &at.member("respondBy"))?,
            signature: signature(shape::get(outer, "signature"), &root.member("signature"))?,
        })
    }
}

/// A public key the relying party trusts for one party or one registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationKey {
    /// An opaque identifier naming this record.
    pub key_id: String,
    /// The key's algorithm, as stated.
    pub algorithm: String,
    /// The key material, as stated: base64 of a DER `SubjectPublicKeyInfo`.
    pub public_key: String,
    /// Whom the key belongs to: a party's UUID, or a registry's name.
    pub holder: String,
    /// The first instant the key is valid at.
    pub valid_from: Instant,
    /// The first instant it is no longer valid at, if any.
    pub valid_until: Option<Instant>,
    /// When the key was revoked, if it was.
    pub revoked_at: Option<Instant>,
}

impl RegistrationKey {
    /// Whether the key was valid at `at`.
    #[must_use]
    pub fn valid_at(&self, at: Instant) -> bool {
        self.valid_from <= at
            && self.valid_until.is_none_or(|until| at < until)
            && self.revoked_at.is_none_or(|revoked| at < revoked)
    }
}

/// The keys a relying party trusts for registrations: its own
/// configuration, never data received with a claim.
///
/// Trusting a registry's key is the relying party's decision that this
/// registry keeps honest time and order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationKeys {
    /// Keys of parties to agreements.
    pub parties: Vec<RegistrationKey>,
    /// Keys of registries.
    pub registries: Vec<RegistrationKey>,
}

impl RegistrationKeys {
    /// Reads `{ "parties": [ … ], "registries": [ … ] }`.
    ///
    /// Every member must be one the configuration defines. `validUntil` and
    /// `revokedAt` may be `null` or absent. A key identifier or a public key
    /// occurs at most once among the keys of parties, and at most once
    /// among the keys of registries.
    pub fn from_value(keys: &Value) -> Result<Self, RegistryError> {
        let at = At::root("trust");
        let root = shape::object(keys, &at, &["parties", "registries"])?;
        let list = |name: &'static str, holder: &'static str, uuid: bool| {
            let keys = shape::each(shape::get(root, name), &at.member(name), |key, at| {
                read_key(key, at, holder, uuid)
            })?;
            for (i, key) in keys.iter().enumerate() {
                for earlier in &keys[..i] {
                    if earlier.key_id == key.key_id {
                        return Err(RegistryError::DuplicateKeyId(key.key_id.clone()));
                    }
                    if earlier.public_key == key.public_key {
                        return Err(RegistryError::DuplicatePublicKey(
                            earlier.key_id.clone(),
                            key.key_id.clone(),
                        ));
                    }
                }
            }
            Ok(keys)
        };
        Ok(Self {
            parties: list("parties", "party", true)?,
            registries: list("registries", "registry", false)?,
        })
    }
}

const KEY_MEMBERS: &[&str] = &[
    "algorithm",
    "keyId",
    "party or registry",
    "publicKey",
    "revokedAt",
    "validFrom",
    "validUntil",
];

fn read_key(
    value: &Value,
    at: &At<'_>,
    holder: &'static str,
    uuid: bool,
) -> Shape<RegistrationKey> {
    let Some(o) = value.as_object() else {
        return at.fail(ShapeProblem::NotAnObject);
    };
    let required = ["algorithm", "keyId", holder, "publicKey", "validFrom"];
    let known =
        |name: &str| required.contains(&name) || ["revokedAt", "validUntil"].contains(&name);
    if !o.keys().all(known) || !required.iter().all(|name| o.get(name).is_some()) {
        return at.fail(ShapeProblem::Members(KEY_MEMBERS));
    }
    let member = |name| shape::get(o, name);
    let text = |name| shape::text(member(name), &at.member(name)).map(str::to_owned);
    let optional_time = |name| shape::nullable(member(name), &at.member(name), shape::instant);
    let holder_at = at.member(holder);
    Ok(RegistrationKey {
        key_id: text("keyId")?,
        algorithm: text("algorithm")?,
        public_key: text("publicKey")?,
        holder: if uuid {
            shape::uuid(member(holder), &holder_at)?
        } else {
            shape::text(member(holder), &holder_at)?
        }
        .to_owned(),
        valid_from: shape::instant(member("validFrom"), &at.member("validFrom"))?,
        valid_until: optional_time("validUntil")?,
        revoked_at: optional_time("revokedAt")?,
    })
}
