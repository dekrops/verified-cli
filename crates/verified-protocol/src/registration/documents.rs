// SPDX-License-Identifier: Apache-2.0

//! The documents a registry's log names: responses, notices, dispute terms,
//! disputes and resolutions. Structure only, like the rest of this module.

use verified_canonical::{SigningDomain, Value};

use super::{StatedTime, domain, time};
use crate::container::{IssuerSignature, ShapeError, ShapeProblem, WireDigest};
use crate::shape::{self, At, Shape};
use crate::statement::signature;

/// The domain a respondent signs a response under.
pub const RESPONSE_DOMAIN: SigningDomain = domain("verified:claim-response:v1\n");
/// The domain a claimant signs a notice under.
pub const NOTICE_DOMAIN: SigningDomain = domain("verified:claim-notice:v1\n");
/// The domain both parties sign dispute terms under.
pub const DISPUTE_TERMS_DOMAIN: SigningDomain = domain("verified:claim-dispute-terms:v1\n");
/// The domain a party signs a dispute under.
pub const DISPUTE_DOMAIN: SigningDomain = domain("verified:claim-dispute:v1\n");
/// The domain a resolution is signed under.
pub const RESOLUTION_DOMAIN: SigningDomain = domain("verified:claim-resolution:v1\n");

/// `{ <name>: { … }, signature }`: the object, where it is, and its one
/// signature.
fn signed_once<'a>(
    signed: &'a Value,
    name: &'static str,
    outer: &'static [&'static str],
) -> Shape<(&'a Value, IssuerSignature<'a>)> {
    let root = At::root(name);
    let o = shape::object(signed, &root, outer)?;
    let signature = signature(shape::get(o, "signature"), &root.member("signature"))?;
    Ok((shape::get(o, name), signature))
}

/// `{ "<Case>": {} }` for a unit case, or `{ "<Case>": { <member>: … } }`
/// for a case with one member, whose value is returned.
fn case<'a>(
    value: &'a Value,
    at: &At<'_>,
    cases: &'static [&'static str],
    members: &[Option<&'static str>],
) -> Shape<(&'a str, Option<&'a Value>)> {
    let (name, content) = shape::variant(value, at)?;
    let Some(index) = cases.iter().position(|case| *case == name) else {
        return at.fail(ShapeProblem::Case(cases));
    };
    let at = at.member(name);
    let Some(member) = members[index] else {
        shape::object(content, &at, &[])?;
        return Ok((name, None));
    };
    match content.as_object().filter(|o| o.has_exactly(&[member])) {
        Some(o) => Ok((name, o.get(member))),
        None => at.fail(ShapeProblem::Not("the case's one member")),
    }
}

/// How a respondent answered a claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer<'a> {
    /// Evidence is offered: the stated commitment of the package holding it.
    Evidence(WireDigest<'a>),
    /// The claim is not work under the agreement it names.
    NotUnderAgreement,
    /// The claim's unit is not the nullifier of its inputs.
    WrongUnit,
    /// The same work was already claimed, by the claim with this digest.
    Duplicate(WireDigest<'a>),
    /// Another reason, stated.
    Other(&'a str),
}

/// A response with its respondent's signature, of the right structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedResponse<'a> {
    /// The `response` member, whole.
    pub response: &'a Value,
    /// The stated protocol identifier.
    pub protocol: &'a str,
    /// The stated digest of the claim answered.
    pub claim: WireDigest<'a>,
    /// The answer.
    pub answer: Answer<'a>,
    /// When the respondent says it responded. Not authenticated.
    pub responded_at: StatedTime<'a>,
    /// The signature, as carried.
    pub signature: IssuerSignature<'a>,
}

impl<'a> SignedResponse<'a> {
    /// Reads `{ response, signature }`, refusing any missing, extra or
    /// mistyped member at any depth.
    pub fn from_value(signed: &'a Value) -> Result<Self, ShapeError> {
        let (response, signature) = signed_once(signed, "response", &["response", "signature"])?;
        let root = At::root("response");
        let at = root.member("response");
        let o = shape::object(
            response,
            &at,
            &["answer", "claim", "protocol", "respondedAt"],
        )?;
        let member = |name| shape::get(o, name);
        let answer_at = at.member("answer");
        let (name, content) = case(
            member("answer"),
            &answer_at,
            &["Evidence", "Refused"],
            &[Some("package"), Some("reason")],
        )?;
        let content = content.unwrap_or(&Value::Null);
        let answer = if name == "Evidence" {
            Answer::Evidence(shape::digest(content, &answer_at.member("package"))?)
        } else {
            let reason_at = answer_at.member("reason");
            let (reason, content) = case(
                content,
                &reason_at,
                &["NotUnderAgreement", "WrongUnit", "Duplicate", "Other"],
                &[None, None, Some("of"), Some("text")],
            )?;
            let content = content.unwrap_or(&Value::Null);
            match reason {
                "NotUnderAgreement" => Answer::NotUnderAgreement,
                "WrongUnit" => Answer::WrongUnit,
                "Duplicate" => Answer::Duplicate(shape::digest(content, &reason_at.member("of"))?),
                _ => Answer::Other(shape::text(content, &reason_at.member("text"))?),
            }
        };
        Ok(Self {
            response,
            protocol: shape::text(member("protocol"), &at.member("protocol"))?,
            claim: shape::digest(member("claim"), &at.member("claim"))?,
            answer,
            responded_at: time(member("respondedAt"), &at.member("respondedAt"))?,
            signature,
        })
    }
}

/// A notice with its claimant's signature, of the right structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedNotice<'a> {
    /// The `notice` member, whole.
    pub notice: &'a Value,
    /// The stated protocol identifier.
    pub protocol: &'a str,
    /// The stated digest of the claim the notice is about.
    pub claim: WireDigest<'a>,
    /// For a supersession, the stated digest of the replacing claim; `None`
    /// for a withdrawal.
    pub superseded_by: Option<WireDigest<'a>>,
    /// When the claimant says it issued the notice. Not authenticated.
    pub issued_at: StatedTime<'a>,
    /// The signature, as carried.
    pub signature: IssuerSignature<'a>,
}

impl<'a> SignedNotice<'a> {
    /// Reads `{ notice, signature }`, refusing any missing, extra or
    /// mistyped member at any depth.
    pub fn from_value(signed: &'a Value) -> Result<Self, ShapeError> {
        let (notice, signature) = signed_once(signed, "notice", &["notice", "signature"])?;
        let root = At::root("notice");
        let at = root.member("notice");
        let o = shape::object(notice, &at, &["action", "claim", "issuedAt", "protocol"])?;
        let member = |name| shape::get(o, name);
        let action_at = at.member("action");
        let (_, by) = case(
            member("action"),
            &action_at,
            &["Withdraw", "Supersede"],
            &[None, Some("by")],
        )?;
        Ok(Self {
            notice,
            protocol: shape::text(member("protocol"), &at.member("protocol"))?,
            claim: shape::digest(member("claim"), &at.member("claim"))?,
            superseded_by: by
                .map(|by| shape::digest(by, &action_at.member("by")))
                .transpose()?,
            issued_at: time(member("issuedAt"), &at.member("issuedAt"))?,
            signature,
        })
    }
}

/// Dispute terms with both parties' signatures, of the right structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedTerms<'a> {
    /// The `terms` member, whole.
    pub terms: &'a Value,
    /// The stated protocol identifier.
    pub protocol: &'a str,
    /// The stated digest of the agreement the terms belong to.
    pub agreement: WireDigest<'a>,
    /// How long after a claim is closed a dispute of it may be recorded.
    pub dispute_within_seconds: i64,
    /// The party who resolves disputes (a UUID), if any.
    pub resolver: Option<&'a str>,
    /// The claimant's signature, as carried.
    pub claimant_signature: IssuerSignature<'a>,
    /// The respondent's signature, as carried.
    pub respondent_signature: IssuerSignature<'a>,
}

/// `{ claimant, respondent }`, both signatures.
fn both<'a>(value: &'a Value, at: &At<'_>) -> Shape<(IssuerSignature<'a>, IssuerSignature<'a>)> {
    let o = shape::object(value, at, &["claimant", "respondent"])?;
    Ok((
        signature(shape::get(o, "claimant"), &at.member("claimant"))?,
        signature(shape::get(o, "respondent"), &at.member("respondent"))?,
    ))
}

impl<'a> SignedTerms<'a> {
    /// Reads `{ terms, signatures: { claimant, respondent } }`, refusing any
    /// missing, extra or mistyped member at any depth.
    pub fn from_value(signed: &'a Value) -> Result<Self, ShapeError> {
        let root = At::root("terms");
        let outer = shape::object(signed, &root, &["signatures", "terms"])?;
        let (claimant_signature, respondent_signature) =
            both(shape::get(outer, "signatures"), &root.member("signatures"))?;
        let terms = shape::get(outer, "terms");
        let at = root.member("terms");
        let o = shape::object(
            terms,
            &at,
            &["agreement", "disputeWithinSeconds", "protocol", "resolver"],
        )?;
        let member = |name| shape::get(o, name);
        Ok(Self {
            terms,
            protocol: shape::text(member("protocol"), &at.member("protocol"))?,
            agreement: shape::digest(member("agreement"), &at.member("agreement"))?,
            dispute_within_seconds: shape::safe_integer(
                member("disputeWithinSeconds"),
                &at.member("disputeWithinSeconds"),
            )?,
            resolver: shape::nullable(member("resolver"), &at.member("resolver"), shape::uuid)?,
            claimant_signature,
            respondent_signature,
        })
    }
}

/// A dispute with the signature of the party that opens it, of the right
/// structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedDispute<'a> {
    /// The `dispute` member, whole.
    pub dispute: &'a Value,
    /// The stated protocol identifier.
    pub protocol: &'a str,
    /// The stated digest of the claim disputed.
    pub claim: WireDigest<'a>,
    /// The stated digest of the terms the dispute is opened under.
    pub terms: WireDigest<'a>,
    /// The party that opens it (a UUID).
    pub by: &'a str,
    /// For the ground `Other`, its text.
    pub other_ground: Option<&'a str>,
    /// When the party says it opened the dispute. Not authenticated.
    pub opened_at: StatedTime<'a>,
    /// The signature, as carried.
    pub signature: IssuerSignature<'a>,
}

impl<'a> SignedDispute<'a> {
    /// Reads `{ dispute, signature }`, refusing any missing, extra or
    /// mistyped member at any depth.
    pub fn from_value(signed: &'a Value) -> Result<Self, ShapeError> {
        let (dispute, signature) = signed_once(signed, "dispute", &["dispute", "signature"])?;
        let root = At::root("dispute");
        let at = root.member("dispute");
        let o = shape::object(
            dispute,
            &at,
            &["by", "claim", "ground", "openedAt", "protocol", "terms"],
        )?;
        let member = |name| shape::get(o, name);
        let ground_at = at.member("ground");
        let (_, text) = case(
            member("ground"),
            &ground_at,
            &[
                "RefusalUnfounded",
                "EvidenceIncomplete",
                "DecisionContested",
                "Other",
            ],
            &[None, None, None, Some("text")],
        )?;
        Ok(Self {
            dispute,
            protocol: shape::text(member("protocol"), &at.member("protocol"))?,
            claim: shape::digest(member("claim"), &at.member("claim"))?,
            terms: shape::digest(member("terms"), &at.member("terms"))?,
            by: shape::uuid(member("by"), &at.member("by"))?,
            other_ground: text
                .map(|text| shape::text(text, &ground_at.member("text")))
                .transpose()?,
            opened_at: time(member("openedAt"), &at.member("openedAt"))?,
            signature,
        })
    }
}

/// Who signed a resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolutionSignatures<'a> {
    /// The resolver the dispute terms name.
    Resolver(IssuerSignature<'a>),
    /// Both parties together.
    Settlement {
        /// The claimant's signature.
        claimant: IssuerSignature<'a>,
        /// The respondent's signature.
        respondent: IssuerSignature<'a>,
    },
}

/// A resolution with its signatures, of the right structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedResolution<'a> {
    /// The `resolution` member, whole.
    pub resolution: &'a Value,
    /// The stated protocol identifier.
    pub protocol: &'a str,
    /// The stated digest of the dispute resolved.
    pub dispute: WireDigest<'a>,
    /// Whether the disputing party's position stands.
    pub upheld: bool,
    /// When the resolution is said to have been made. Not authenticated.
    pub resolved_at: StatedTime<'a>,
    /// The signatures, as carried.
    pub signatures: ResolutionSignatures<'a>,
}

impl<'a> SignedResolution<'a> {
    /// Reads `{ resolution, signatures }`, refusing any missing, extra or
    /// mistyped member at any depth.
    pub fn from_value(signed: &'a Value) -> Result<Self, ShapeError> {
        let root = At::root("resolution");
        let outer = shape::object(signed, &root, &["resolution", "signatures"])?;
        let signatures_at = root.member("signatures");
        let (kind, content) = shape::variant(shape::get(outer, "signatures"), &signatures_at)?;
        let signatures = match kind {
            "Resolver" => {
                let at = signatures_at.member("Resolver");
                let o = shape::object(content, &at, &["signature"])?;
                ResolutionSignatures::Resolver(signature(
                    shape::get(o, "signature"),
                    &at.member("signature"),
                )?)
            }
            "Settlement" => {
                let (claimant, respondent) = both(content, &signatures_at.member("Settlement"))?;
                ResolutionSignatures::Settlement {
                    claimant,
                    respondent,
                }
            }
            _ => return signatures_at.fail(ShapeProblem::Case(&["Resolver", "Settlement"])),
        };
        let resolution = shape::get(outer, "resolution");
        let at = root.member("resolution");
        let o = shape::object(
            resolution,
            &at,
            &["dispute", "outcome", "protocol", "resolvedAt"],
        )?;
        let member = |name| shape::get(o, name);
        let outcome = shape::unit(
            member("outcome"),
            &at.member("outcome"),
            &["Upheld", "Rejected"],
        )?;
        Ok(Self {
            resolution,
            protocol: shape::text(member("protocol"), &at.member("protocol"))?,
            dispute: shape::digest(member("dispute"), &at.member("dispute"))?,
            upheld: outcome == "Upheld",
            resolved_at: time(member("resolvedAt"), &at.member("resolvedAt"))?,
            signatures,
        })
    }
}
