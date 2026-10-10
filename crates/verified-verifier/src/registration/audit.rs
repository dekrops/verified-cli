// SPDX-License-Identifier: Apache-2.0

//! The audit of a registry's whole log: every registered claim's state, and
//! whether the registry kept its two rules.
//!
//! An audit reads the log from its first entry, together with the documents
//! the log names: agreements, claims, responses, notices, dispute terms,
//! disputes and resolutions. A document is found by the digest the log
//! names; documents the log does not name are ignored.
//!
//! # What an audit establishes
//!
//! The log, up to its last entry, is a consistent history. Every claim was
//! registered under an agreement both parties signed and closed at most
//! once: by the respondent in time, by expiry after the deadline, or by the
//! claimant. No claim was registered for a unit another claim held, or
//! beyond its agreement's limit on open claims.
//!
//! # What it does not establish
//!
//! - **Anything about the work.** A state is the log's state, not a
//!   verification result. `ANSWERED` means evidence was offered, not that it
//!   supports the claim; that is decided by verifying the package.
//! - **That the log is complete.** A registry can withhold its latest
//!   entries, and an audit of what it shows still passes.
//! - **That a unit belongs to a claim's inputs.** Units are compared as the
//!   claims state them; only holders of the unit key can check one.
//!
//! A claim with an open dispute is not ready to be acted on, whatever its
//! state.

use std::collections::BTreeMap;

use verified_canonical::{Limits, Sha256Digest, Value, parse};
use verified_protocol::registration::{
    Answer, DISPUTE_DOMAIN, DISPUTE_TERMS_DOMAIN, EntryKind, LogEntry, NOTICE_DOMAIN,
    REGISTRATION_PROTOCOL, RESOLUTION_DOMAIN, RESPONSE_DOMAIN, RegistrationCode as Code,
    ResolutionSignatures, SignedAgreement, SignedClaim, SignedDispute, SignedNotice,
    SignedResolution, SignedResponse, SignedTerms,
};
use verified_protocol::{Instant, IssuerSignature, ShapeError, WireDigest};

use super::log::check_log;
use super::{
    Checked, RegistrationRefusal, RegistrationTrust, Signing, canonical, is_hex_digest, refuse,
    signed, verify_registration,
};

/// The state of a registered claim, as the log has it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClaimState {
    /// Registered and not closed. The respondent has yet to answer.
    Open,
    /// The respondent offered evidence in time. Not a verification result.
    Answered,
    /// The respondent refused the claim in time, with a reason.
    Refused,
    /// The deadline passed without a response.
    Expired,
    /// The claimant withdrew the claim.
    Withdrawn,
    /// The claimant replaced the claim with another.
    Superseded,
}

impl ClaimState {
    /// The protocol's spelling of the state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "OPEN",
            Self::Answered => "ANSWERED",
            Self::Refused => "REFUSED",
            Self::Expired => "EXPIRED",
            Self::Withdrawn => "WITHDRAWN",
            Self::Superseded => "SUPERSEDED",
        }
    }
}

/// The state of a claim's dispute.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DisputeState {
    /// Opened and not resolved. The claim is not ready to be acted on.
    Open,
    /// Resolved: the disputing party's position stands.
    Upheld,
    /// Resolved against the disputing party.
    Rejected,
}

impl DisputeState {
    /// The protocol's spelling of the state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "OPEN",
            Self::Upheld => "UPHELD",
            Self::Rejected => "REJECTED",
        }
    }
}

/// A registered claim, as an audit found it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditedClaim {
    /// The claim's digest.
    pub claim: Sha256Digest,
    /// The claim's identifier.
    pub id: String,
    /// The position of its receipt in the log.
    pub position: i64,
    /// When the respondent must have answered, as the receipt spells it.
    pub respond_by: String,
    /// The claim's state.
    pub state: ClaimState,
    /// The state of its dispute, if it was disputed.
    pub dispute: Option<DisputeState>,
}

struct Agreement {
    digest: Sha256Digest,
    unit_key: String,
    limit: i64,
    claimant: String,
    respondent: String,
    valid_from: Instant,
}

struct Dispute {
    digest: Sha256Digest,
    resolver: Option<String>,
}

struct Claim {
    public: AuditedClaim,
    agreement: usize,
    unit: String,
    respond_by: Instant,
    /// When its closure was recorded.
    closed_at: Option<Instant>,
    dispute: Option<Dispute>,
}

impl Claim {
    /// Whether the claim holds its unit: while it is open or answered,
    /// while a dispute of it is open, or once its refusal was disputed by
    /// the claimant and the dispute upheld.
    fn holds(&self) -> bool {
        let public = &self.public;
        matches!(public.state, ClaimState::Open | ClaimState::Answered)
            || public.dispute == Some(DisputeState::Open)
            || (public.state == ClaimState::Refused && public.dispute == Some(DisputeState::Upheld))
    }
}

const KINDS: [&str; 7] = [
    "agreement",
    "claim",
    "response",
    "notice",
    "terms",
    "dispute",
    "resolution",
];

/// The supplied documents, by kind and by the digest of what they sign.
struct Supplied<'t>(BTreeMap<(&'static str, String), &'t [u8]>);

impl<'t> Supplied<'t> {
    /// Reads whatever is JSON, of any spelling: a document is found by its
    /// digest, and is checked only once the log names it.
    fn new(documents: &[&'t [u8]]) -> Self {
        let mut found = BTreeMap::new();
        for text in documents {
            let Ok(value) = parse(text, &Limits::DEFAULT) else {
                continue;
            };
            let Some(object) = value.as_object() else {
                continue;
            };
            for kind in KINDS {
                if let Some(signed) = object.get(kind) {
                    found
                        .entry((kind, signed.digest().to_hex()))
                        .or_insert(*text);
                }
            }
        }
        Self(found)
    }

    fn find(&self, kind: &'static str, digest: &str, missing: Code) -> Checked<&'t [u8]> {
        match self.0.get(&(kind, digest.to_owned())) {
            Some(text) => Ok(text),
            None => refuse(missing, format!("the {kind} {digest} was not supplied")),
        }
    }
}

fn malformed(shape: &ShapeError) -> RegistrationRefusal {
    RegistrationRefusal {
        code: Code::Malformed,
        detail: shape.to_string(),
    }
}

/// A named document is of this protocol and states SHA-256 commitments.
fn of_protocol<'a>(
    protocol: &str,
    commitments: impl IntoIterator<Item = WireDigest<'a>>,
    what: &str,
) -> Checked<()> {
    if protocol != REGISTRATION_PROTOCOL {
        return refuse(
            Code::UnsupportedProtocol,
            format!("the {what} is not of claim registration v1"),
        );
    }
    if !commitments
        .into_iter()
        .all(|d| d.algorithm == Sha256Digest::ALGORITHM && is_hex_digest(d))
    {
        return refuse(
            Code::MalformedCommitment,
            format!("the {what} states a commitment that is not a SHA-256 digest"),
        );
    }
    Ok(())
}

struct Audit<'t> {
    trust: &'t RegistrationTrust,
    supplied: Supplied<'t>,
    agreements: Vec<Agreement>,
    claims: Vec<Claim>,
    /// A supersession just recorded: the digest of the claim that must be
    /// registered next, and the agreement of the claim it replaces.
    pending: Option<(String, usize)>,
}

impl Audit<'_> {
    fn party(
        &self,
        signature: IssuerSignature<'_>,
        party: &str,
        at: Instant,
        domain: verified_canonical::SigningDomain,
        object: &Value,
        what: &str,
    ) -> Checked<()> {
        let signing = Signing {
            signature,
            domain,
            object,
            what,
        };
        signed(
            &self.trust.parties,
            party,
            Code::PartyMismatch,
            at,
            &signing,
        )
    }

    fn registered(&self, entry: &LogEntry<'_>, absent: Code) -> Checked<usize> {
        let found = self
            .claims
            .iter()
            .position(|c| entry.claim.states(&c.public.claim));
        match found {
            Some(index) => Ok(index),
            None => refuse(
                absent,
                format!(
                    "entry {} is about a claim the log did not register before it",
                    entry.sequence
                ),
            ),
        }
    }

    /// Whether a claim other than `except` holds `unit` under `unit_key`.
    fn held(&self, unit_key: &str, unit: &str, except: Option<usize>) -> bool {
        self.claims.iter().enumerate().any(|(i, c)| {
            Some(i) != except
                && c.unit == unit
                && self.agreements[c.agreement].unit_key == unit_key
                && c.holds()
        })
    }

    fn receipt(&mut self, entry: &LogEntry<'_>, text: &[u8], respond_by: Instant) -> Checked<()> {
        let pending = self.pending.take();
        if pending
            .as_ref()
            .is_some_and(|(by, _)| *by != entry.claim.hex)
        {
            return refuse(
                Code::SupersessionIncomplete,
                "the entry after a supersession does not register the replacing claim",
            );
        }
        let claim_text = self
            .supplied
            .find("claim", entry.claim.hex, Code::MissingClaim)?;
        let claim_value = canonical(claim_text, "claim")?;
        let claim = SignedClaim::from_value(&claim_value).map_err(|e| malformed(&e))?;
        let agreement_text =
            self.supplied
                .find("agreement", claim.agreement.hex, Code::MissingAgreement)?;
        let registration = verify_registration(agreement_text, claim_text, text, self.trust)?;

        let known = self
            .agreements
            .iter()
            .position(|a| a.digest == registration.agreement);
        let agreement = if let Some(index) = known {
            index
        } else {
            let value = canonical(agreement_text, "agreement")?;
            let read = SignedAgreement::from_value(&value).map_err(|e| malformed(&e))?;
            self.agreements.push(Agreement {
                digest: registration.agreement,
                unit_key: read.unit_key.hex.to_owned(),
                limit: read.open_claim_limit,
                claimant: read.claimant.to_owned(),
                respondent: read.respondent.to_owned(),
                valid_from: read.valid_from,
            });
            self.agreements.len() - 1
        };
        if pending.is_some_and(|(_, replaced)| replaced != agreement) {
            return refuse(
                Code::SupersessionInvalid,
                "a replacing claim is under another agreement than the claim it replaces",
            );
        }
        if self.held(&self.agreements[agreement].unit_key, claim.unit.hex, None) {
            return refuse(
                Code::UnitHeld,
                format!(
                    "entry {} registers a claim for a unit an earlier claim holds",
                    entry.sequence
                ),
            );
        }
        let open = self
            .claims
            .iter()
            .filter(|c| c.agreement == agreement && c.public.state == ClaimState::Open)
            .count();
        if i64::try_from(open).unwrap_or(i64::MAX) >= self.agreements[agreement].limit {
            return refuse(
                Code::LimitExceeded,
                format!(
                    "entry {} registers a claim beyond its agreement's limit on open claims",
                    entry.sequence
                ),
            );
        }
        self.claims.push(Claim {
            public: AuditedClaim {
                claim: registration.claim,
                id: registration.claim_id,
                position: entry.sequence,
                respond_by: registration.respond_by,
                state: ClaimState::Open,
                dispute: None,
            },
            agreement,
            unit: claim.unit.hex.to_owned(),
            respond_by,
            closed_at: None,
            dispute: None,
        });
        Ok(())
    }

    fn closure(
        &mut self,
        entry: &LogEntry<'_>,
        closing: &str,
        rests_on: Option<WireDigest<'_>>,
    ) -> Checked<()> {
        let index = self.registered(entry, Code::ClosureWithoutRegistration)?;
        let by_claimant = matches!(closing, "Withdrawn" | "Superseded");
        let state = self.claims[index].public.state;
        let closable = state == ClaimState::Open || (by_claimant && state == ClaimState::Answered);
        if !closable {
            return refuse(
                Code::AlreadyClosed,
                format!(
                    "entry {} closes a claim that is already closed",
                    entry.sequence
                ),
            );
        }
        if by_claimant && self.claims[index].public.dispute == Some(DisputeState::Open) {
            return refuse(
                Code::DisputeOpen,
                "a claim with an open dispute cannot be withdrawn or replaced",
            );
        }
        let recorded_at = entry.at.at;
        let named = rests_on.map_or("", |d| d.hex);
        let state = match closing {
            "Expired" => {
                if recorded_at <= self.claims[index].respond_by {
                    return refuse(
                        Code::ExpiredEarly,
                        format!(
                            "entry {} records an expiry before the deadline",
                            entry.sequence
                        ),
                    );
                }
                ClaimState::Expired
            }
            "Responded" => self.response(index, named, recorded_at)?,
            _ => self.notice(index, named, recorded_at, closing == "Superseded")?,
        };
        let claim = &mut self.claims[index];
        claim.public.state = state;
        claim.closed_at = Some(recorded_at);
        Ok(())
    }

    fn response(&self, index: usize, digest: &str, recorded_at: Instant) -> Checked<ClaimState> {
        let claim = &self.claims[index];
        let text = self
            .supplied
            .find("response", digest, Code::MissingResponse)?;
        let value = canonical(text, "response")?;
        let response = SignedResponse::from_value(&value).map_err(|e| malformed(&e))?;
        let named = match response.answer {
            Answer::Evidence(package) => Some(package),
            Answer::Duplicate(of) => Some(of),
            _ => None,
        };
        of_protocol(
            response.protocol,
            [Some(response.claim), named].into_iter().flatten(),
            "response",
        )?;
        if response.answer == Answer::Other("") {
            return refuse(
                Code::ResponseInvalid,
                "a refusal for another reason states no reason",
            );
        }
        if !response.claim.states(&claim.public.claim) {
            return refuse(Code::ClaimMismatch, "the response answers another claim");
        }
        self.party(
            response.signature,
            &self.agreements[claim.agreement].respondent,
            response.responded_at.at,
            RESPONSE_DOMAIN,
            response.response,
            "the response's signature",
        )?;
        if response.responded_at.at > recorded_at {
            return refuse(
                Code::RespondedAfterRecord,
                "the response is dated after the registry recorded it",
            );
        }
        if recorded_at > claim.respond_by {
            return refuse(
                Code::LateResponse,
                "the response was recorded after the deadline",
            );
        }
        Ok(match response.answer {
            Answer::Evidence(_) => ClaimState::Answered,
            _ => ClaimState::Refused,
        })
    }

    fn notice(
        &mut self,
        index: usize,
        digest: &str,
        recorded_at: Instant,
        supersedes: bool,
    ) -> Checked<ClaimState> {
        let claim = &self.claims[index];
        let text = self.supplied.find("notice", digest, Code::MissingNotice)?;
        let value = canonical(text, "notice")?;
        let notice = SignedNotice::from_value(&value).map_err(|e| malformed(&e))?;
        of_protocol(
            notice.protocol,
            [Some(notice.claim), notice.superseded_by]
                .into_iter()
                .flatten(),
            "notice",
        )?;
        if notice.superseded_by.is_some() != supersedes {
            return refuse(
                Code::NoticeMismatch,
                "the notice's action is not the closure's",
            );
        }
        if !notice.claim.states(&claim.public.claim) {
            return refuse(Code::ClaimMismatch, "the notice is about another claim");
        }
        self.party(
            notice.signature,
            &self.agreements[claim.agreement].claimant,
            notice.issued_at.at,
            NOTICE_DOMAIN,
            notice.notice,
            "the notice's signature",
        )?;
        if notice.issued_at.at > recorded_at {
            return refuse(
                Code::NoticeAfterRecord,
                "the notice is dated after the registry recorded it",
            );
        }
        Ok(match notice.superseded_by {
            Some(by) => {
                self.pending = Some((by.hex.to_owned(), claim.agreement));
                ClaimState::Superseded
            }
            None => ClaimState::Withdrawn,
        })
    }

    /// The dispute terms with this digest: of this agreement, sound, and
    /// signed by both parties. Returns the window and the resolver.
    fn terms(&self, agreement: &Agreement, digest: &str) -> Checked<(i64, Option<String>)> {
        let text = self.supplied.find("terms", digest, Code::MissingTerms)?;
        let value = canonical(text, "dispute terms")?;
        let terms = SignedTerms::from_value(&value).map_err(|e| malformed(&e))?;
        of_protocol(terms.protocol, [terms.agreement], "dispute terms")?;
        if !terms.agreement.states(&agreement.digest) {
            return refuse(
                Code::AgreementMismatch,
                "the dispute terms belong to another agreement than the claim's",
            );
        }
        let resolver_is_a_party = terms
            .resolver
            .is_some_and(|r| r == agreement.claimant || r == agreement.respondent);
        if terms.dispute_within_seconds <= 0 || resolver_is_a_party {
            return refuse(
                Code::TermsInvalid,
                "dispute terms need a positive window and a resolver who is neither party",
            );
        }
        for (signature, party, what) in [
            (
                terms.claimant_signature,
                &agreement.claimant,
                "the claimant's signature of the dispute terms",
            ),
            (
                terms.respondent_signature,
                &agreement.respondent,
                "the respondent's signature of the dispute terms",
            ),
        ] {
            self.party(
                signature,
                party,
                agreement.valid_from,
                DISPUTE_TERMS_DOMAIN,
                terms.terms,
                what,
            )?;
        }
        Ok((
            terms.dispute_within_seconds,
            terms.resolver.map(str::to_owned),
        ))
    }

    fn opened(&mut self, entry: &LogEntry<'_>, index: usize, digest: &str) -> Checked<()> {
        let claim = &self.claims[index];
        let agreement = &self.agreements[claim.agreement];
        let state = claim.public.state;
        if !matches!(state, ClaimState::Refused | ClaimState::Answered) {
            return refuse(
                Code::NotDisputable,
                "only a refused or an answered claim can be disputed",
            );
        }
        if claim.public.dispute.is_some() {
            return refuse(Code::AlreadyDisputed, "the claim was disputed before");
        }
        let text = self
            .supplied
            .find("dispute", digest, Code::MissingDispute)?;
        let value = canonical(text, "dispute")?;
        let dispute = SignedDispute::from_value(&value).map_err(|e| malformed(&e))?;
        of_protocol(dispute.protocol, [dispute.claim, dispute.terms], "dispute")?;
        if dispute.other_ground == Some("") {
            return refuse(
                Code::DisputeInvalid,
                "a dispute on another ground states no ground",
            );
        }
        if !dispute.claim.states(&claim.public.claim) {
            return refuse(Code::ClaimMismatch, "the dispute is about another claim");
        }

        let (window, resolver) = self.terms(agreement, dispute.terms.hex)?;

        // Only the claimant disputes a refusal; either party, evidence.
        let may_dispute = dispute.by == agreement.claimant
            || (state == ClaimState::Answered && dispute.by == agreement.respondent);
        if !may_dispute {
            return refuse(
                Code::PartyMismatch,
                "the dispute is opened by someone who may not dispute this claim",
            );
        }
        self.party(
            dispute.signature,
            dispute.by,
            dispute.opened_at.at,
            DISPUTE_DOMAIN,
            dispute.dispute,
            "the dispute's signature",
        )?;
        let recorded_at = entry.at.at;
        if dispute.opened_at.at > recorded_at {
            return refuse(
                Code::DisputedAfterRecord,
                "the dispute is dated after the registry recorded it",
            );
        }
        let window_end = claim
            .closed_at
            .and_then(|closed| closed.plus_seconds(window));
        if window_end.is_some_and(|end| recorded_at > end) {
            return refuse(
                Code::LateDispute,
                "the dispute was recorded after the agreed window",
            );
        }
        // An open dispute holds the unit again, so no other claim may.
        if !claim.holds() && self.held(&agreement.unit_key, &claim.unit, Some(index)) {
            return refuse(
                Code::UnitHeld,
                "the dispute would hold a unit that another claim holds",
            );
        }
        let opened = Dispute {
            digest: dispute.dispute.digest(),
            resolver,
        };
        let claim = &mut self.claims[index];
        claim.dispute = Some(opened);
        claim.public.dispute = Some(DisputeState::Open);
        Ok(())
    }

    fn resolved(&mut self, entry: &LogEntry<'_>, index: usize, digest: &str) -> Checked<()> {
        let claim = &self.claims[index];
        let agreement = &self.agreements[claim.agreement];
        let Some(dispute) = claim
            .dispute
            .as_ref()
            .filter(|_| claim.public.dispute == Some(DisputeState::Open))
        else {
            return refuse(Code::NoOpenDispute, "the claim has no open dispute");
        };
        let text = self
            .supplied
            .find("resolution", digest, Code::MissingResolution)?;
        let value = canonical(text, "resolution")?;
        let resolution = SignedResolution::from_value(&value).map_err(|e| malformed(&e))?;
        of_protocol(resolution.protocol, [resolution.dispute], "resolution")?;
        if !resolution.dispute.states(&dispute.digest) {
            return refuse(
                Code::DisputeMismatch,
                "the resolution is of another dispute than the open one",
            );
        }
        let at = resolution.resolved_at.at;
        let sign = |signature, party: &str, what| {
            self.party(
                signature,
                party,
                at,
                RESOLUTION_DOMAIN,
                resolution.resolution,
                what,
            )
        };
        match resolution.signatures {
            ResolutionSignatures::Resolver(signature) => {
                let Some(resolver) = &dispute.resolver else {
                    return refuse(
                        Code::NoResolver,
                        "the dispute terms name no resolver; only a settlement ends the dispute",
                    );
                };
                sign(signature, resolver, "the resolver's signature")?;
            }
            ResolutionSignatures::Settlement {
                claimant,
                respondent,
            } => {
                sign(
                    claimant,
                    &agreement.claimant,
                    "the claimant's signature of the settlement",
                )?;
                sign(
                    respondent,
                    &agreement.respondent,
                    "the respondent's signature of the settlement",
                )?;
            }
        }
        if at > entry.at.at {
            return refuse(
                Code::ResolvedAfterRecord,
                "the resolution is dated after the registry recorded it",
            );
        }
        self.claims[index].public.dispute = Some(if resolution.upheld {
            DisputeState::Upheld
        } else {
            DisputeState::Rejected
        });
        Ok(())
    }
}

/// Audits a registry's log from the text of its entries, from the first,
/// and the text of the documents it names, in any order.
///
/// See the module documentation for what a passing audit establishes.
///
/// # Errors
///
/// The first of the protocol's checks that fails.
pub fn audit(
    entries: &[&[u8]],
    documents: &[&[u8]],
    trust: &RegistrationTrust,
) -> Result<Vec<AuditedClaim>, RegistrationRefusal> {
    // Step 1: a segment from the start of the log.
    check_log(entries, None, None, trust)?;

    let mut audit = Audit {
        trust,
        supplied: Supplied::new(documents),
        agreements: Vec::new(),
        claims: Vec::new(),
        pending: None,
    };
    let incomplete = || {
        refuse(
            Code::SupersessionIncomplete,
            "a supersession is not followed by the registration of the replacing claim",
        )
    };
    for text in entries {
        // The segment verified, so each entry reads again.
        let value = canonical(text, "entry")?;
        let entry = LogEntry::from_value(&value).map_err(|e| malformed(&e))?;
        match entry.kind {
            EntryKind::Receipt { respond_by } => audit.receipt(&entry, text, respond_by.at)?,
            _ if audit.pending.is_some() => return incomplete(),
            EntryKind::Closure { closing, rests_on } => audit.closure(&entry, closing, rests_on)?,
            EntryKind::DisputeRecord { step, names } => {
                let index = audit.registered(&entry, Code::DisputeWithoutClaim)?;
                if step == "Opened" {
                    audit.opened(&entry, index, names.hex)?;
                } else {
                    audit.resolved(&entry, index, names.hex)?;
                }
            }
        }
    }
    if audit.pending.is_some() {
        return incomplete();
    }
    Ok(audit.claims.into_iter().map(|c| c.public).collect())
}
