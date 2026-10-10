//! Signed evidence statements (`verified-evidence-statement-v1`).
//!
//! A statement is evidence: an attributable, tamper-evident assertion that an
//! issuer observed something about a subject. A correctly signed statement
//! can be false; the signature shows only who said it.

use verified_canonical::{Sha256Digest, SigningDomain, Value};

use crate::container::{IssuerSignature, WireDigest};
use crate::shape::{self, At, Shape};
use crate::time::Instant;

/// The protocol identifier a statement must carry.
pub const STATEMENT_PROTOCOL: &str = "verified-evidence-statement-v1";

/// The domain a statement's signature is made under.
pub const STATEMENT_DOMAIN: SigningDomain =
    match SigningDomain::new("verified:evidence-statement:v1\n") {
        Ok(domain) => domain,
        Err(_) => panic!("the statement signing domain is one line"),
    };

/// The evidence kinds a statement may name.
pub const EVIDENCE_KINDS: [&str; 11] = [
    "StateTransition",
    "DatabaseChange",
    "ApiResponse",
    "Event",
    "Document",
    "AgentTrace",
    "SignedAttestation",
    "HumanWitness",
    "SensorObservation",
    "ExternalAssertion",
    "CryptographicProof",
];

/// A signed statement of the right structure, borrowed from its JSON.
///
/// Structure is all that has been checked: not the protocol identifier, the
/// commitments, the key or the signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedStatement<'a> {
    /// The `statement` member, whole: the signature is over its canonical
    /// text, and its digest identifies it.
    pub statement: &'a Value,
    /// The stated protocol identifier.
    pub protocol: &'a str,
    /// The evidence identifier (a UUID).
    pub id: &'a str,
    /// The tenant the statement says it belongs to.
    pub tenant: &'a str,
    /// The evidence kind's case name.
    pub kind: &'a str,
    /// The asserting actor (a UUID).
    pub issuer: &'a str,
    /// The system the issuer says it observed.
    pub source_system: &'a str,
    /// The asserted observation time. Not authenticated.
    pub observed_at: Instant,
    /// The stated commitment to the evidence body.
    pub payload: WireDigest<'a>,
    /// The stated digest of the previous step of the issuer's stream, if the
    /// statement is chained and is not the first step.
    pub chain_previous: Option<WireDigest<'a>>,
    /// The signature, as carried.
    pub signature: IssuerSignature<'a>,
}

impl<'a> SignedStatement<'a> {
    /// Reads `{ statement, signature }`, refusing any missing, extra or
    /// mistyped member at any depth.
    pub fn from_value(signed: &'a Value) -> Result<Self, crate::ShapeError> {
        Self::read(signed, &At::root("statement"))
    }

    pub(crate) fn read(signed: &'a Value, at: &At<'_>) -> Shape<Self> {
        let outer = shape::object(signed, at, &["signature", "statement"])?;
        let signature = signature(shape::get(outer, "signature"), &at.member("signature"))?;

        let statement = shape::get(outer, "statement");
        let at = at.member("statement");
        let o = shape::object(
            statement,
            &at,
            &[
                "chain",
                "id",
                "issuer",
                "kind",
                "observedAt",
                "payload",
                "protocol",
                "source",
                "subject",
                "tenant",
            ],
        )?;
        let member = |name| shape::get(o, name);
        shape::subject(member("subject"), &at.member("subject"))?;
        let chain_at = at.member("chain");
        let chain_previous = shape::nullable(member("chain"), &chain_at, |chain, at| {
            let chain = shape::object(chain, at, &["previous", "sequence", "stream"])?;
            shape::text(shape::get(chain, "stream"), &at.member("stream"))?;
            shape::int64(shape::get(chain, "sequence"), &at.member("sequence"))?;
            shape::nullable(
                shape::get(chain, "previous"),
                &at.member("previous"),
                shape::digest,
            )
        })?
        .flatten();
        Ok(Self {
            statement,
            protocol: shape::text(member("protocol"), &at.member("protocol"))?,
            id: shape::uuid(member("id"), &at.member("id"))?,
            tenant: shape::wrapped(member("tenant"), &at.member("tenant"))?,
            kind: shape::unit(member("kind"), &at.member("kind"), &EVIDENCE_KINDS)?,
            issuer: shape::uuid(member("issuer"), &at.member("issuer"))?,
            source_system: shape::source(member("source"), &at.member("source"))?,
            observed_at: shape::instant(member("observedAt"), &at.member("observedAt"))?,
            payload: shape::digest(member("payload"), &at.member("payload"))?,
            chain_previous,
            signature,
        })
    }

    /// The statement's digest: the SHA-256 of its canonical text. It
    /// identifies the statement in commitments.
    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        self.statement.digest()
    }

    /// The bytes the signature is over.
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        STATEMENT_DOMAIN.signing_input(self.statement)
    }

    /// A member of the statement, as JSON. `Null` if there is none.
    #[must_use]
    pub fn member(&self, name: &str) -> &'a Value {
        self.statement
            .as_object()
            .and_then(|o| o.get(name))
            .unwrap_or(&Value::Null)
    }
}

/// `{ scheme, keyId, encoded }`, all text.
pub(crate) fn signature<'a>(value: &'a Value, at: &At<'_>) -> Shape<IssuerSignature<'a>> {
    let o = shape::object(value, at, &["encoded", "keyId", "scheme"])?;
    Ok(IssuerSignature {
        scheme: shape::text(shape::get(o, "scheme"), &at.member("scheme"))?,
        key_id: shape::text(shape::get(o, "keyId"), &at.member("keyId"))?,
        encoded: shape::text(shape::get(o, "encoded"), &at.member("encoded"))?,
    })
}
