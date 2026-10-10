//! Decisions.

use std::fmt;
use std::str::FromStr;

use verified_canonical::{SigningDomain, Value};

use crate::container::WireDigest;
use crate::shape::{self, At, Shape};
use crate::version::ProtocolVersion;

/// What an evaluator concludes about a claim under a contract and evidence.
///
/// A decision is about the claim under this evidence. It is not a statement
/// that any source was right.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Decision {
    /// The admitted evidence establishes the claim under the contract.
    Supported,
    /// The admitted evidence conclusively contradicts the claim.
    Contradicted,
    /// The admitted evidence does not settle the claim.
    Undetermined,
}

impl Decision {
    /// The protocol's name for this decision. Stable.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "SUPPORTED",
            Self::Contradicted => "CONTRADICTED",
            Self::Undetermined => "UNDETERMINED",
        }
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Decision {
    type Err = ();

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "SUPPORTED" => Ok(Self::Supported),
            "CONTRADICTED" => Ok(Self::Contradicted),
            "UNDETERMINED" => Ok(Self::Undetermined),
            _ => Err(()),
        }
    }
}

/// The evaluator a decision names: `{ name, specification }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Evaluator<'a> {
    /// The evaluator's name.
    pub name: &'a str,
    /// The version of its specification.
    pub specification: &'a str,
}

impl ProtocolVersion {
    /// The one evaluator this protocol version specifies.
    #[must_use]
    pub const fn evaluator(self) -> Evaluator<'static> {
        match self {
            Self::V0_1 => Evaluator {
                name: "order-transition",
                specification: "1",
            },
            Self::V0_2 => Evaluator {
                name: "work-contract",
                specification: "1",
            },
        }
    }

    /// The domain an issuer's signature over a decision is made under. The
    /// domains differ, so a signature over a decision of one version cannot
    /// be presented as a signature over a decision of the other.
    #[must_use]
    pub const fn decision_domain(self) -> SigningDomain {
        match self {
            Self::V0_1 => DECISION_DOMAIN_V0_1,
            Self::V0_2 => DECISION_DOMAIN_V0_2,
        }
    }
}

const fn domain(prefix: &'static str) -> SigningDomain {
    match SigningDomain::new(prefix) {
        Ok(domain) => domain,
        Err(_) => panic!("a decision signing domain is one line"),
    }
}

// Evaluated at compile time: a malformed prefix does not build.
const DECISION_DOMAIN_V0_1: SigningDomain = domain("verified:wvp-decision:v0.1\n");
const DECISION_DOMAIN_V0_2: SigningDomain = domain("verified:wvp-decision:v0.2\n");

/// The source name through which a trust registry authorizes a key to sign
/// decisions. It is the same for both protocol versions.
pub const DECISION_SOURCE: &str = "wvp-decision";

/// The members of `decision.json` both protocol versions share, as stated.
///
/// A recorded decision is a claim by whoever wrote the package. It counts
/// only once a verifier has recomputed it and found the same bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordedDecision<'a> {
    /// The component, whole.
    pub value: &'a Value,
    /// The protocol the decision says it was made under.
    pub protocol: &'a str,
    /// The evaluator the decision names.
    pub evaluator: Evaluator<'a>,
}

/// Reads the members every decision has. `o` is the decision object, whose
/// member set the caller has already checked.
pub(crate) fn common<'a>(
    value: &'a Value,
    o: &'a verified_canonical::Object,
    at: &At<'_>,
) -> Shape<RecordedDecision<'a>> {
    shape::text(shape::get(o, "decision"), &at.member("decision"))?;
    let evaluator_at = at.member("evaluator");
    let evaluator = shape::object(
        shape::get(o, "evaluator"),
        &evaluator_at,
        &["name", "specification"],
    )?;
    let commitments_at = at.member("commitments");
    let commitments = shape::object(
        shape::get(o, "commitments"),
        &commitments_at,
        &["claim", "contract", "evidence", "inputs"],
    )?;
    for (name, commitment) in commitments.iter() {
        let _: WireDigest<'_> = shape::digest(commitment, &commitments_at.member(name))?;
    }
    Ok(RecordedDecision {
        value,
        protocol: shape::text(shape::get(o, "protocol"), &at.member("protocol"))?,
        evaluator: Evaluator {
            name: shape::text(shape::get(evaluator, "name"), &evaluator_at.member("name"))?,
            specification: shape::text(
                shape::get(evaluator, "specification"),
                &evaluator_at.member("specification"),
            )?,
        },
    })
}
