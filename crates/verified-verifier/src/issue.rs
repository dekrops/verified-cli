// SPDX-License-Identifier: Apache-2.0

//! Issuing `wvp-0.2` packages: evaluating a contract against a claim's
//! signed evidence and sealing the result.
//!
//! **Issuing is not verifying.** [`issue`] produces a package that carries
//! its issuer's decision. What a relying party may rely on is what
//! [`crate::verify`] establishes under the relying party's own registry.
//!
//! An issuer and a verifier cannot disagree here, by construction:
//!
//! - the input conditions, the environment and the evaluation are the
//!   verifier's own (`work_contract::evaluate`), and the decision document is
//!   written by the function the verifier compares against;
//! - the finished text is verified under the issuer's registry before it is
//!   returned. A package that would be refused is an [`IssueError`], never
//!   an artifact.
//!
//! This module collects no evidence, holds no key and decides nothing about
//! whom to trust. It takes statements that are already signed, and a
//! countersignature that was already made.

use verified_canonical::{CANONICAL_VERSION, Integer, LimitExceeded, Limits, Sha256Digest, Value};
use verified_contract::Contract;
use verified_protocol::v02::Components;
use verified_protocol::{
    ComponentPath, PACKAGE_VERSION, PackageId, ProtocolVersion, RefusalCode, SignedStatement,
};

use crate::container::{self, Options, ProtocolSelection, Refusal, Rejection, refusal};
use crate::json::{digest, object, text, wrapped};
use crate::report::{IssuerSignature, Report};
use crate::trust::Trust;
use crate::verify::{Commitments, decision_over, verify};
use crate::work_contract;

const PROTOCOL: ProtocolVersion = ProtocolVersion::V0_2;

/// What a `wvp-0.2` package is issued from.
///
/// Identifiers and times are given in the protocol's spelling (lowercase
/// UUIDs; instants such as `2026-03-01T12:00:00Z`) and are checked when the
/// draft is read. Nothing here is authenticated by being in a draft.
#[derive(Clone, Copy, Debug)]
pub struct Draft<'a> {
    /// The tenant the claim and its evaluation are for.
    pub tenant: &'a str,
    /// The contract: a well-formed Work Contract Language 1 contract.
    pub contract: &'a Value,
    /// The claim's identifier (a UUID).
    pub claim: &'a str,
    /// The actor making the claim (a UUID).
    pub claimant: &'a str,
    /// The values the claim supplies for the contract's declared inputs.
    pub inputs: &'a Value,
    /// When the claim was submitted.
    pub submitted_at: &'a str,
    /// The evidence the claim relies on: each signed statement with the body
    /// its payload commits to, in any order.
    pub evidence: &'a [(&'a Value, &'a Value)],
    /// The identifier of this evaluation's evidence set (a UUID), written as
    /// `packageId` in `inputs.json`. It is not the package identifier, which
    /// is computed.
    pub evidence_set: &'a str,
    /// When the evidence was ingested.
    pub ingested_at: &'a str,
    /// When the evidence set was assembled.
    pub assembled_at: &'a str,
    /// When the contract was evaluated.
    pub evaluated_at: &'a str,
}

/// A package this library issued, with the report of verifying it under the
/// issuer's registry. The report is always complete.
///
/// The decision in the report may be `CONTRADICTED` or `UNDETERMINED`: those
/// are results of issuing, not failures of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issued {
    /// The package's canonical text.
    pub package: String,
    /// What verifying it under the issuer's registry established.
    pub report: Report,
}

/// An issuer signature over a decision, made elsewhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Countersignature<'a> {
    /// The identifier of the key that signed.
    pub key_id: &'a str,
    /// The signature: standard base64 of 64 bytes, over
    /// [`decision_signing_input`].
    pub encoded: &'a str,
}

/// Why no package was issued.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IssueError {
    /// The draft cannot be written as the components of a package.
    #[error("the draft is not well formed: {0}")]
    Draft(String),
    /// A verifier would refuse the package, under the registry given. The
    /// refusal is the verifier's.
    #[error("the package would be refused: {0}")]
    Refused(#[from] Refusal),
    /// The package exceeds a resource limit of this verifier.
    #[error("the package exceeds a resource limit: {0}")]
    Limit(#[from] LimitExceeded),
}

impl From<Rejection> for IssueError {
    fn from(rejection: Rejection) -> Self {
        match rejection {
            Rejection::Refused(refusal) => Self::Refused(refusal),
            Rejection::Limit(limit) => Self::Limit(limit),
            other => Self::Draft(other.to_string()),
        }
    }
}

/// The container around six components and their issuer signatures.
fn seal(files: [(ComponentPath, &Value); 6], signatures: Value) -> String {
    let entries = files.iter().map(|(path, content)| {
        object([
            ("hash", digest(&content.digest())),
            ("path", text(path.as_str())),
        ])
    });
    let manifest = object([
        ("canonicalVersion", text(CANONICAL_VERSION)),
        ("files", Value::Array(entries.collect())),
        (
            "packageVersion",
            Value::Integer(Integer::from(PACKAGE_VERSION)),
        ),
        ("protocol", text(PROTOCOL.identifier())),
    ]);
    let commitment = manifest.digest();
    let contents = files.iter().map(|(path, content)| {
        object([
            ("content", (*content).clone()),
            ("path", text(path.as_str())),
        ])
    });
    object([
        ("files", Value::Array(contents.collect())),
        ("manifest", manifest),
        ("packageCommitment", digest(&commitment)),
        (
            "packageId",
            text(&PackageId::from_commitment(commitment).to_string()),
        ),
        ("signatures", signatures),
    ])
    .to_canonical_string()
}

/// Verifies a package this module wrote, as a relying party holding `trust`
/// would.
fn checked(package: String, trust: &Trust) -> Result<Issued, IssueError> {
    let options = Options {
        protocol: ProtocolSelection::Require(PROTOCOL),
        trust: Some(trust),
        ..Options::default()
    };
    let report = verify(package.as_bytes(), &options)?;
    Ok(Issued { package, report })
}

/// Evaluates the draft's contract against its evidence and seals the result
/// into a `wvp-0.2` package without issuer signatures.
///
/// `trust` is the registry the issuer authenticates its evidence under. The
/// package is returned only if a verifier holding that registry reproduces
/// its decision.
///
/// # Errors
///
/// [`IssueError::Draft`] for a draft that cannot be written as components;
/// [`IssueError::Refused`] with the verifier's refusal for anything a
/// verifier would refuse: an ill-formed contract (`MALFORMED_COMPONENT`), a
/// statement whose key may not speak for its source
/// (`SOURCE_NOT_AUTHORIZED`), inputs or records that do not fit the contract
/// (`INPUT_MISMATCH`), and so on.
pub fn issue(draft: &Draft<'_>, trust: &Trust) -> Result<Issued, IssueError> {
    let malformed = |error: verified_protocol::ShapeError| IssueError::Draft(error.to_string());

    // Statements are carried in ascending order of identifier.
    let mut evidence = draft
        .evidence
        .iter()
        .map(|(statement, body)| {
            let id = SignedStatement::from_value(statement)
                .map_err(malformed)?
                .id;
            Ok((id, *statement, *body))
        })
        .collect::<Result<Vec<_>, IssueError>>()?;
    evidence.sort_by_key(|(id, ..)| *id);

    let contract_digest = draft.contract.digest();
    let claim = object([
        ("claimant", wrapped(draft.claimant)),
        ("contract", digest(&contract_digest)),
        (
            "evidence",
            Value::Array(evidence.iter().map(|(id, ..)| wrapped(id)).collect()),
        ),
        ("id", wrapped(draft.claim)),
        ("inputs", draft.inputs.clone()),
        ("submittedAt", wrapped(draft.submitted_at)),
        ("tenant", wrapped(draft.tenant)),
    ]);
    let inputs = object([
        ("assembledAt", wrapped(draft.assembled_at)),
        ("evaluatedAt", wrapped(draft.evaluated_at)),
        ("ingestedAt", wrapped(draft.ingested_at)),
        ("packageId", wrapped(draft.evidence_set)),
        ("tenant", wrapped(draft.tenant)),
    ]);
    let bodies = Value::Array(
        evidence
            .iter()
            .map(|(id, _, body)| object([("body", (*body).clone()), ("id", wrapped(id))]))
            .collect(),
    );
    let statements = Value::Array(
        evidence
            .iter()
            .map(|(_, statement, _)| (*statement).clone())
            .collect(),
    );

    // The components are read back through the verifier's own reader, with a
    // decision that only holds the place of the one about to be computed.
    let nothing = Sha256Digest::of(&[]);
    let placeholder = decision_over(
        PROTOCOL,
        object([
            ("conflicts", Value::Array(Vec::new())),
            ("decision", text("UNDETERMINED")),
            ("ignored", Value::Array(Vec::new())),
            ("requirements", Value::Array(Vec::new())),
        ]),
        &Commitments {
            claim: nothing,
            contract: nothing,
            evidence: nothing,
            inputs: nothing,
        },
    );
    let components = Components::read([
        &claim,
        draft.contract,
        &placeholder,
        &bodies,
        &statements,
        &inputs,
    ])
    .map_err(malformed)?;
    let contract = Contract::read(draft.contract).map_err(|error| {
        refusal(
            RefusalCode::MalformedComponent,
            format!("contract.json is not a well-formed work-contract-1 contract ({error})"),
        )
    })?;
    let (outcome, evidence_commitment) =
        work_contract::evaluate(&components, &contract, &contract_digest)?;
    let decision = decision_over(
        PROTOCOL,
        outcome.to_value(),
        &Commitments {
            claim: claim.digest(),
            contract: contract_digest,
            evidence: evidence_commitment,
            inputs: inputs.digest(),
        },
    );

    let package = seal(
        [
            (ComponentPath::Claim, &claim),
            (ComponentPath::Contract, draft.contract),
            (ComponentPath::Decision, &decision),
            (ComponentPath::EvidenceBodies, &bodies),
            (ComponentPath::EvidenceStatements, &statements),
            (ComponentPath::Inputs, &inputs),
        ],
        Value::Array(Vec::new()),
    );
    checked(package, trust)
}

/// The bytes an issuer signs to stand behind a package's decision: the
/// decision domain of the package's protocol version, followed by the
/// canonical text of `decision.json`.
///
/// The package must pass the container checks (steps 1 to 6). Nothing else
/// about it is checked: signing a decision vouches for it, so verify first.
///
/// # Errors
///
/// The container check the package fails.
pub fn decision_signing_input(package: &[u8]) -> Result<Vec<u8>, Rejection> {
    let value = container::read(package, &Limits::DEFAULT)?;
    let checked = container::check(&value, ProtocolSelection::Detect)?;
    let [_, _, decision, ..] = checked.files;
    Ok(checked.protocol.decision_domain().signing_input(decision))
}

/// Adds issuer signatures to a `wvp-0.2` package and returns the new text.
///
/// Signatures lie outside the package commitment, so the identifier does not
/// change. The package is returned only if, under `trust`, it verifies
/// completely and every signature it then carries counts.
///
/// # Errors
///
/// The verifier's refusal, `ISSUER_SIGNATURE_INVALID` among them.
pub fn countersign(
    package: &[u8],
    signatures: &[Countersignature<'_>],
    trust: &Trust,
) -> Result<Issued, IssueError> {
    let value = container::read(package, &Limits::DEFAULT)?;
    let checked_container = container::check(&value, ProtocolSelection::Require(PROTOCOL))?;
    let all = checked_container
        .signatures
        .iter()
        .map(|s| (s.encoded, s.key_id, s.scheme))
        .chain(signatures.iter().map(|s| (s.encoded, s.key_id, "Ed25519")))
        .map(|(encoded, key_id, scheme)| {
            object([
                ("encoded", text(encoded)),
                ("keyId", text(key_id)),
                ("scheme", text(scheme)),
            ])
        });
    let files = std::array::from_fn(|i| (ComponentPath::ALL[i], checked_container.files[i]));
    let issued = checked(seal(files, Value::Array(all.collect())), trust)?;
    if !matches!(
        issued.report.issuer_signature,
        IssuerSignature::Established { .. }
    ) {
        return Err(IssueError::Draft(
            "no issuer signature was given".to_owned(),
        ));
    }
    Ok(issued)
}
