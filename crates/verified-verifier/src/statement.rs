// SPDX-License-Identifier: Apache-2.0

//! Steps 9 and 10: each statement verifies under the registry, and the
//! statements are the evidence of this claim.

use verified_canonical::Value;
use verified_protocol::{Evidence, RefusalCode, STATEMENT_PROTOCOL, SignedStatement, WireDigest};

use crate::container::{Refusal, refusal};
use crate::json::{digest, object, text};
use crate::trust::{ED25519, Trust, verifies};

fn is_commitment(digest: WireDigest<'_>) -> bool {
    digest.algorithm == verified_canonical::Sha256Digest::ALGORITHM
        && digest
            .hex
            .parse::<verified_canonical::Sha256Digest>()
            .is_ok()
}

/// Step 9 for one statement. Checks run in the order the evidence statement
/// protocol fixes, so every verifier reports the same code.
pub(crate) fn authenticate(statement: &SignedStatement<'_>, trust: &Trust) -> Result<(), Refusal> {
    let id = statement.id;
    let fail = |code, what: &str| Err(refusal(code, format!("statement {id}: {what}")));
    if statement.protocol != STATEMENT_PROTOCOL {
        return fail(
            RefusalCode::UnsupportedProtocol,
            "is not an evidence statement v1",
        );
    }
    let previous = statement.chain.and_then(|link| link.previous);
    if !is_commitment(statement.payload) || !previous.is_none_or(is_commitment) {
        return fail(
            RefusalCode::MalformedCommitment,
            "carries a commitment that is not a SHA-256 digest",
        );
    }
    let Some((key, material)) = trust.find(statement.signature.key_id) else {
        return fail(
            RefusalCode::UnknownKey,
            &format!("the registry holds no key {:?}", statement.signature.key_id),
        );
    };
    let (ED25519, ED25519, Some(material)) =
        (key.algorithm.as_str(), statement.signature.scheme, material)
    else {
        return fail(
            RefusalCode::UnsupportedAlgorithm,
            "the key or the scheme is not Ed25519",
        );
    };
    if key.tenant != statement.tenant {
        return fail(
            RefusalCode::TenantMismatch,
            "the key is not trusted for the statement's tenant",
        );
    }
    if key.issuer != statement.issuer {
        return fail(
            RefusalCode::IssuerMismatch,
            "the key does not belong to the statement's issuer",
        );
    }
    if !key.speaks_for(statement.source_system) {
        return fail(
            RefusalCode::SourceNotAuthorized,
            &format!(
                "the key is not authorized for source {:?}",
                statement.source_system
            ),
        );
    }
    if !key.valid_at(statement.observed_at) {
        return fail(
            RefusalCode::KeyNotValid,
            "the key was not valid when the statement was observed",
        );
    }
    if !verifies(
        material,
        &statement.signing_input(),
        statement.signature.encoded,
    ) {
        return fail(
            RefusalCode::SignatureInvalid,
            "the signature does not verify",
        );
    }
    Ok(())
}

/// Step 10: admission. The tenant comes from the evaluation's inputs, never
/// from the statements.
pub(crate) fn admit<B>(
    tenant: &str,
    claimed: &[&str],
    evidence: &[Evidence<'_, B>],
) -> Result<(), Refusal> {
    let ids: Vec<&str> = evidence.iter().map(|e| e.statement.id).collect();
    let distinct = |ids: &[&str]| ids.iter().enumerate().all(|(i, id)| !ids[..i].contains(id));
    if let Some(foreign) = evidence.iter().find(|e| e.statement.tenant != tenant) {
        return Err(refusal(
            RefusalCode::ForeignTenantEvidence,
            format!(
                "statement {} belongs to another tenant",
                foreign.statement.id
            ),
        ));
    }
    if !distinct(&ids) || !distinct(claimed) {
        return Err(refusal(
            RefusalCode::DuplicateEvidenceId,
            "an evidence identifier occurs twice",
        ));
    }
    if let Some(id) = ids.iter().find(|id| !claimed.contains(id)) {
        return Err(refusal(
            RefusalCode::EvidenceNotClaimed,
            format!("statement {id} is not named by the claim"),
        ));
    }
    if let Some(id) = claimed.iter().find(|id| !ids.contains(id)) {
        return Err(refusal(
            RefusalCode::MissingEvidence,
            format!("the claim names evidence {id}, which the package does not carry"),
        ));
    }
    for item in evidence {
        let body: &Value = item.body_value;
        // The payload was shown to be a SHA-256 commitment in step 9.
        if item.statement.payload.hex != body.digest().to_hex() {
            return Err(refusal(
                RefusalCode::PayloadMismatch,
                format!(
                    "the body of statement {} is not the one it commits to",
                    item.statement.id
                ),
            ));
        }
    }
    Ok(())
}

/// The evidence manifest that admission produces: the admitted statements,
/// in ascending order of identifier, as the evidence of one claim. The
/// identifiers and times are the caller's, in wire form.
pub(crate) fn manifest<'a>(
    statements: impl Iterator<Item = &'a SignedStatement<'a>>,
    package_id: &Value,
    claim_id: &Value,
    ingested_at: &Value,
    assembled_at: &Value,
) -> Value {
    let item = |statement: &SignedStatement<'_>| {
        let transformation = object([
            ("name", text("verified-evidence-statement")),
            (
                "version",
                object([
                    ("major", Value::Integer(1.into())),
                    ("minor", Value::Integer(0.into())),
                    ("patch", Value::Integer(0.into())),
                ]),
            ),
            (
                "inputHashes",
                Value::Array(vec![digest(&statement.digest())]),
            ),
        ]);
        object([
            ("id", statement.member("id").clone()),
            ("kind", statement.member("kind").clone()),
            ("subject", statement.member("subject").clone()),
            ("payloadHash", statement.member("payload").clone()),
            (
                "provenance",
                object([
                    ("source", statement.member("source").clone()),
                    ("witness", statement.member("issuer").clone()),
                    ("trust", object([("Signed", object([]))])),
                    ("observedAt", statement.member("observedAt").clone()),
                    ("ingestedAt", ingested_at.clone()),
                    ("transformations", Value::Array(vec![transformation])),
                    ("causedBy", Value::Array(Vec::new())),
                ]),
            ),
        ])
    };
    object([
        ("version", text("verified-evidence-manifest-v1")),
        ("id", package_id.clone()),
        ("claimId", claim_id.clone()),
        ("items", Value::Array(statements.map(item).collect())),
        ("assembledAt", assembled_at.clone()),
    ])
}
