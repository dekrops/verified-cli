// SPDX-License-Identifier: Apache-2.0

//! Contract approval v1 (a **draft**): checking a signed approval offline.
//!
//! An approver approves the exact text of a Work Contract by signing a
//! statement with a passkey (a `WebAuthn` credential). The statement names the
//! contract's digest and the digest of a snapshot of what the approver was
//! shown. [`verify_approval`] applies the specification's fifteen checks to
//! an approval file, in order, and stops at the first that fails.
//!
//! # What a valid approval establishes
//!
//! Whoever approved held the passkey's authenticator, and the authenticator
//! saw the user present. The approval is for exactly one contract and one
//! snapshot: changing either breaks the signature.
//!
//! # What it does not establish
//!
//! - Whose passkey it is. The approval carries its key; that the key belongs
//!   to the approver is the relying party's knowledge, from how it was
//!   registered.
//! - What the person saw. Authenticators do not display what they sign; the
//!   snapshot is what the service says it showed.
//! - That the passkey is hardware-backed: no attestation is checked. Neither
//!   are the user-verified flag, the signature counter, `issuedAt` or the
//!   nonce.

use std::fmt;

use base64::Engine as _;
use base64::alphabet::URL_SAFE;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519Key};
use p256::ecdsa::signature::Verifier as _;
use p256::pkcs8::DecodePublicKey as _;
use verified_canonical::{Limits, Object, Sha256Digest, Value, parse};

use crate::trust::SPKI_PREFIX;

/// The statement's `type`.
pub const APPROVAL_PROTOCOL: &str = "verified.contract-approval/1";

/// COSE algorithm identifiers this version supports.
const ES256: &str = "-7";
const EDDSA: &str = "-8";
const RS256: &str = "-257";

/// Base64url, as the browser returns it: padding optional, no other alphabet.
const BASE64URL: GeneralPurpose = GeneralPurpose::new(
    &URL_SAFE,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// The specification's code for the check an approval failed. Stable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalCode {
    /// A member is missing or of the wrong type, or a value cannot be read.
    Malformed,
    /// The snapshot's digest is not the statement's `shown`.
    SnapshotMismatch,
    /// The snapshot is of another contract than the statement's.
    SnapshotContract,
    /// The assertion was made with another passkey than the approval's key.
    OtherPasskey,
    /// The client data is not of a `webauthn.get` ceremony.
    Ceremony,
    /// The assertion is for another challenge: the statement was changed.
    Challenge,
    /// The assertion comes from an origin the relying party does not accept.
    Origin,
    /// The assertion is for another relying party.
    RelyingParty,
    /// The authenticator did not see the user present.
    UserNotPresent,
    /// The key's algorithm is not ES256, `EdDSA` or RS256.
    UnsupportedAlgorithm,
    /// The signature does not verify under the key.
    Signature,
}

impl ApprovalCode {
    /// The code as the specification writes it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "MALFORMED",
            Self::SnapshotMismatch => "SNAPSHOT_MISMATCH",
            Self::SnapshotContract => "SNAPSHOT_CONTRACT",
            Self::OtherPasskey => "OTHER_PASSKEY",
            Self::Ceremony => "CEREMONY",
            Self::Challenge => "CHALLENGE",
            Self::Origin => "ORIGIN",
            Self::RelyingParty => "RELYING_PARTY",
            Self::UserNotPresent => "USER_NOT_PRESENT",
            Self::UnsupportedAlgorithm => "UNSUPPORTED_ALGORITHM",
            Self::Signature => "SIGNATURE",
        }
    }
}

impl fmt::Display for ApprovalCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why an approval was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {detail}")]
pub struct ApprovalRefusal {
    /// The specification's code for the failed check. Stable.
    pub code: ApprovalCode,
    /// A description for people. Not stable; do not match on it.
    pub detail: String,
}

type Checked<T> = Result<T, ApprovalRefusal>;

fn refuse<T>(code: ApprovalCode, detail: impl Into<String>) -> Checked<T> {
    Err(ApprovalRefusal {
        code,
        detail: detail.into(),
    })
}

/// The signed statement: exactly these members, each a string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    /// The tenant the approval was made in.
    pub tenant: String,
    /// The repository whose contract was approved.
    pub repository: String,
    /// The digest of the approved contract's canonical text.
    pub contract: String,
    /// The digest of the snapshot of what the approver was shown.
    pub shown: String,
    /// The approver, as the service names them.
    pub approver: String,
    /// When the service issued the statement. Not checked.
    pub issued_at: String,
    /// The service's nonce. Not checked.
    pub nonce: String,
    value: Value,
}

impl Statement {
    /// The statement as a value: what its challenge is computed over.
    #[must_use]
    pub fn value(&self) -> &Value {
        &self.value
    }

    /// The `WebAuthn` challenge for this statement: the SHA-256 of its
    /// canonical bytes.
    #[must_use]
    pub fn challenge(&self) -> Sha256Digest {
        self.value.digest()
    }
}

/// A valid approval: the statement it signs, and the algorithm of the key
/// that signed it. See the module documentation for what that establishes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Approved {
    /// The statement.
    pub statement: Statement,
    /// The key's COSE algorithm: `-7`, `-8` or `-257`.
    pub algorithm: i64,
}

/// In canonical order, as [`Object::has_exactly`] takes them.
const STATEMENT_MEMBERS: [&str; 8] = [
    "approver",
    "contract",
    "issuedAt",
    "nonce",
    "repository",
    "shown",
    "tenant",
    "type",
];

fn malformed<T>(detail: impl Into<String>) -> Checked<T> {
    refuse(ApprovalCode::Malformed, detail)
}

fn member<'a>(object: &'a Object, name: &str, of: &str) -> Checked<&'a Value> {
    match object.get(name) {
        Some(value) => Ok(value),
        None => malformed(format!("{of} has no {name}")),
    }
}

fn text<'a>(object: &'a Object, name: &str, of: &str) -> Checked<&'a str> {
    match member(object, name, of)?.as_str() {
        Some(text) => Ok(text),
        None => malformed(format!("{of}'s {name} is not a string")),
    }
}

fn object<'a>(value: &'a Value, of: &str) -> Checked<&'a Object> {
    match value.as_object() {
        Some(object) => Ok(object),
        None => malformed(format!("{of} is not an object")),
    }
}

fn statement(value: &Value) -> Checked<Statement> {
    let object = object(value, "the statement")?;
    if !object.has_exactly(&STATEMENT_MEMBERS) {
        return malformed("the statement does not have exactly the eight members of version 1");
    }
    let field = |name| text(object, name, "the statement").map(str::to_owned);
    if field("type")? != APPROVAL_PROTOCOL {
        return malformed(format!("the statement's type is not {APPROVAL_PROTOCOL}"));
    }
    Ok(Statement {
        tenant: field("tenant")?,
        repository: field("repository")?,
        contract: field("contract")?,
        shown: field("shown")?,
        approver: field("approver")?,
        issued_at: field("issuedAt")?,
        nonce: field("nonce")?,
        value: value.clone(),
    })
}

fn decode(encoded: &str, what: &str) -> Checked<Vec<u8>> {
    match BASE64URL.decode(encoded) {
        Ok(bytes) => Ok(bytes),
        Err(_) => malformed(format!("{what} is not base64url")),
    }
}

/// Checks an approval file, as the relying party for `rp_id` that accepts
/// assertions from `origins`.
///
/// # Errors
///
/// The first of the specification's checks that the approval fails, with its
/// code.
pub fn verify_approval(bytes: &[u8], rp_id: &str, origins: &[String]) -> Checked<Approved> {
    // Step 1: the members and their types. The file is read with the
    // canonical reader, so a snapshot without a canonical form (step 2) is
    // refused here too, with the same code.
    let root = match parse(bytes, &Limits::DEFAULT) {
        Ok(value) => value,
        Err(error) => return malformed(format!("the approval cannot be read: {error}")),
    };
    let root = object(&root, "the approval")?;
    let statement = statement(member(root, "statement", "the approval")?)?;
    let assertion = object(member(root, "assertion", "the approval")?, "the assertion")?;
    let credential = text(assertion, "credentialId", "the assertion")?;
    let authenticator_data = text(assertion, "authenticatorData", "the assertion")?;
    let client_data = text(assertion, "clientDataJSON", "the assertion")?;
    let signature = text(assertion, "signature", "the assertion")?;
    let key = object(member(root, "key", "the approval")?, "the key")?;
    let key_credential = text(key, "credentialId", "the key")?;
    let public_key = text(key, "publicKey", "the key")?;
    let Some(algorithm) = member(key, "algorithm", "the key")?.as_integer() else {
        return malformed("the key's algorithm is not an integer");
    };
    let shown = member(root, "shown", "the approval")?;

    // Steps 3 and 4: the snapshot.
    let digest = format!("{}:{}", Sha256Digest::ALGORITHM, shown.digest().to_hex());
    if digest != statement.shown {
        return refuse(
            ApprovalCode::SnapshotMismatch,
            format!(
                "the snapshot's digest is {digest}, the statement names {}",
                statement.shown
            ),
        );
    }
    let of_contract = shown
        .as_object()
        .and_then(|o| o.get("contract"))
        .and_then(Value::as_str);
    if of_contract != Some(statement.contract.as_str()) {
        return refuse(
            ApprovalCode::SnapshotContract,
            "the snapshot is not of the contract the statement names",
        );
    }

    // Step 5: the passkey.
    if credential != key_credential {
        return refuse(
            ApprovalCode::OtherPasskey,
            "the assertion was made with another passkey than the approval's key",
        );
    }

    // Step 6: decoding.
    let authenticator_data = decode(authenticator_data, "authenticatorData")?;
    let client_data = decode(client_data, "clientDataJSON")?;
    let signature = decode(signature, "the signature")?;
    let public_key = decode(public_key, "the public key")?;

    // Steps 7 to 10: the client data.
    check_client_data(&client_data, &statement.challenge(), origins)?;

    // Steps 11 to 13: the authenticator data.
    if authenticator_data.len() < 37 {
        return malformed("the authenticator data is shorter than 37 bytes");
    }
    if authenticator_data[..32] != *Sha256Digest::of(rp_id.as_bytes()).as_bytes() {
        return refuse(
            ApprovalCode::RelyingParty,
            format!("the assertion is not for the relying party {rp_id}"),
        );
    }
    if authenticator_data[32] & 0x01 == 0 {
        return refuse(
            ApprovalCode::UserNotPresent,
            "the user-present flag is not set",
        );
    }

    // Steps 14 and 15: the signature over the authenticator data and the
    // digest of the client data.
    let mut message = authenticator_data;
    message.extend_from_slice(Sha256Digest::of(&client_data).as_bytes());
    let (verified, algorithm) = match algorithm.as_str() {
        ES256 => (es256(&public_key, &message, &signature), -7),
        EDDSA => (eddsa(&public_key, &message, &signature), -8),
        RS256 => (rs256(&public_key, &message, &signature), -257),
        other => {
            return refuse(
                ApprovalCode::UnsupportedAlgorithm,
                format!("algorithm {other} is not ES256 (-7), EdDSA (-8) or RS256 (-257)"),
            );
        }
    };
    if !verified {
        return refuse(
            ApprovalCode::Signature,
            "the signature does not verify under the key",
        );
    }
    Ok(Approved {
        statement,
        algorithm,
    })
}

fn check_client_data(bytes: &[u8], challenge: &Sha256Digest, origins: &[String]) -> Checked<()> {
    // Strict UTF-8: the canonical reader refuses anything else.
    let value = match parse(bytes, &Limits::DEFAULT) {
        Ok(value) => value,
        Err(error) => return malformed(format!("clientDataJSON is not UTF-8 JSON: {error}")),
    };
    let get = |name| {
        value
            .as_object()
            .and_then(|o| o.get(name))
            .and_then(Value::as_str)
    };
    if get("type") != Some("webauthn.get") {
        return refuse(
            ApprovalCode::Ceremony,
            "the client data is not of a webauthn.get ceremony",
        );
    }
    if get("challenge") != Some(URL_SAFE_NO_PAD.encode(challenge.as_bytes()).as_str()) {
        return refuse(
            ApprovalCode::Challenge,
            "the assertion is for another challenge than this statement's",
        );
    }
    match get("origin") {
        Some(origin) if origins.iter().any(|o| o == origin) => Ok(()),
        Some(origin) => refuse(
            ApprovalCode::Origin,
            format!("the assertion comes from {origin}, which is not accepted"),
        ),
        None => refuse(ApprovalCode::Origin, "the client data names no origin"),
    }
}

fn es256(spki: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = p256::ecdsa::VerifyingKey::from_public_key_der(spki) else {
        return false;
    };
    p256::ecdsa::DerSignature::try_from(signature)
        .is_ok_and(|signature| key.verify(message, &signature).is_ok())
}

/// Strict, as every Ed25519 signature in this tool (decision 0009).
fn eddsa(spki: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let key = spki
        .strip_prefix(&SPKI_PREFIX)
        .and_then(|rest| <[u8; 32]>::try_from(rest).ok())
        .and_then(|bytes| Ed25519Key::from_bytes(&bytes).ok())
        .filter(|key| !key.is_weak());
    let signature = Ed25519Signature::from_slice(signature).ok();
    match (key, signature) {
        (Some(key), Some(signature)) => key.verify_strict(message, &signature).is_ok(),
        _ => false,
    }
}

fn rs256(spki: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use rsa::signature::Verifier as _;
    let Ok(key) = rsa::RsaPublicKey::from_public_key_der(spki) else {
        return false;
    };
    let key = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(key);
    rsa::pkcs1v15::Signature::try_from(signature)
        .is_ok_and(|signature| key.verify(message, &signature).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_accepts_padding_or_none_and_no_other_alphabet() {
        assert_eq!(BASE64URL.decode("-_8").ok(), Some(vec![0xfb, 0xff]));
        assert_eq!(BASE64URL.decode("-_8=").ok(), Some(vec![0xfb, 0xff]));
        assert!(BASE64URL.decode("+/8").is_err());
        assert!(BASE64URL.decode("-_8 ").is_err());
    }

    #[test]
    fn an_unpaired_surrogate_is_malformed_not_a_panic() {
        let approval = br#"{"statement":{"approver":"\ud800","contract":"c","issuedAt":"t","nonce":"n","repository":"r","shown":"s","tenant":"t","type":"verified.contract-approval/1"},"assertion":{},"key":{},"shown":{}}"#;
        let refusal = verify_approval(approval, "rp", &[]).map_err(|r| r.code);
        assert_eq!(refusal, Err(ApprovalCode::Malformed));
        let challenge = Sha256Digest::of(b"statement");
        let client = br#"{"type":"webauthn.get","challenge":"\udc00","origin":"https://x"}"#;
        let refusal = check_client_data(client, &challenge, &[]).map_err(|r| r.code);
        assert_eq!(refusal, Err(ApprovalCode::Malformed));
    }

    #[test]
    fn client_data_must_be_utf8() {
        let challenge = Sha256Digest::of(b"statement");
        let mut bytes = br#"{"type":"webauthn.get","origin":"https://x","challenge":""#.to_vec();
        bytes.extend_from_slice(URL_SAFE_NO_PAD.encode(challenge.as_bytes()).as_bytes());
        bytes.extend_from_slice(b"\",\"note\":\"\xff\"}");
        let refusal = check_client_data(&bytes, &challenge, &["https://x".to_owned()]);
        assert_eq!(refusal.map_err(|r| r.code), Err(ApprovalCode::Malformed));
    }

    #[test]
    fn client_data_of_another_ceremony_or_origin_is_refused() {
        let challenge = Sha256Digest::of(b"statement");
        let encoded = URL_SAFE_NO_PAD.encode(challenge.as_bytes());
        let client = |kind: &str, origin: &str| {
            format!(r#"{{"type":"{kind}","challenge":"{encoded}","origin":"{origin}"}}"#)
        };
        let origins = ["https://x".to_owned()];
        let code = |bytes: String| {
            check_client_data(bytes.as_bytes(), &challenge, &origins).map_err(|r| r.code)
        };
        assert_eq!(code(client("webauthn.get", "https://x")), Ok(()));
        assert_eq!(
            code(client("webauthn.create", "https://x")),
            Err(ApprovalCode::Ceremony)
        );
        assert_eq!(
            code(client("webauthn.get", "https://y")),
            Err(ApprovalCode::Origin)
        );
    }
}
