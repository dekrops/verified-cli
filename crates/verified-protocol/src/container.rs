// SPDX-License-Identifier: Apache-2.0

//! The package container: the outer object every WVP package is.
//!
//! ```text
//! { files, manifest, packageCommitment, packageId, signatures }
//! ```
//!
//! [`Container::from_value`] checks shape only: exactly these members, of
//! these types. It does not check that the component set is the protocol's,
//! that any digest matches, or that the versions are supported. Those are
//! separate checks with their own refusal codes, and their order is the
//! verifier's to keep.

use std::fmt;

use verified_canonical::{Integer, Object, Sha256Digest, Value};

/// A digest as a package states it: `{ algorithm, hex }`, both unchecked.
///
/// A package is untrusted, so the stated algorithm and spelling are kept as
/// written until a check compares them with a computed [`Sha256Digest`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireDigest<'a> {
    /// The stated algorithm.
    pub algorithm: &'a str,
    /// The stated digest text.
    pub hex: &'a str,
}

impl WireDigest<'_> {
    /// Whether this states exactly `digest`: the algorithm `sha-256` and the
    /// same 64 lowercase hexadecimal characters.
    #[must_use]
    pub fn states(&self, digest: &Sha256Digest) -> bool {
        self.algorithm == Sha256Digest::ALGORITHM && self.hex.parse().as_ref() == Ok(digest)
    }
}

/// The identifier of a package: `wvp:sha-256:<hex of the package commitment>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PackageId(Sha256Digest);

impl PackageId {
    /// The identifier that follows from a package commitment.
    #[must_use]
    pub const fn from_commitment(commitment: Sha256Digest) -> Self {
        Self(commitment)
    }

    /// The package commitment this identifier names.
    #[must_use]
    pub const fn commitment(&self) -> &Sha256Digest {
        &self.0
    }
}

/// The text is not `wvp:sha-256:` followed by 64 lowercase hexadecimal
/// characters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("a package identifier is wvp:sha-256: followed by 64 lowercase hexadecimal characters")]
pub struct PackageIdParseError;

impl std::str::FromStr for PackageId {
    type Err = PackageIdParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        text.strip_prefix(Self::PREFIX)
            .and_then(|hex| hex.parse().ok())
            .map(Self)
            .ok_or(PackageIdParseError)
    }
}

impl PackageId {
    /// What every package identifier starts with.
    pub const PREFIX: &'static str = "wvp:sha-256:";
}

impl fmt::Display for PackageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wvp:sha-256:{}", self.0)
    }
}

/// The versions a manifest declares, read leniently.
///
/// The protocol checks versions before it checks shape, so this reads only
/// what is there and never fails: an absent or mistyped member is `None`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeclaredVersion<'a> {
    /// `manifest.packageVersion`, if it is an integer.
    pub package_version: Option<&'a Integer>,
    /// `manifest.protocol`, if it is a string.
    pub protocol: Option<&'a str>,
    /// `manifest.canonicalVersion`, if it is a string.
    pub canonical_version: Option<&'a str>,
}

impl<'a> DeclaredVersion<'a> {
    /// Reads the declared versions of a package.
    #[must_use]
    pub fn of(package: &'a Value) -> Self {
        let manifest = package
            .as_object()
            .and_then(|p| p.get("manifest"))
            .and_then(Value::as_object);
        let member = |name| manifest.and_then(|m| m.get(name));
        Self {
            package_version: member("packageVersion").and_then(Value::as_integer),
            protocol: member("protocol").and_then(Value::as_str),
            canonical_version: member("canonicalVersion").and_then(Value::as_str),
        }
    }
}

/// One entry of `files`: a component's path and content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Component<'a> {
    /// The stated path.
    pub path: &'a str,
    /// The component's JSON content.
    pub content: &'a Value,
}

/// One entry of `manifest.files`: a component's path and stated digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManifestEntry<'a> {
    /// The stated path.
    pub path: &'a str,
    /// The stated digest of the component's canonical content.
    pub hash: WireDigest<'a>,
}

/// An issuer signature over the decision, as carried. Not verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IssuerSignature<'a> {
    /// The stated signature scheme.
    pub scheme: &'a str,
    /// The identifier of the key said to have signed.
    pub key_id: &'a str,
    /// The encoded signature.
    pub encoded: &'a str,
}

/// A package container of the right shape, borrowed from its parsed value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Container<'a> {
    /// The manifest, whole: the package commitment is its digest.
    pub manifest: &'a Value,
    /// `manifest.files`, in stated order.
    pub manifest_files: Vec<ManifestEntry<'a>>,
    /// `files`, in stated order.
    pub files: Vec<Component<'a>>,
    /// `packageCommitment`, as stated.
    pub package_commitment: WireDigest<'a>,
    /// `packageId`, as stated.
    pub package_id: &'a str,
    /// `signatures`, in stated order.
    pub signatures: Vec<IssuerSignature<'a>>,
}

/// What is wrong with a value's shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ShapeProblem {
    /// An object was required.
    #[error("is not an object")]
    NotAnObject,
    /// An array was required.
    #[error("is not an array")]
    NotAnArray,
    /// A string was required.
    #[error("is not a string")]
    NotAString,
    /// An integer was required.
    #[error("is not an integer")]
    NotAnInteger,
    /// The object's members are not exactly the ones listed.
    #[error("does not have exactly the members {0:?}")]
    Members(&'static [&'static str]),
    /// The value is not one of the listed enumeration cases.
    #[error("is not one of the cases {0:?}")]
    Case(&'static [&'static str]),
    /// The value is not what the protocol requires here.
    #[error("is not {0}")]
    Not(&'static str),
    /// Two parts of a component that must agree do not.
    #[error("{0}")]
    Inconsistent(&'static str),
}

/// A package that does not have the container's shape.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{location} {problem}")]
pub struct ShapeError {
    /// Where in the package, as a path such as `manifest.files[2].hash`.
    pub location: String,
    /// What is wrong there.
    pub problem: ShapeProblem,
}

type Shape<T> = Result<T, ShapeError>;

fn fail<T>(location: &str, problem: ShapeProblem) -> Shape<T> {
    Err(ShapeError {
        location: location.to_owned(),
        problem,
    })
}

/// The object at `location`, with exactly `members` (given in canonical order).
fn object<'a>(
    value: &'a Value,
    location: &str,
    members: &'static [&'static str],
) -> Shape<&'a Object> {
    let Some(object) = value.as_object() else {
        return fail(location, ShapeProblem::NotAnObject);
    };
    if object.has_exactly(members) {
        Ok(object)
    } else {
        fail(location, ShapeProblem::Members(members))
    }
}

/// A member [`object`] has already shown to be present.
fn member<'a>(object: &'a Object, name: &str) -> &'a Value {
    object.get(name).unwrap_or(&Value::Null)
}

fn string<'a>(object: &'a Object, location: &str, name: &str) -> Shape<&'a str> {
    match member(object, name).as_str() {
        Some(s) => Ok(s),
        None => fail(&format!("{location}.{name}"), ShapeProblem::NotAString),
    }
}

fn array<'a>(object: &'a Object, location: &str, name: &str) -> Shape<&'a [Value]> {
    match member(object, name).as_array() {
        Some(a) => Ok(a),
        None => fail(&format!("{location}.{name}"), ShapeProblem::NotAnArray),
    }
}

fn digest<'a>(value: &'a Value, location: &str) -> Shape<WireDigest<'a>> {
    let object = object(value, location, &["algorithm", "hex"])?;
    Ok(WireDigest {
        algorithm: string(object, location, "algorithm")?,
        hex: string(object, location, "hex")?,
    })
}

impl<'a> Container<'a> {
    /// Reads a container, refusing any missing, extra or mistyped member.
    pub fn from_value(package: &'a Value) -> Result<Self, ShapeError> {
        const ROOT: &str = "package";
        let root = object(
            package,
            ROOT,
            &[
                "files",
                "manifest",
                "packageCommitment",
                "packageId",
                "signatures",
            ],
        )?;

        let manifest = member(root, "manifest");
        let manifest_object = object(
            manifest,
            "manifest",
            &["canonicalVersion", "files", "packageVersion", "protocol"],
        )?;
        string(manifest_object, "manifest", "canonicalVersion")?;
        string(manifest_object, "manifest", "protocol")?;
        if member(manifest_object, "packageVersion")
            .as_integer()
            .is_none()
        {
            return fail("manifest.packageVersion", ShapeProblem::NotAnInteger);
        }
        let manifest_files = array(manifest_object, "manifest", "files")?
            .iter()
            .enumerate()
            .map(|(i, entry)| {
                let location = format!("manifest.files[{i}]");
                let entry = object(entry, &location, &["hash", "path"])?;
                Ok(ManifestEntry {
                    path: string(entry, &location, "path")?,
                    hash: digest(member(entry, "hash"), &format!("{location}.hash"))?,
                })
            })
            .collect::<Shape<Vec<_>>>()?;

        let files = array(root, ROOT, "files")?
            .iter()
            .enumerate()
            .map(|(i, file)| {
                let location = format!("files[{i}]");
                let file = object(file, &location, &["content", "path"])?;
                Ok(Component {
                    path: string(file, &location, "path")?,
                    content: member(file, "content"),
                })
            })
            .collect::<Shape<Vec<_>>>()?;

        let signatures = array(root, ROOT, "signatures")?
            .iter()
            .enumerate()
            .map(|(i, signature)| {
                let location = format!("signatures[{i}]");
                let signature = object(signature, &location, &["encoded", "keyId", "scheme"])?;
                Ok(IssuerSignature {
                    scheme: string(signature, &location, "scheme")?,
                    key_id: string(signature, &location, "keyId")?,
                    encoded: string(signature, &location, "encoded")?,
                })
            })
            .collect::<Shape<Vec<_>>>()?;

        Ok(Self {
            manifest,
            manifest_files,
            files,
            package_commitment: digest(member(root, "packageCommitment"), "packageCommitment")?,
            package_id: string(root, ROOT, "packageId")?,
            signatures,
        })
    }
}

#[cfg(test)]
mod tests {
    use verified_canonical::{Limits, parse};

    use super::*;

    const HEX: &str = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

    fn value(json: &str) -> Value {
        parse(json.as_bytes(), &Limits::DEFAULT).expect("test JSON parses")
    }

    /// A container of the right shape. Its digests are not consistent, which
    /// shape checking must not care about.
    fn well_shaped() -> String {
        format!(
            r#"{{
              "files": [{{"content": {{"any": [1, null]}}, "path": "claim.json"}}],
              "manifest": {{
                "canonicalVersion": "verified-json-v1",
                "files": [{{"hash": {{"algorithm": "sha-256", "hex": "{HEX}"}}, "path": "claim.json"}}],
                "packageVersion": 2,
                "protocol": "wvp-0.2"
              }},
              "packageCommitment": {{"algorithm": "sha-256", "hex": "{HEX}"}},
              "packageId": "wvp:sha-256:{HEX}",
              "signatures": [{{"encoded": "AA==", "keyId": "k", "scheme": "Ed25519"}}]
            }}"#
        )
    }

    fn shape_error(json: &str) -> ShapeError {
        Container::from_value(&value(json)).expect_err("should be refused")
    }

    #[test]
    fn reads_a_well_shaped_container() {
        let package = value(&well_shaped());
        let container = Container::from_value(&package).expect("well shaped");
        assert_eq!(container.files.len(), 1);
        assert_eq!(container.files[0].path, "claim.json");
        assert_eq!(container.manifest_files[0].hash.hex, HEX);
        assert_eq!(container.package_commitment.algorithm, "sha-256");
        assert_eq!(container.package_id, format!("wvp:sha-256:{HEX}"));
        assert_eq!(
            container.signatures,
            [IssuerSignature {
                scheme: "Ed25519",
                key_id: "k",
                encoded: "AA=="
            }]
        );
        assert_eq!(container.manifest.as_object().map(Object::len), Some(4));
    }

    #[test]
    fn refuses_extra_missing_and_mistyped_members_with_their_location() {
        let base = well_shaped();
        let cases: [(&str, &str, &str, ShapeProblem); 9] = [
            (
                "\"signatures\": [",
                "\"extra\": 1, \"signatures\": [",
                "package",
                MEMBERS_ROOT,
            ),
            (
                "\"packageId\": \"wvp:sha-256:",
                "\"packageID\": \"wvp:sha-256:",
                "package",
                MEMBERS_ROOT,
            ),
            (
                "\"protocol\": \"wvp-0.2\"",
                "\"protocol\": \"wvp-0.2\", \"x\": 1",
                "manifest",
                MEMBERS_MANIFEST,
            ),
            (
                "\"packageVersion\": 2",
                "\"packageVersion\": \"2\"",
                "manifest.packageVersion",
                ShapeProblem::NotAnInteger,
            ),
            (
                "\"path\": \"claim.json\"}],\n              \"manifest\"",
                "\"path\": 7}],\n              \"manifest\"",
                "files[0].path",
                ShapeProblem::NotAString,
            ),
            (
                "{\"algorithm\": \"sha-256\", \"hex\": \"44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a\"}, \"path\"",
                "\"sha-256\", \"path\"",
                "manifest.files[0].hash",
                ShapeProblem::NotAnObject,
            ),
            (
                "\"signatures\": [{\"encoded\": \"AA==\", \"keyId\": \"k\", \"scheme\": \"Ed25519\"}]",
                "\"signatures\": {}",
                "package.signatures",
                ShapeProblem::NotAnArray,
            ),
            ("\"keyId\": \"k\", ", "", "signatures[0]", MEMBERS_SIGNATURE),
            (
                "\"encoded\": \"AA==\"",
                "\"encoded\": null",
                "signatures[0].encoded",
                ShapeProblem::NotAString,
            ),
        ];
        for (from, to, location, problem) in cases {
            assert!(base.contains(from), "test fixture lacks {from:?}");
            let err = shape_error(&base.replacen(from, to, 1));
            assert_eq!(
                (err.location.as_str(), err.problem),
                (location, problem),
                "{to}"
            );
        }
        assert_eq!(shape_error("[]").problem, ShapeProblem::NotAnObject);
    }

    const MEMBERS_ROOT: ShapeProblem = ShapeProblem::Members(&[
        "files",
        "manifest",
        "packageCommitment",
        "packageId",
        "signatures",
    ]);
    const MEMBERS_MANIFEST: ShapeProblem =
        ShapeProblem::Members(&["canonicalVersion", "files", "packageVersion", "protocol"]);
    const MEMBERS_SIGNATURE: ShapeProblem = ShapeProblem::Members(&["encoded", "keyId", "scheme"]);

    #[test]
    fn declared_version_reads_what_is_there_and_never_fails() {
        let package = value(&well_shaped());
        let declared = DeclaredVersion::of(&package);
        assert_eq!(declared.package_version.and_then(Integer::to_i64), Some(2));
        assert_eq!(declared.protocol, Some("wvp-0.2"));
        assert_eq!(declared.canonical_version, Some("verified-json-v1"));

        for json in [
            "null",
            "[]",
            "{}",
            r#"{"manifest":[]}"#,
            r#"{"manifest":{"protocol":2}}"#,
        ] {
            let package = value(json);
            let declared = DeclaredVersion::of(&package);
            assert_eq!(
                (
                    declared.package_version,
                    declared.protocol,
                    declared.canonical_version
                ),
                (None, None, None),
                "{json}"
            );
        }
    }

    #[test]
    fn a_wire_digest_states_a_digest_only_exactly() {
        let digest = Sha256Digest::of(b"{}");
        assert_eq!(digest.to_hex(), HEX);
        assert!(
            WireDigest {
                algorithm: "sha-256",
                hex: HEX
            }
            .states(&digest)
        );
        let upper = HEX.to_uppercase();
        for (algorithm, hex) in [
            ("sha-256", &HEX[1..]),
            ("SHA-256", HEX),
            ("sha256", HEX),
            ("sha-256", upper.as_str()),
        ] {
            assert!(
                !WireDigest { algorithm, hex }.states(&digest),
                "{algorithm} {hex}"
            );
        }
    }

    #[test]
    fn a_package_id_is_spelled_from_its_commitment() {
        let id = PackageId::from_commitment(Sha256Digest::of(b"{}"));
        assert_eq!(id.to_string(), format!("wvp:sha-256:{HEX}"));
        assert_eq!(id.commitment().to_hex(), HEX);
    }
}
