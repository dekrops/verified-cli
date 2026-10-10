// SPDX-License-Identifier: Apache-2.0

//! The container checks: protocol steps 1 to 6.

use verified_canonical::{
    CANONICAL_VERSION, Integer, LimitExceeded, Limits, Value, parse_canonical,
};
use verified_protocol::{
    ComponentPath, Container, DeclaredVersion, IssuerSignature, PACKAGE_VERSION, PackageId,
    ProtocolVersion, RefusalCode,
};

use crate::report::{ComponentCommitment, Expectations};
use crate::trust::Trust;

/// Which protocol version a package must declare.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProtocolSelection {
    /// Any version this verifier supports; the report names the one found.
    #[default]
    Detect,
    /// Exactly this version. A package of another is refused, as the
    /// protocol requires of a verifier for one version.
    Require(ProtocolVersion),
}

/// How to verify.
#[derive(Clone, Debug, Default)]
pub struct Options<'a> {
    /// Resource bounds for reading the package.
    pub limits: Limits,
    /// Which protocol version to accept.
    pub protocol: ProtocolSelection,
    /// The relying party's trust registry. Without one, verification stops
    /// once package integrity is established: no signature is checked and no
    /// decision is reproduced. Keys carried by a package are never trusted.
    pub trust: Option<&'a Trust>,
    /// What the relying party expects the package to be about.
    pub expectations: Expectations,
    /// A work record the relying party holds (`wvp-0.2`): a record of one
    /// verification, as JSON. If given, the package must be the one the
    /// record is about, member for member, or it is refused.
    pub record: Option<&'a Value>,
}

/// A protocol refusal: the first check the package failed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {detail}")]
pub struct Refusal {
    /// The protocol's code for the failed check. Stable.
    pub code: RefusalCode,
    /// A description for people. Not stable; do not match on it.
    pub detail: String,
}

/// Why there is no report.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Rejection {
    /// The package failed a protocol check.
    #[error("refused: {0}")]
    Refused(#[from] Refusal),
    /// The package exceeds a resource limit of this verifier. This is not a
    /// protocol refusal: the package was not examined, and another verifier
    /// with other limits may accept it.
    #[error("not examined: the package exceeds a resource limit: {0}")]
    Limit(#[from] LimitExceeded),
    /// Expectations were given for a protocol version that does not define
    /// them. Ignoring them would report more than was checked, so nothing
    /// is reported.
    #[error("not examined: {0} does not define relying-party expectations")]
    ExpectationsUndefined(ProtocolVersion),
    /// A work record was given for a protocol version that does not define
    /// one. Ignoring it would report more than was checked.
    #[error("not examined: {0} does not define work records")]
    RecordUndefined(ProtocolVersion),
}

pub(crate) fn refusal(code: RefusalCode, detail: impl Into<String>) -> Refusal {
    Refusal {
        code,
        detail: detail.into(),
    }
}

fn refuse<T>(code: RefusalCode, detail: impl Into<String>) -> Result<T, Rejection> {
    Err(Rejection::Refused(refusal(code, detail)))
}

/// Step 2. Versions are read before the shape is checked, so that a package
/// of an unknown version is refused as such whatever else it contains.
fn supported_version(
    package: &Value,
    selection: ProtocolSelection,
) -> Result<ProtocolVersion, Rejection> {
    let declared = DeclaredVersion::of(package);
    if declared.package_version.and_then(Integer::to_i64) != Some(PACKAGE_VERSION) {
        return refuse(
            RefusalCode::UnsupportedVersion,
            format!("manifest.packageVersion is not {PACKAGE_VERSION}"),
        );
    }
    let protocol = match (
        declared.protocol.map(str::parse::<ProtocolVersion>),
        selection,
    ) {
        (Some(Ok(found)), ProtocolSelection::Detect) => found,
        (Some(Ok(found)), ProtocolSelection::Require(required)) if found == required => found,
        (Some(Ok(found)), ProtocolSelection::Require(required)) => {
            return refuse(
                RefusalCode::UnsupportedVersion,
                format!("the package is {found}, not {required}"),
            );
        }
        (Some(Err(unknown)), _) => {
            return refuse(RefusalCode::UnsupportedVersion, unknown.to_string());
        }
        (None, _) => {
            return refuse(
                RefusalCode::UnsupportedVersion,
                "manifest.protocol is not stated",
            );
        }
    };
    if declared.canonical_version != Some(CANONICAL_VERSION) {
        return refuse(
            RefusalCode::UnsupportedVersion,
            format!("manifest.canonicalVersion is not {CANONICAL_VERSION}"),
        );
    }
    Ok(protocol)
}

/// A package that passed the container checks, borrowed from its value.
pub(crate) struct Checked<'a> {
    pub(crate) protocol: ProtocolVersion,
    pub(crate) package_id: PackageId,
    pub(crate) components: [ComponentCommitment; 6],
    /// The component contents, in protocol order.
    pub(crate) files: [&'a Value; 6],
    pub(crate) signatures: Vec<IssuerSignature<'a>>,
}

/// Step 1: the text is the canonical encoding of a JSON value.
pub(crate) fn read(package: &[u8], limits: &Limits) -> Result<Value, Rejection> {
    match parse_canonical(package, limits) {
        Ok(value) => Ok(value),
        Err(error) => match error.limit() {
            Some(limit) => Err(Rejection::Limit(limit)),
            None => refuse(RefusalCode::NotCanonical, error.to_string()),
        },
    }
}

/// Steps 2 to 6, in protocol order, stopping at the first failure.
pub(crate) fn check(value: &Value, selection: ProtocolSelection) -> Result<Checked<'_>, Rejection> {
    // Step 2.
    let protocol = supported_version(value, selection)?;

    // Step 3.
    let container = match Container::from_value(value) {
        Ok(container) => container,
        Err(error) => return refuse(RefusalCode::MalformedComponent, error.to_string()),
    };

    // Step 4.
    let expected = ComponentPath::ALL.map(ComponentPath::as_str);
    if !container.files.iter().map(|f| f.path).eq(expected) {
        return refuse(
            RefusalCode::ComponentSet,
            "files are not the protocol's six components, in order",
        );
    }
    if !container.manifest_files.iter().map(|f| f.path).eq(expected) {
        return refuse(
            RefusalCode::ComponentSet,
            "manifest.files are not the protocol's six components, in order",
        );
    }

    // Step 5.
    let mut components = Vec::with_capacity(expected.len());
    let mut files = Vec::with_capacity(expected.len());
    for ((path, file), entry) in ComponentPath::ALL
        .into_iter()
        .zip(&container.files)
        .zip(&container.manifest_files)
    {
        let digest = file.content.digest();
        if !entry.hash.states(&digest) {
            return refuse(
                RefusalCode::ComponentDigest,
                format!("{path} is not the content its manifest entry commits to"),
            );
        }
        components.push(ComponentCommitment { path, digest });
        files.push(file.content);
    }
    let (Ok(components), Ok(files)) = (
        <[ComponentCommitment; 6]>::try_from(components),
        <[&Value; 6]>::try_from(files),
    ) else {
        // Unreachable after step 4; refused rather than assumed.
        return refuse(RefusalCode::ComponentSet, "fewer than six components");
    };

    // Step 6.
    let commitment = container.manifest.digest();
    if !container.package_commitment.states(&commitment) {
        return refuse(
            RefusalCode::CommitmentMismatch,
            "packageCommitment is not the digest of the manifest",
        );
    }
    let package_id = PackageId::from_commitment(commitment);
    if container.package_id != package_id.to_string() {
        return refuse(
            RefusalCode::CommitmentMismatch,
            "packageId does not follow from the package commitment",
        );
    }

    Ok(Checked {
        protocol,
        package_id,
        components,
        files,
        signatures: container.signatures,
    })
}
