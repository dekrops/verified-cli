//! Builds synthetic package containers for tests.
//!
//! Nothing here is real protocol data: component contents are placeholders,
//! which is enough for the container checks (they commit to content without
//! interpreting it). Shared with the CLI's tests by path.
#![allow(dead_code, unreachable_pub)]

use verified_canonical::{Limits, Object, Value, parse};

pub const PATHS: [&str; 6] = [
    "claim.json",
    "contract.json",
    "decision.json",
    "evidence/bodies.json",
    "evidence/statements.json",
    "inputs.json",
];

pub fn json(text: &str) -> Value {
    parse(text.as_bytes(), &Limits::DEFAULT).expect("test JSON parses")
}

pub fn object<const N: usize>(members: [(&str, Value); N]) -> Value {
    Value::Object(
        members
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect::<Object>(),
    )
}

pub fn string(text: impl Into<String>) -> Value {
    Value::String(text.into())
}

pub fn hash(value: &Value) -> Value {
    object([
        ("algorithm", string("sha-256")),
        ("hex", string(value.digest().to_hex())),
    ])
}

/// A package under construction. Every field is free to be made wrong.
#[derive(Clone)]
pub struct Draft {
    pub protocol: Value,
    pub package_version: Value,
    pub canonical_version: Value,
    /// `(path, content)` as carried in `files`.
    pub files: Vec<(Value, Value)>,
    /// `(path, hash)` as listed in the manifest; `None` derives them from `files`.
    pub manifest_files: Option<Vec<(Value, Value)>>,
    /// `None` derives the commitment from the manifest.
    pub package_commitment: Option<Value>,
    /// `None` derives the identifier from the manifest.
    pub package_id: Option<Value>,
    pub signatures: Value,
}

impl Draft {
    /// A package that passes every container check.
    pub fn consistent(protocol: &str) -> Self {
        Self {
            protocol: string(protocol),
            package_version: Value::Integer(2.into()),
            canonical_version: string("verified-json-v1"),
            files: PATHS
                .iter()
                .map(|path| (string(*path), object([("synthetic", string(*path))])))
                .collect(),
            manifest_files: None,
            package_commitment: None,
            package_id: None,
            signatures: Value::Array(Vec::new()),
        }
    }

    pub fn manifest(&self) -> Value {
        let listed = self.manifest_files.clone().unwrap_or_else(|| {
            self.files
                .iter()
                .map(|(path, content)| (path.clone(), hash(content)))
                .collect()
        });
        object([
            ("canonicalVersion", self.canonical_version.clone()),
            (
                "files",
                Value::Array(
                    listed
                        .into_iter()
                        .map(|(path, hash)| object([("hash", hash), ("path", path)]))
                        .collect(),
                ),
            ),
            ("packageVersion", self.package_version.clone()),
            ("protocol", self.protocol.clone()),
        ])
    }

    pub fn value(&self) -> Value {
        let manifest = self.manifest();
        let commitment = manifest.digest().to_hex();
        object([
            (
                "files",
                Value::Array(
                    self.files
                        .iter()
                        .map(|(path, content)| {
                            object([("content", content.clone()), ("path", path.clone())])
                        })
                        .collect(),
                ),
            ),
            (
                "packageCommitment",
                self.package_commitment
                    .clone()
                    .unwrap_or_else(|| hash(&manifest)),
            ),
            (
                "packageId",
                self.package_id
                    .clone()
                    .unwrap_or_else(|| string(format!("wvp:sha-256:{commitment}"))),
            ),
            ("signatures", self.signatures.clone()),
            ("manifest", manifest),
        ])
    }

    /// The package text, canonical.
    pub fn text(&self) -> String {
        self.value().to_canonical_string()
    }
}
