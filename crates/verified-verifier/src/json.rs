//! Building the JSON values a verifier recomputes.

use verified_canonical::{Object, Sha256Digest, Value};

pub(crate) fn text(s: &str) -> Value {
    Value::String(s.to_owned())
}

pub(crate) fn object<const N: usize>(members: [(&str, Value); N]) -> Value {
    Value::Object(
        members
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect::<Object>(),
    )
}

/// A digest in wire form: `{ algorithm, hex }`.
pub(crate) fn digest(digest: &Sha256Digest) -> Value {
    object([
        ("algorithm", text(Sha256Digest::ALGORITHM)),
        ("hex", text(&digest.to_hex())),
    ])
}

/// An identifier in wire form: `{ value }`.
pub(crate) fn wrapped(value: &str) -> Value {
    object([("value", text(value))])
}
