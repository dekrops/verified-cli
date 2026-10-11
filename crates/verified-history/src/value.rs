// SPDX-License-Identifier: Apache-2.0

//! A reading as a JSON value, in the form the conformance vectors state.

use verified_canonical::{Integer, Object, Sha256Digest, Value};
use verified_protocol::relation::Reference;

use crate::{Reading, Standing};

fn object<const N: usize>(members: [(&str, Value); N]) -> Object {
    members
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect()
}

fn text(value: &str) -> Value {
    Value::String(value.to_owned())
}

fn wrapped(value: &str) -> Value {
    Value::Object(object([("value", text(value))]))
}

fn digest(value: &Sha256Digest) -> Value {
    Value::Object(object([
        ("algorithm", text(Sha256Digest::ALGORITHM)),
        ("hex", text(&value.to_hex())),
    ]))
}

fn reference(value: &Reference) -> Value {
    Value::Object(object([
        ("digest", digest(&value.digest)),
        ("kind", text(value.kind.as_str())),
    ]))
}

impl Reading {
    /// The reading as a JSON value: `records`, `relations`, `sameClaims`
    /// and `streams`, each in the order the specification gives.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let records = self.records.iter().map(|record| match record {
            Ok(held) => reference(held),
            Err(code) => Value::Object(object([("error", text(code))])),
        });
        let relations = self.relations.iter().map(|read| {
            let mut o = object([("standing", text(read.standing.as_str()))]);
            if let Some(relation) = read.relation {
                o.insert("relation", text(relation));
            }
            if let Some(source) = &read.source {
                o.insert("source", text(source));
            }
            if let Some(key_id) = &read.key_id {
                o.insert("keyId", text(key_id));
            }
            match &read.standing {
                Standing::Refused(code) | Standing::Contradicted(code) => {
                    o.insert("code", text(code));
                }
                Standing::Stated(absent) => {
                    o.insert(
                        "absent",
                        Value::Array(absent.iter().map(reference).collect()),
                    );
                }
                Standing::Checked => {}
            }
            Value::Object(o)
        });
        let same = self.same_claims.iter().map(|same| {
            Value::Object(object([
                ("agreement", digest(&same.agreement)),
                ("claim", digest(&same.claim)),
                ("package", digest(&same.package)),
                ("result", text(same.result)),
            ]))
        });
        let streams = self.streams.iter().map(|stream| {
            let mut o = object([
                ("completeness", text(stream.completeness)),
                ("issuer", wrapped(&stream.issuer)),
                ("stream", text(&stream.stream)),
                ("tenant", wrapped(&stream.tenant)),
            ]);
            if let Some(last) = stream.last {
                o.insert("last", Value::Integer(Integer::from(last)));
            }
            Value::Object(o)
        });
        Value::Object(object([
            ("records", Value::Array(records.collect())),
            ("relations", Value::Array(relations.collect())),
            ("sameClaims", Value::Array(same.collect())),
            ("streams", Value::Array(streams.collect())),
        ]))
    }
}
