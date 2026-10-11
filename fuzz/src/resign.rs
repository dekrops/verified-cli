// SPDX-License-Identifier: Apache-2.0

//! Signing again what the fuzzer changed.
//!
//! A fuzzer that changes a byte of a signed object breaks its signature, so
//! everything checked after a signature is reached only through the seeds.
//! The targets that use this module take, beside their usual input, the
//! private halves of the test keys the published corpus signs with
//! (`seedHex`, marked there as test-only). Before a check runs, every
//! signature made by one of those keys is computed again over the object as
//! the fuzzer left it. The check then sees authentic objects with arbitrary
//! content, which is what the logic after a signature has to withstand.
//!
//! Every signed object of Evidence Statement v1 and claim registration v1
//! has exactly two members: its content, named by kind, and `signature` or
//! `signatures`. A signature is `{ encoded, keyId, scheme }`, over the
//! kind's signing domain followed by the content's canonical text. Packages
//! are not re-signed: their contents are also committed to by digests,
//! which a change breaks first.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer as _, SigningKey};
use verified_canonical::{Object, SigningDomain, Value};
use verified_protocol::STATEMENT_DOMAIN;
use verified_protocol::registration::{
    AGREEMENT_DOMAIN, CLAIM_DOMAIN, CLOSURE_DOMAIN, DISPUTE_DOMAIN, DISPUTE_RECORD_DOMAIN,
    DISPUTE_TERMS_DOMAIN, NOTICE_DOMAIN, RECEIPT_DOMAIN, RESOLUTION_DOMAIN, RESPONSE_DOMAIN,
};

use crate::json;

/// The domain a signed object's content is signed under, by its member name.
fn domain(content: &str) -> Option<SigningDomain> {
    Some(match content {
        "statement" => STATEMENT_DOMAIN,
        "agreement" => AGREEMENT_DOMAIN,
        "claim" => CLAIM_DOMAIN,
        "receipt" => RECEIPT_DOMAIN,
        "closure" => CLOSURE_DOMAIN,
        "disputeRecord" => DISPUTE_RECORD_DOMAIN,
        "response" => RESPONSE_DOMAIN,
        "notice" => NOTICE_DOMAIN,
        "terms" => DISPUTE_TERMS_DOMAIN,
        "dispute" => DISPUTE_DOMAIN,
        "resolution" => RESOLUTION_DOMAIN,
        _ => return None,
    })
}

/// Test keys by key identifier.
pub struct Keys(BTreeMap<String, SigningKey>);

impl Keys {
    /// Reads `{ keyId: seedHex, … }`. Entries that are not a 32-byte seed in
    /// hexadecimal are left out; a line that is not such an object is no
    /// keys at all.
    pub fn from_line(line: &[u8]) -> Self {
        let value = json(line).unwrap_or(Value::Null);
        let keys = value
            .as_object()
            .map(|o| {
                o.iter()
                    .filter_map(|(id, seed)| Some((id.to_owned(), key(seed.as_str()?)?)))
                    .collect()
            })
            .unwrap_or_default();
        Self(keys)
    }

    /// The input with every line that is JSON signed again and written as
    /// canonical text. Other lines, empty ones among them, are kept as they
    /// are, so the input's structure survives.
    pub fn resign_lines(&self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        for (i, line) in crate::lines(data).enumerate() {
            if i > 0 {
                out.push(b'\n');
            }
            match json(line) {
                Some(value) => {
                    out.extend_from_slice(self.resign(&value).to_canonical_string().as_bytes())
                }
                None => out.extend_from_slice(line),
            }
        }
        out
    }

    /// The value with every signature by one of these keys made again over
    /// its object's present content. Inner objects are signed first, since
    /// an outer signature covers them.
    pub fn resign(&self, value: &Value) -> Value {
        match value {
            Value::Array(items) => Value::Array(items.iter().map(|v| self.resign(v)).collect()),
            Value::Object(object) => {
                let inner: Object = object
                    .iter()
                    .map(|(name, member)| (name.to_owned(), self.resign(member)))
                    .collect();
                Value::Object(self.signed(inner))
            }
            other => other.clone(),
        }
    }

    /// Signs `object` again if it is a signed object of a known kind.
    fn signed(&self, object: Object) -> Object {
        if object.len() != 2 {
            return object;
        }
        let is_signatures = |name: &str| name == "signature" || name == "signatures";
        let (Some(signatures), Some(content)) = (
            object.keys().find(|name| is_signatures(name)),
            object.keys().find(|name| !is_signatures(name)),
        ) else {
            return object;
        };
        let (Some(domain), Some(payload)) = (domain(content), object.get(content)) else {
            return object;
        };
        let input = domain.signing_input(payload);
        let Some(replaced) = object.get(signatures).map(|s| self.replace(s, &input)) else {
            return object;
        };
        let mut out = Object::new();
        for (name, member) in object.iter() {
            let member = if name == signatures {
                replaced.clone()
            } else {
                member.clone()
            };
            out.insert(name, member);
        }
        out
    }

    /// Every `{ encoded, keyId, scheme }` under `value` whose key is known,
    /// with `encoded` made again over `input`.
    fn replace(&self, value: &Value, input: &[u8]) -> Value {
        match value {
            Value::Array(items) => {
                Value::Array(items.iter().map(|v| self.replace(v, input)).collect())
            }
            Value::Object(o) if o.has_exactly(&["encoded", "keyId", "scheme"]) => {
                let key = o
                    .get("keyId")
                    .and_then(Value::as_str)
                    .and_then(|id| self.0.get(id));
                let Some(key) = key else { return value.clone() };
                let encoded = STANDARD.encode(key.sign(input).to_bytes());
                Value::Object(
                    o.iter()
                        .map(|(name, member)| {
                            let member = if name == "encoded" {
                                Value::String(encoded.clone())
                            } else {
                                member.clone()
                            };
                            (name.to_owned(), member)
                        })
                        .collect(),
                )
            }
            Value::Object(o) => Value::Object(
                o.iter()
                    .map(|(name, member)| (name.to_owned(), self.replace(member, input)))
                    .collect(),
            ),
            other => other.clone(),
        }
    }
}

fn key(seed_hex: &str) -> Option<SigningKey> {
    let bytes = seed_hex.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut seed = [0u8; 32];
    for (byte, pair) in seed.iter_mut().zip(bytes.chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(SigningKey::from_bytes(&seed))
}
