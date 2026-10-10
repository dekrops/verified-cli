// SPDX-License-Identifier: Apache-2.0

//! Domain-separated signing input.

use crate::value::Value;

/// A signing domain: the prefix that keeps a signature over one kind of
/// object from being valid for another.
///
/// The protocol's domains have the form `verified:<purpose>:<version>\n`. A
/// domain is one line: non-empty, ending in the only line feed it contains.
/// Canonical text contains no raw line feed (it is always escaped), so the
/// first line feed of a signing input marks the end of its domain. Signing
/// input under two different domains therefore always differs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SigningDomain(&'static str);

/// The text is not a single line terminated by its only line feed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("a signing domain is one non-empty line ending in its only line feed")]
pub struct InvalidDomain;

impl SigningDomain {
    /// Checks and wraps a domain prefix.
    pub const fn new(prefix: &'static str) -> Result<Self, InvalidDomain> {
        let bytes = prefix.as_bytes();
        if bytes.len() < 2 || bytes[bytes.len() - 1] != b'\n' {
            return Err(InvalidDomain);
        }
        let mut i = 0;
        while i < bytes.len() - 1 {
            if bytes[i] == b'\n' {
                return Err(InvalidDomain);
            }
            i += 1;
        }
        Ok(Self(prefix))
    }

    /// The prefix, including its line feed.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        self.0
    }

    /// The bytes a signer signs for `value` under this domain: the prefix
    /// followed by the value's canonical text.
    #[must_use]
    pub fn signing_input(&self, value: &Value) -> Vec<u8> {
        let mut input = self.0.as_bytes().to_vec();
        input.extend_from_slice(value.to_canonical_string().as_bytes());
        input
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_one_terminated_line_only() {
        assert!(SigningDomain::new("example:purpose:v1\n").is_ok());
        for bad in ["", "\n", "no-terminator", "two\nlines\n", "trailing\n\n"] {
            assert_eq!(SigningDomain::new(bad), Err(InvalidDomain), "{bad:?}");
        }
    }

    #[test]
    fn signing_input_is_prefix_then_canonical_text() {
        let domain = SigningDomain::new("example:purpose:v1\n").expect("valid");
        let value = Value::Array(vec![Value::Null]);
        assert_eq!(domain.signing_input(&value), b"example:purpose:v1\n[null]");
    }
}
