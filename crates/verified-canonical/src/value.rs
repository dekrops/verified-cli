//! The value model of `verified-json-v1`.

use std::cmp::Ordering;
use std::fmt;

use crate::digest::Sha256Digest;
use crate::encode;

/// A JSON value as `verified-json-v1` models it.
///
/// Two values are equal exactly when their canonical encodings are equal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// An integer of any size.
    Integer(Integer),
    /// A sequence of Unicode scalar values.
    String(String),
    /// An ordered sequence of values.
    Array(Vec<Value>),
    /// A set of uniquely keyed members.
    Object(Object),
}

impl Value {
    /// The canonical text of this value.
    #[must_use]
    pub fn to_canonical_string(&self) -> String {
        let mut out = String::new();
        encode::write_value(self, &mut out);
        out
    }

    /// The SHA-256 digest of the canonical text.
    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        Sha256Digest::of(self.to_canonical_string().as_bytes())
    }

    /// The string, if this is one.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    /// The integer, if this is one.
    #[must_use]
    pub fn as_integer(&self) -> Option<&Integer> {
        match self {
            Self::Integer(i) => Some(i),
            _ => None,
        }
    }

    /// The elements, if this is an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(a) => Some(a),
            _ => None,
        }
    }

    /// The object, if this is one.
    #[must_use]
    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Self::Object(o) => Some(o),
            _ => None,
        }
    }
}

/// An integer in canonical decimal spelling: an optional `-`, then digits
/// without a leading zero. Zero is `0`, never `-0`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Integer(String);

impl Integer {
    /// Builds an integer from a canonical spelling the parser has produced.
    pub(crate) fn from_canonical(spelling: String) -> Self {
        debug_assert!(is_canonical_integer(&spelling), "not canonical: {spelling}");
        Self(spelling)
    }

    /// The canonical decimal spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The value, if it fits an `i64`.
    #[must_use]
    pub fn to_i64(&self) -> Option<i64> {
        self.0.parse().ok()
    }
}

impl From<i64> for Integer {
    fn from(n: i64) -> Self {
        Self(n.to_string())
    }
}

impl fmt::Display for Integer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn is_canonical_integer(s: &str) -> bool {
    let digits = s.strip_prefix('-').unwrap_or(s);
    let negative = digits.len() != s.len();
    !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'))
        && !(negative && digits == "0")
}

/// Orders two object keys as `verified-json-v1` does: by UTF-16 code unit.
///
/// This differs from Rust's `str` order (by scalar value) for keys that mix
/// supplementary-plane characters with U+E000–U+FFFF.
#[must_use]
pub fn cmp_keys(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// The members of a JSON object: unique keys, held in canonical order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Object {
    members: Vec<(String, Value)>,
}

impl Object {
    /// An object without members.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets a member, returning the value it replaces.
    pub fn insert(&mut self, key: impl Into<String>, value: Value) -> Option<Value> {
        let key = key.into();
        match self.position(&key) {
            Ok(i) => Some(std::mem::replace(&mut self.members[i].1, value)),
            Err(i) => {
                self.members.insert(i, (key, value));
                None
            }
        }
    }

    /// The member with this key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.position(key).ok().map(|i| &self.members[i].1)
    }

    /// The number of members.
    #[must_use]
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Whether the object has no members.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// The members in canonical key order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&str, &Value)> {
        self.members.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// The keys in canonical order.
    pub fn keys(&self) -> impl ExactSizeIterator<Item = &str> {
        self.members.iter().map(|(k, _)| k.as_str())
    }

    /// Whether the keys are exactly `expected`, which must itself be in
    /// canonical order.
    #[must_use]
    pub fn has_exactly(&self, expected: &[&str]) -> bool {
        debug_assert!(expected.windows(2).all(|w| cmp_keys(w[0], w[1]).is_lt()));
        self.keys().eq(expected.iter().copied())
    }

    fn position(&self, key: &str) -> Result<usize, usize> {
        self.members.binary_search_by(|(k, _)| cmp_keys(k, key))
    }
}

impl FromIterator<(String, Value)> for Object {
    /// Later members replace earlier ones with the same key.
    fn from_iter<I: IntoIterator<Item = (String, Value)>>(iter: I) -> Self {
        let mut object = Self::new();
        for (key, value) in iter {
            object.insert(key, value);
        }
        object
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_order_by_utf16_code_unit_not_scalar_value() {
        // U+10000 encodes as the surrogate pair D800 DC00, which sorts before
        // U+E000 in UTF-16 although its scalar value is larger.
        assert_eq!(cmp_keys("\u{10000}", "\u{e000}"), Ordering::Less);
        assert_eq!("\u{10000}".cmp("\u{e000}"), Ordering::Greater);
    }

    #[test]
    fn insert_keeps_canonical_order_and_replaces() {
        let mut o = Object::new();
        assert_eq!(o.insert("b", Value::Null), None);
        assert_eq!(o.insert("a", Value::Bool(true)), None);
        assert_eq!(o.insert("b", Value::Bool(false)), Some(Value::Null));
        assert_eq!(o.keys().collect::<Vec<_>>(), ["a", "b"]);
        assert!(o.has_exactly(&["a", "b"]));
        assert!(!o.has_exactly(&["a"]));
    }

    #[test]
    fn canonical_integer_spellings() {
        for ok in ["0", "7", "-7", "10", "900719925474099312345678901234567890"] {
            assert!(is_canonical_integer(ok), "{ok}");
        }
        for bad in ["", "-", "-0", "01", "+1", "1.0", "1e3", " 1"] {
            assert!(!is_canonical_integer(bad), "{bad}");
        }
    }
}
