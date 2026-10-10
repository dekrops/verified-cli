// SPDX-License-Identifier: Apache-2.0

//! A contract as read, and the lexical rules its values follow.

use std::collections::BTreeMap;

use verified_canonical::Value;

/// A contract that has been read and found well formed.
///
/// The only way to obtain one is [`Contract::read`], so holding a `Contract`
/// is holding one that may be evaluated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contract {
    pub(crate) language: String,
    pub(crate) id: String,
    pub(crate) version: String,
    pub(crate) inputs: BTreeMap<String, Type>,
    pub(crate) kinds: BTreeMap<String, Kind>,
    pub(crate) conflicts: ConflictPolicy,
    pub(crate) sources: BTreeMap<String, Vec<String>>,
    pub(crate) policy: BTreeMap<String, Parameter>,
    pub(crate) semantics: String,
    pub(crate) cutoff: Option<String>,
    pub(crate) requires: Vec<Requirement>,
}

impl Contract {
    /// The contract's identifier (`identity.id`).
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The contract's version (`identity.version`).
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The language the contract is written in.
    #[must_use]
    pub fn language(&self) -> &str {
        &self.language
    }

    /// The evaluation semantics the contract declares.
    #[must_use]
    pub fn semantics(&self) -> &str {
        &self.semantics
    }

    /// Whether `source` counts for records of `kind`.
    pub(crate) fn accepts(&self, kind: &str, source: &str) -> bool {
        self.sources
            .get(kind)
            .is_some_and(|sources| sources.iter().any(|s| s == source))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Type {
    Text,
    Bool,
    Int,
    Time,
    Decimal { scale: i32 },
    Money { scale: i32, currency: String },
}

impl Type {
    /// Whether `lt`, `le`, `gt` and `ge` apply.
    pub(crate) const fn is_ordered(&self) -> bool {
        !matches!(self, Self::Text | Self::Bool)
    }

    /// Whether the type's own parameters are in range.
    pub(crate) fn is_valid(&self) -> bool {
        let scale_fits = |scale: &i32| (0..=18).contains(scale);
        match self {
            Self::Decimal { scale } => scale_fits(scale),
            Self::Money { scale, currency } => {
                scale_fits(scale)
                    && currency.len() == 3
                    && currency.bytes().all(|b| b.is_ascii_uppercase())
            }
            _ => true,
        }
    }

    /// Reads a value written next to this type, if it fits.
    pub(crate) fn value(&self, json: &Value) -> Option<Val> {
        match self {
            Self::Text => match json {
                Value::String(s) if s.len() <= MAX_TEXT_BYTES => Some(Val::Text(s.clone())),
                _ => None,
            },
            Self::Bool => match json {
                Value::Bool(b) => Some(Val::Bool(*b)),
                _ => None,
            },
            _ => {
                let n = number(json)?;
                (!matches!(self, Self::Time) || n >= 0).then_some(Val::Number(n))
            }
        }
    }
}

const MAX_TEXT_BYTES: usize = 1024;

/// A typed value. Two values are only ever compared when their types are
/// identical, which the static rules guarantee.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Val {
    Text(String),
    Bool(bool),
    Number(i64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Kind {
    pub(crate) key: Vec<String>,
    pub(crate) fields: BTreeMap<String, Field>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Field {
    pub(crate) ty: Type,
    pub(crate) optional: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConflictPolicy {
    Unknown,
    SourceOrder,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Parameter {
    pub(crate) id: String,
    pub(crate) version: String,
    pub(crate) ty: Type,
    pub(crate) value: Val,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Requirement {
    pub(crate) id: String,
    pub(crate) predicate: Pred,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Term {
    Literal { value: Val, of: Type },
    Input(String),
    Parameter(String),
    Field { variable: String, field: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Quantifier {
    Exists,
    Forall,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Pred {
    Compare {
        op: Op,
        left: Term,
        right: Term,
    },
    And(Vec<Pred>),
    Or(Vec<Pred>),
    Not(Box<Pred>),
    Quantified {
        quantifier: Quantifier,
        variable: String,
        kind: String,
        body: Box<Pred>,
    },
}

impl Pred {
    pub(crate) fn children(&self) -> &[Pred] {
        match self {
            Self::Compare { .. } => &[],
            Self::And(args) | Self::Or(args) => args,
            Self::Not(inner) => std::slice::from_ref(inner),
            Self::Quantified { body, .. } => std::slice::from_ref(body),
        }
    }

    /// The number of predicate nodes.
    pub(crate) fn nodes(&self) -> u64 {
        1 + self.children().iter().map(Self::nodes).sum::<u64>()
    }

    /// The deepest nesting of quantifiers.
    pub(crate) fn quantifier_depth(&self) -> u32 {
        u32::from(matches!(self, Self::Quantified { .. }))
            + self
                .children()
                .iter()
                .map(Self::quantifier_depth)
                .max()
                .unwrap_or(0)
    }
}

/// `[A-Za-z][A-Za-z0-9_.-]{0,63}`: inputs, kinds, fields, parameters,
/// sources, variables, requirement and record identifiers.
pub(crate) fn is_name(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() <= 64
        && bytes.first().is_some_and(u8::is_ascii_alphabetic)
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// `[0-9A-Za-z][0-9A-Za-z.+-]{0,63}`: contract and policy versions.
pub(crate) fn is_version(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() <= 64
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-'))
}

/// A number: a JSON string `-?(0|[1-9][0-9]{0,18})` other than `-0`, whose
/// value lies strictly between −2⁶³ and 2⁶³.
pub(crate) fn number(json: &Value) -> Option<i64> {
    let text = json.as_str()?;
    let digits = text.strip_prefix('-').unwrap_or(text);
    let spelled = !digits.is_empty()
        && digits.len() <= 19
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'))
        && text != "-0";
    if !spelled {
        return None;
    }
    text.parse::<i64>().ok().filter(|n| *n != i64::MIN)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(s: &str) -> Value {
        Value::String(s.to_owned())
    }

    #[test]
    fn numbers_are_strings_in_one_spelling_and_range() {
        for (spelling, value) in [
            ("0", 0),
            ("-1", -1),
            ("1250", 1250),
            ("9223372036854775807", i64::MAX),
            ("-9223372036854775807", -i64::MAX),
        ] {
            assert_eq!(number(&text(spelling)), Some(value), "{spelling}");
        }
        for bad in [
            "",
            "-",
            "-0",
            "01",
            "+1",
            "1.0",
            "1e3",
            " 1",
            "9223372036854775808",
            "-9223372036854775808",
            "10000000000000000000",
        ] {
            assert_eq!(number(&text(bad)), None, "{bad}");
        }
        assert_eq!(number(&Value::Integer(5.into())), None);
    }

    #[test]
    fn names_and_versions() {
        let long = "a".repeat(64);
        for ok in ["a", "A1", "sap-s4", "e-0000", "a.b_c-d", long.as_str()] {
            assert!(is_name(ok), "{ok}");
        }
        let too_long = "a".repeat(65);
        for bad in ["", "1a", "-a", "a b", "é", too_long.as_str()] {
            assert!(!is_name(bad), "{bad}");
        }
        assert!(is_version("1.0.0"));
        assert!(is_version("2024+build-1"));
        assert!(!is_version(".1"));
        assert!(!is_version("1 0"));
    }

    #[test]
    fn values_fit_their_types() {
        assert_eq!(Type::Time.value(&text("-1")), None);
        assert_eq!(Type::Int.value(&text("-1")), Some(Val::Number(-1)));
        assert_eq!(Type::Bool.value(&text("true")), None);
        assert_eq!(Type::Text.value(&text(&"x".repeat(1025))), None);
        assert!(Type::Text.value(&text(&"x".repeat(1024))).is_some());
        assert!(
            !Type::Money {
                scale: 2,
                currency: "eur".into()
            }
            .is_valid()
        );
        assert!(!Type::Decimal { scale: 19 }.is_valid());
    }
}
