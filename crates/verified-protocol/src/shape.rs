// SPDX-License-Identifier: Apache-2.0

//! Reading closed shapes out of untrusted JSON.
//!
//! Every protocol object is closed: a member the protocol does not list, an
//! enumeration case it does not name, a case carrying members it does not
//! have and a value of the wrong type are all refused, at any depth. These
//! helpers read one such shape each and say where a value fails.

use std::fmt;

use verified_canonical::{Integer, Object, Value};

use crate::container::{ShapeError, ShapeProblem, WireDigest};
use crate::time::Instant;

pub(crate) type Shape<T> = Result<T, ShapeError>;

/// A position in a component, for error messages. Built on the stack as
/// reading descends; rendered only when something is wrong.
#[derive(Clone, Copy)]
pub(crate) struct At<'a> {
    parent: Option<&'a At<'a>>,
    segment: Segment<'a>,
}

#[derive(Clone, Copy)]
enum Segment<'a> {
    Root(&'a str),
    Member(&'a str),
    Index(usize),
}

impl<'a> At<'a> {
    pub(crate) const fn root(name: &'a str) -> Self {
        Self {
            parent: None,
            segment: Segment::Root(name),
        }
    }

    pub(crate) const fn member(&'a self, name: &'a str) -> Self {
        Self {
            parent: Some(self),
            segment: Segment::Member(name),
        }
    }

    pub(crate) const fn index(&'a self, index: usize) -> Self {
        Self {
            parent: Some(self),
            segment: Segment::Index(index),
        }
    }

    pub(crate) fn fail<T>(&self, problem: ShapeProblem) -> Shape<T> {
        Err(ShapeError {
            location: self.to_string(),
            problem,
        })
    }
}

impl fmt::Display for At<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(parent) = self.parent {
            parent.fmt(f)?;
        }
        match self.segment {
            Segment::Root(name) => f.write_str(name),
            Segment::Member(name) => write!(f, ".{name}"),
            Segment::Index(index) => write!(f, "[{index}]"),
        }
    }
}

/// An object with exactly `members`, which are given in canonical order.
pub(crate) fn object<'a>(
    value: &'a Value,
    at: &At<'_>,
    members: &'static [&'static str],
) -> Shape<&'a Object> {
    let Some(object) = value.as_object() else {
        return at.fail(ShapeProblem::NotAnObject);
    };
    if object.has_exactly(members) {
        Ok(object)
    } else {
        at.fail(ShapeProblem::Members(members))
    }
}

/// A member [`object`] has already shown to be present.
pub(crate) fn get<'a>(object: &'a Object, name: &str) -> &'a Value {
    object.get(name).unwrap_or(&Value::Null)
}

pub(crate) fn text<'a>(value: &'a Value, at: &At<'_>) -> Shape<&'a str> {
    match value.as_str() {
        Some(text) => Ok(text),
        None => at.fail(ShapeProblem::NotAString),
    }
}

pub(crate) fn boolean(value: &Value, at: &At<'_>) -> Shape<bool> {
    match value {
        Value::Bool(b) => Ok(*b),
        _ => at.fail(ShapeProblem::Not("a boolean")),
    }
}

pub(crate) fn list<'a>(value: &'a Value, at: &At<'_>) -> Shape<&'a [Value]> {
    match value.as_array() {
        Some(items) => Ok(items),
        None => at.fail(ShapeProblem::NotAnArray),
    }
}

/// Reads every element of an array with `item`.
pub(crate) fn each<'a, T>(
    value: &'a Value,
    at: &At<'_>,
    item: impl Fn(&'a Value, &At<'_>) -> Shape<T>,
) -> Shape<Vec<T>> {
    list(value, at)?
        .iter()
        .enumerate()
        .map(|(i, element)| item(element, &at.index(i)))
        .collect()
}

/// An integer that fits 32 bits.
pub(crate) fn int32(value: &Value, at: &At<'_>) -> Shape<i32> {
    match value
        .as_integer()
        .and_then(Integer::to_i64)
        .and_then(|n| i32::try_from(n).ok())
    {
        Some(n) => Ok(n),
        None => at.fail(ShapeProblem::Not("an integer that fits 32 bits")),
    }
}

/// An integer that fits 64 bits.
pub(crate) fn int64(value: &Value, at: &At<'_>) -> Shape<i64> {
    match value.as_integer().and_then(Integer::to_i64) {
        Some(n) => Ok(n),
        None => at.fail(ShapeProblem::Not("an integer that fits 64 bits")),
    }
}

/// `{ "value": <text> }`.
pub(crate) fn wrapped<'a>(value: &'a Value, at: &At<'_>) -> Shape<&'a str> {
    let object = object(value, at, &["value"])?;
    text(get(object, "value"), &at.member("value"))
}

fn is_uuid(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => matches!(b, b'0'..=b'9' | b'a'..=b'f'),
        })
}

/// An identifier: `{ "value": "<lowercase uuid>" }`.
pub(crate) fn uuid<'a>(value: &'a Value, at: &At<'_>) -> Shape<&'a str> {
    let text = wrapped(value, at)?;
    if is_uuid(text) {
        Ok(text)
    } else {
        at.member("value")
            .fail(ShapeProblem::Not("a lowercase UUID"))
    }
}

/// A time: `{ "value": "<canonical instant>" }`.
pub(crate) fn instant(value: &Value, at: &At<'_>) -> Shape<Instant> {
    match Instant::parse(wrapped(value, at)?) {
        Some(instant) => Ok(instant),
        None => at
            .member("value")
            .fail(ShapeProblem::Not("the canonical spelling of an instant")),
    }
}

/// A digest as stated: `{ algorithm, hex }`, both text and both unchecked.
pub(crate) fn digest<'a>(value: &'a Value, at: &At<'_>) -> Shape<WireDigest<'a>> {
    let object = object(value, at, &["algorithm", "hex"])?;
    Ok(WireDigest {
        algorithm: text(get(object, "algorithm"), &at.member("algorithm"))?,
        hex: text(get(object, "hex"), &at.member("hex"))?,
    })
}

/// `null`, or what `read` reads.
pub(crate) fn nullable<'a, T>(
    value: &'a Value,
    at: &At<'_>,
    read: impl FnOnce(&'a Value, &At<'_>) -> Shape<T>,
) -> Shape<Option<T>> {
    match value {
        Value::Null => Ok(None),
        other => read(other, at).map(Some),
    }
}

/// An enumeration case with members: `{ "<Case>": { … } }`. Returns the case
/// name and its content; the caller refuses names it does not list.
pub(crate) fn variant<'a>(value: &'a Value, at: &At<'_>) -> Shape<(&'a str, &'a Value)> {
    let mut members = value.as_object().map(Object::iter).into_iter().flatten();
    match (members.next(), members.next()) {
        (Some(case), None) => Ok(case),
        _ => at.fail(ShapeProblem::Not(
            "an object with exactly one member, the case",
        )),
    }
}

/// An enumeration case without members: `{ "<Case>": {} }`, one of `cases`.
pub(crate) fn unit<'a>(
    value: &'a Value,
    at: &At<'_>,
    cases: &'static [&'static str],
) -> Shape<&'a str> {
    let (name, content) = variant(value, at)?;
    if !cases.contains(&name) {
        return at.fail(ShapeProblem::Case(cases));
    }
    object(content, &at.member(name), &[])?;
    Ok(name)
}

/// `{ system, kind, key }`: the business object something is about.
pub(crate) fn subject(value: &Value, at: &At<'_>) -> Shape<()> {
    let object = object(value, at, &["key", "kind", "system"])?;
    for (name, member) in object.iter() {
        text(member, &at.member(name))?;
    }
    Ok(())
}

/// `{ system, observationId }`. Returns the system.
pub(crate) fn source<'a>(value: &'a Value, at: &At<'_>) -> Shape<&'a str> {
    let object = object(value, at, &["observationId", "system"])?;
    text(get(object, "observationId"), &at.member("observationId"))?;
    text(get(object, "system"), &at.member("system"))
}

/// `{ major, minor, patch }`.
pub(crate) fn version(value: &Value, at: &At<'_>) -> Shape<()> {
    let object = object(value, at, &["major", "minor", "patch"])?;
    for (name, member) in object.iter() {
        int32(member, &at.member(name))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locations_read_as_paths() {
        let root = At::root("claim.json");
        let evidence = root.member("evidence");
        let third = evidence.index(2);
        assert_eq!(
            third.member("value").to_string(),
            "claim.json.evidence[2].value"
        );
    }

    #[test]
    fn uuids_are_lowercase_and_hyphenated() {
        assert!(is_uuid("00000000-0000-4000-8000-00000000abcd"));
        for bad in [
            "00000000-0000-4000-8000-00000000ABCD",
            "00000000000040008000000000000abcd000",
            "00000000-0000-4000-8000-00000000abc",
            "00000000-0000-4000-8000-00000000abcde",
            "0000000g-0000-4000-8000-00000000abcd",
        ] {
            assert!(!is_uuid(bad), "{bad}");
        }
    }
}
