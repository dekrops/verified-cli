// SPDX-License-Identifier: Apache-2.0

//! Writing canonical text.

use std::fmt::Write as _;

use crate::value::Value;

pub(crate) fn write_value(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Integer(i) => out.push_str(i.as_str()),
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
        Value::Object(object) => {
            out.push('{');
            for (i, (key, member)) in object.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_value(member, out);
            }
            out.push('}');
        }
    }
}

/// The length in bytes of `value`'s canonical text, without writing it.
///
/// It must agree with [`write_value`] byte for byte; a property test checks that it does. Sums
/// saturate, so a value too large to measure reads as `usize::MAX`.
pub(crate) fn canonical_len(value: &Value) -> usize {
    match value {
        Value::Null | Value::Bool(true) => 4,
        Value::Bool(false) => 5,
        Value::Integer(i) => i.as_str().len(),
        Value::String(s) => string_len(s),
        // Brackets, plus a comma between items.
        Value::Array(items) => items.iter().fold(
            items.len().saturating_sub(1).saturating_add(2),
            |len, item| len.saturating_add(canonical_len(item)),
        ),
        // Braces, a comma between members, and a colon in each.
        Value::Object(object) => object.iter().fold(
            object.len().saturating_sub(1).saturating_add(2),
            |len, (key, member)| {
                len.saturating_add(string_len(key))
                    .saturating_add(1)
                    .saturating_add(canonical_len(member))
            },
        ),
    }
}

/// The length of a string's canonical text, quotes and escapes included.
fn string_len(text: &str) -> usize {
    text.chars().fold(2, |len: usize, ch| {
        len.saturating_add(match ch {
            '"' | '\\' | '\u{08}' | '\t' | '\n' | '\u{0c}' | '\r' => 2,
            '\u{00}'..='\u{1f}' | '\u{7f}'..='\u{9f}' => 6,
            _ => ch.len_utf8(),
        })
    })
}

fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            // C0 controls, DEL and the C1 controls. U+00A0 is not escaped.
            '\u{00}'..='\u{1f}' | '\u{7f}'..='\u{9f}' => {
                // Writing to a `String` cannot fail.
                let _ = write!(out, "\\u{:04x}", u32::from(ch));
            }
            _ => out.push(ch),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use crate::value::{Object, Value};

    fn s(text: &str) -> Value {
        Value::String(text.to_owned())
    }

    #[test]
    fn escapes_exactly_the_specified_characters() {
        assert_eq!(
            s("\"\\/\u{08}\t\n\u{0c}\r").to_canonical_string(),
            r#""\"\\/\b\t\n\f\r""#
        );
        assert_eq!(s("\u{00}\u{1f}").to_canonical_string(), r#""\u0000\u001f""#);
        assert_eq!(s("\u{7f}\u{9f}").to_canonical_string(), r#""\u007f\u009f""#);
        // The first character after the escaped ranges, and non-ASCII text.
        assert_eq!(s("\u{a0}é𐀀").to_canonical_string(), "\"\u{a0}é𐀀\"");
    }

    #[test]
    fn objects_are_written_in_key_order_without_whitespace() {
        let mut inner = Object::new();
        inner.insert("y", Value::Integer(2.into()));
        inner.insert("b", Value::Integer(1.into()));
        let mut outer = Object::new();
        outer.insert("z", Value::Null);
        outer.insert("a", Value::Object(inner));
        outer.insert(
            "m",
            Value::Array(vec![Value::Bool(true), Value::Bool(false)]),
        );
        assert_eq!(
            Value::Object(outer).to_canonical_string(),
            r#"{"a":{"b":1,"y":2},"m":[true,false],"z":null}"#
        );
    }
}
