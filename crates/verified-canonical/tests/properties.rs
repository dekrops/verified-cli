//! Properties of the canonical encoding over generated values.

use std::fmt::Write as _;

use proptest::prelude::*;
use verified_canonical::{
    Integer, Limits, Object, SigningDomain, Value, cmp_keys, parse, parse_canonical,
};

fn integer() -> impl Strategy<Value = Integer> {
    prop_oneof![
        any::<i64>().prop_map(Integer::from),
        // Beyond 64 bits, through the parser.
        ("-?[1-9][0-9]{20,60}").prop_map(|s| {
            match parse(s.as_bytes(), &Limits::DEFAULT) {
                Ok(Value::Integer(i)) => i,
                other => panic!("{s} should be an integer, got {other:?}"),
            }
        }),
    ]
}

fn text() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-zA-Z0-9 ]{0,8}",
        // Controls, DEL, C1, quotes, and both sides of the UTF-16 ordering trap.
        proptest::collection::vec(
            prop_oneof![
                Just('"'),
                Just('\\'),
                Just('/'),
                Just('\u{0}'),
                Just('\n'),
                Just('\u{1f}'),
                Just('\u{7f}'),
                Just('\u{9f}'),
                Just('\u{a0}'),
                Just('\u{e000}'),
                Just('\u{ffff}'),
                Just('\u{10000}'),
                Just('\u{10ffff}'),
                any::<char>(),
            ],
            0..6
        )
        .prop_map(|chars| chars.into_iter().collect()),
    ]
}

fn value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        integer().prop_map(Value::Integer),
        text().prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 48, 6, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            proptest::collection::vec((text(), inner), 0..6)
                .prop_map(|members| Value::Object(members.into_iter().collect::<Object>())),
        ]
    })
}

/// Writes a value in a deliberately non-canonical spelling: members in
/// reverse order, padded with whitespace, every string character escaped.
fn respell(value: &Value, out: &mut String) {
    fn string(s: &str, out: &mut String) {
        out.push('"');
        for unit in s.encode_utf16() {
            let _ = write!(out, "\\u{unit:04X}");
        }
        out.push('"');
    }
    match value {
        Value::Null => out.push_str(" null "),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "\tfalse" }),
        Value::Integer(i) => {
            out.push_str(i.as_str());
            out.push_str(".0e0");
        }
        Value::String(s) => string(s, out),
        Value::Array(items) => {
            out.push_str("[ ");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(" ,\n");
                }
                respell(item, out);
            }
            out.push_str(" ]");
        }
        Value::Object(object) => {
            out.push_str("{ ");
            let members: Vec<_> = object.iter().collect();
            for (i, (key, member)) in members.iter().rev().enumerate() {
                if i > 0 {
                    out.push_str(" , ");
                }
                string(key, out);
                out.push_str(" : ");
                respell(member, out);
            }
            out.push_str(" }");
        }
    }
}

proptest! {
    #[test]
    fn canonical_text_round_trips(value in value()) {
        let text = value.to_canonical_string();
        let reread = parse_canonical(text.as_bytes(), &Limits::DEFAULT);
        prop_assert_eq!(reread, Ok(value));
    }

    #[test]
    fn every_spelling_of_a_value_has_one_canonical_text_and_digest(value in value()) {
        let mut spelling = String::new();
        respell(&value, &mut spelling);
        let reread = parse(spelling.as_bytes(), &Limits::DEFAULT)
            .map_err(|e| TestCaseError::fail(format!("{spelling:?}: {e}")))?;
        prop_assert_eq!(reread.to_canonical_string(), value.to_canonical_string());
        prop_assert_eq!(reread.digest(), value.digest());
    }

    #[test]
    fn equal_digests_mean_equal_values(a in value(), b in value()) {
        prop_assert_eq!(a.digest() == b.digest(), a == b);
    }

    #[test]
    fn object_members_are_strictly_ascending_in_utf16_order(
        members in proptest::collection::vec((text(), Just(Value::Null)), 0..12)
    ) {
        let object: Object = members.into_iter().collect();
        let keys: Vec<&str> = object.keys().collect();
        prop_assert!(keys.windows(2).all(|w| cmp_keys(w[0], w[1]).is_lt()));
    }

    #[test]
    fn canonical_text_has_no_raw_control_characters(value in value()) {
        let text = value.to_canonical_string();
        prop_assert!(!text.chars().any(char::is_control), "{:?}", text);
    }

    #[test]
    fn signing_inputs_under_different_domains_never_collide(a in value(), b in value()) {
        let one = SigningDomain::new("test:one:v1\n").expect("valid");
        let two = SigningDomain::new("test:one:v2\n").expect("valid");
        prop_assert_ne!(one.signing_input(&a), two.signing_input(&b));
    }

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let _ = parse(&bytes, &Limits::DEFAULT);
    }

    #[test]
    fn json_like_noise_never_panics(text in r#"[\[\]{}:,"\\ue0-9a-f.+\- nulltruefalse]{0,64}"#) {
        let _ = parse_canonical(text.as_bytes(), &Limits::DEFAULT);
    }
}
