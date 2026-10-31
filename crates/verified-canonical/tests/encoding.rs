// SPDX-License-Identifier: Apache-2.0

//! Known answers and adversarial input for `verified-json-v1`.
//!
//! The expected canonical texts here were written by hand from the rules in
//! the crate documentation. The shared cross-implementation corpus is run by
//! `tests/shared_vectors.rs`.

use verified_canonical::{
    CanonicalError, LimitExceeded, Limits, ParseError, SyntaxError, Value, parse, parse_canonical,
};

fn canonical(input: &str) -> String {
    parse(input.as_bytes(), &Limits::DEFAULT)
        .unwrap_or_else(|e| panic!("{input:?} should parse: {e}"))
        .to_canonical_string()
}

fn error(input: &[u8]) -> ParseError {
    parse(input, &Limits::DEFAULT).expect_err("should be refused")
}

#[test]
fn empty_object_digest_is_the_sha256_of_two_braces() {
    let value = parse(b" { } ", &Limits::DEFAULT).expect("parses");
    assert_eq!(value.to_canonical_string(), "{}");
    assert_eq!(
        value.digest().to_hex(),
        "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
    );
}

#[test]
fn keys_sort_recursively_and_whitespace_goes() {
    assert_eq!(
        canonical("{ \"z\": null,\n\t\"a\": {\"y\": 2, \"b\": 1}}\r\n"),
        r#"{"a":{"b":1,"y":2},"z":null}"#
    );
}

#[test]
fn keys_sort_by_utf16_code_unit() {
    // U+10000 (surrogates D800 DC00) sorts before U+E000.
    assert_eq!(
        canonical(r#"{"\ue000":1,"\ud800\udc00":2,"a":3}"#),
        "{\"a\":3,\"\u{10000}\":2,\"\u{e000}\":1}"
    );
}

#[test]
fn arrays_keep_order_and_nulls() {
    assert_eq!(
        canonical("[2, 1, null, true, false, []]"),
        "[2,1,null,true,false,[]]"
    );
}

#[test]
fn integral_spellings_become_plain_integers() {
    assert_eq!(
        canonical("[1.0, 1e0, -0, 100e-2, 1e3, 1E+2, -12.50e1, 0.0, 0e99999999999999999999]"),
        "[1,1,0,1,1000,100,-125,0,0]"
    );
    let large = "900719925474099312345678901234567890";
    assert_eq!(canonical(large), large);
    assert_eq!(canonical(&format!("-{large}00e-2")), format!("-{large}"));
}

#[test]
fn fractions_are_refused() {
    for input in ["0.5", "1e-1", "[1,1.01]", "125e-3", "-0.000001"] {
        assert!(
            matches!(error(input.as_bytes()), ParseError::FractionalNumber { .. }),
            "{input}"
        );
    }
}

#[test]
fn malformed_numbers_are_refused() {
    for input in [
        "01", "-", "1.", ".5", "1e", "1e+", "+1", "--1", "0x10", "1_000", "NaN",
    ] {
        assert!(
            matches!(error(input.as_bytes()), ParseError::Syntax { .. }),
            "{input}"
        );
    }
}

#[test]
fn strings_are_not_normalized() {
    // U+00E9 and U+0065 U+0301 stay distinct.
    assert_eq!(
        canonical("[\"\u{e9}\",\"e\u{301}\"]"),
        "[\"\u{e9}\",\"e\u{301}\"]"
    );
}

#[test]
fn escapes_are_decoded_then_rewritten_canonically() {
    assert_eq!(
        canonical(r#""\u0041\/\u000A\u007F\u00a0\uD83D\uDE00""#),
        "\"A/\\n\\u007f\u{a0}😀\""
    );
}

#[test]
fn unpaired_surrogates_are_refused_in_values_and_keys() {
    for input in [
        r#""\ud800""#,
        r#""\udc00""#,
        r#""\ud800x""#,
        r#""\ud800\u0041""#,
        r#""\ud800\ud800""#,
        r#"{"\ud800":1}"#,
    ] {
        assert!(
            matches!(
                error(input.as_bytes()),
                ParseError::UnpairedSurrogate { .. }
            ),
            "{input}"
        );
    }
}

#[test]
fn duplicate_keys_are_refused_even_when_spelled_differently() {
    assert_eq!(
        error(br#"{"a":1,"b":2,"a":3}"#),
        ParseError::DuplicateKey { offset: 13 }
    );
    assert!(matches!(
        error(br#"{"a":1,"\u0061":1}"#),
        ParseError::DuplicateKey { .. }
    ));
}

#[test]
fn syntax_errors_carry_their_position() {
    let cases: [(&[u8], usize, SyntaxError); 9] = [
        (b"", 0, SyntaxError::UnexpectedEnd),
        (b"[1,", 3, SyntaxError::UnexpectedEnd),
        (b"[1 2]", 3, SyntaxError::UnexpectedCharacter),
        (b"{\"a\" 1}", 5, SyntaxError::UnexpectedCharacter),
        (b"{a:1}", 1, SyntaxError::UnexpectedCharacter),
        (b"nul", 0, SyntaxError::UnexpectedCharacter),
        (b"\"a\nb\"", 2, SyntaxError::ControlCharacter),
        (b"\"\\x\"", 1, SyntaxError::Escape),
        (b"{} {}", 3, SyntaxError::TrailingData),
    ];
    for (input, offset, kind) in cases {
        assert_eq!(
            error(input),
            ParseError::Syntax { offset, kind },
            "{:?}",
            String::from_utf8_lossy(input)
        );
    }
}

#[test]
fn invalid_utf8_and_byte_order_marks_are_refused() {
    assert_eq!(error(b"\"\xff\""), ParseError::InvalidUtf8 { offset: 1 });
    assert!(matches!(
        error(b"\xef\xbb\xbf{}"),
        ParseError::Syntax { offset: 0, .. }
    ));
}

#[test]
fn limits_are_enforced() {
    let limits = Limits {
        max_bytes: 64,
        max_depth: 3,
        max_values: 8,
        max_integer_digits: 5,
    };
    let refused = |input: &str| match parse(input.as_bytes(), &limits) {
        Err(ParseError::Limit(limit)) => limit,
        other => panic!("{input}: expected a limit, got {other:?}"),
    };
    assert!(parse(b"[[[1]]]", &limits).is_ok());
    assert_eq!(refused("[[[[1]]]]"), LimitExceeded::Depth { limit: 3 });
    assert_eq!(
        refused("[1,2,3,4,5,6,7,8]"),
        LimitExceeded::Values { limit: 8 }
    );
    assert_eq!(refused(&" ".repeat(65)), LimitExceeded::Bytes { limit: 64 });
    assert!(parse(b"12345", &limits).is_ok());
    assert_eq!(refused("123456"), LimitExceeded::IntegerDigits { limit: 5 });
    assert_eq!(refused("1e5"), LimitExceeded::IntegerDigits { limit: 5 });
    assert_eq!(
        refused("1e99999999999999999999999"),
        LimitExceeded::IntegerDigits { limit: 5 }
    );
}

#[test]
fn exponents_cannot_multiply_the_input_beyond_the_byte_limit() {
    let limits = Limits {
        max_bytes: 100,
        max_depth: 4,
        max_values: 100,
        max_integer_digits: 40,
    };
    assert!(parse(b"[1e30,1e30,1e30]", &limits).is_ok());
    assert_eq!(
        parse(b"[1e30,1e30,1e30,1e30]", &limits),
        Err(ParseError::Limit(LimitExceeded::Bytes { limit: 100 }))
    );
}

#[test]
fn the_byte_limit_bounds_the_canonical_text_not_only_the_input() {
    let limits = |max_bytes| Limits {
        max_bytes,
        ..Limits::DEFAULT
    };
    let too_large = |max_bytes| Err(ParseError::Limit(LimitExceeded::Bytes { limit: max_bytes }));

    // An exponent: 5 bytes of input, 12 of canonical text (`[1000000000]`).
    assert_eq!(parse(b"[1e9]", &limits(10)), too_large(10));
    assert_eq!(parse(b"[1e9]", &limits(11)), too_large(11));
    assert!(parse(b"[1e9]", &limits(12)).is_ok());

    // A raw C1 control: 4 bytes of input, 8 of canonical text (`"\u0080"`).
    let c1 = "\"\u{80}\"".as_bytes();
    assert_eq!(c1.len(), 4);
    assert_eq!(parse(c1, &limits(7)), too_large(7));
    assert!(parse(c1, &limits(8)).is_ok());

    // The same in an object key, with structure around it: 8 bytes of input, 12 of canonical
    // text (`{"\u0080":0}`).
    let key = "{\"\u{80}\":0}".as_bytes();
    assert_eq!(key.len(), 8);
    assert_eq!(parse(key, &limits(11)), too_large(11));
    assert!(parse(key, &limits(12)).is_ok());

    // A raw DEL, which JSON allows unescaped: 3 bytes of input, 8 of canonical text.
    assert_eq!(parse(b"\"\x7f\"", &limits(7)), too_large(7));
    assert!(parse(b"\"\x7f\"", &limits(8)).is_ok());
}

#[test]
fn deep_nesting_is_refused_without_exhausting_the_stack() {
    let input = "[".repeat(1_000_000);
    assert_eq!(
        error(input.as_bytes()),
        ParseError::Limit(LimitExceeded::Depth {
            limit: Limits::DEFAULT.max_depth
        })
    );
}

#[test]
fn parse_canonical_accepts_only_canonical_text() {
    let limits = Limits::DEFAULT;
    assert_eq!(
        parse_canonical(br#"{"a":1,"b":[true,null]}"#, &limits).map(|v| v.to_canonical_string()),
        Ok(r#"{"a":1,"b":[true,null]}"#.to_owned())
    );
    let not_canonical: [(&[u8], usize); 7] = [
        (br#"{"b":1,"a":2}"#, 2),
        (br#"{"a": 1}"#, 5),
        (b"1.0", 1),
        (b"-0", 0),
        (br#""\u0041""#, 1),
        (br#""\/""#, 1),
        (b"{}\n", 2),
    ];
    for (input, offset) in not_canonical {
        assert_eq!(
            parse_canonical(input, &limits),
            Err(CanonicalError::NotCanonical { offset }),
            "{:?}",
            String::from_utf8_lossy(input)
        );
    }
    assert!(matches!(
        parse_canonical(b"{", &limits),
        Err(CanonicalError::Parse(_))
    ));
}

#[test]
fn a_limit_is_distinguishable_from_non_canonical_text() {
    let limits = Limits {
        max_depth: 1,
        ..Limits::DEFAULT
    };
    let err = parse_canonical(b"[[]]", &limits).expect_err("too deep");
    assert_eq!(err.limit(), Some(LimitExceeded::Depth { limit: 1 }));
    assert_eq!(
        parse_canonical(b"[ ]", &limits)
            .expect_err("spaced")
            .limit(),
        None
    );
}

#[test]
fn accessors_expose_the_value_model() {
    let value = parse(br#"{"n":-7,"s":"x","a":[1]}"#, &Limits::DEFAULT).expect("parses");
    let object = value.as_object().expect("an object");
    assert_eq!(object.len(), 3);
    assert_eq!(
        object
            .get("n")
            .and_then(Value::as_integer)
            .and_then(verified_canonical::Integer::to_i64),
        Some(-7)
    );
    assert_eq!(object.get("s").and_then(Value::as_str), Some("x"));
    assert_eq!(
        object
            .get("a")
            .and_then(Value::as_array)
            .map(<[Value]>::len),
        Some(1)
    );
    assert_eq!(object.get("missing"), None);
}
