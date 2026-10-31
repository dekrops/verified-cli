// SPDX-License-Identifier: Apache-2.0

//! Reading untrusted JSON text.
//!
//! The parser is written for this encoding rather than borrowed from a
//! general JSON library because every deviation matters to a commitment: it
//! must keep integers exact at any size, refuse fractions, refuse unpaired
//! surrogates and duplicate keys, and never exceed stated resource bounds.

use crate::value::{Integer, Object, Value, cmp_keys};

/// Resource bounds for one parse. Input is hostile until proven otherwise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The largest input, and the largest canonical text, in bytes.
    pub max_bytes: usize,
    /// How deeply arrays and objects may nest.
    pub max_depth: usize,
    /// How many values (of any kind) the text may contain.
    pub max_values: usize,
    /// How many digits one integer may have.
    pub max_integer_digits: usize,
}

impl Limits {
    /// Bounds suited to protocol packages: 32 MiB, 128 levels, two million
    /// values, 4096-digit integers.
    pub const DEFAULT: Self = Self {
        max_bytes: 32 * 1024 * 1024,
        max_depth: 128,
        max_values: 2_000_000,
        max_integer_digits: 4096,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A resource bound of [`Limits`] that the input exceeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LimitExceeded {
    /// The input, or its canonical text, is larger than `max_bytes`.
    #[error("larger than {limit} bytes")]
    Bytes {
        /// The configured bound.
        limit: usize,
    },
    /// Arrays and objects nest deeper than `max_depth`.
    #[error("nested deeper than {limit} levels")]
    Depth {
        /// The configured bound.
        limit: usize,
    },
    /// The text holds more than `max_values` values.
    #[error("more than {limit} values")]
    Values {
        /// The configured bound.
        limit: usize,
    },
    /// An integer has more than `max_integer_digits` digits.
    #[error("an integer of more than {limit} digits")]
    IntegerDigits {
        /// The configured bound.
        limit: usize,
    },
}

/// How text fails to be JSON.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SyntaxError {
    /// The text ends inside a value.
    #[error("unexpected end of input")]
    UnexpectedEnd,
    /// A character that cannot appear at this position.
    #[error("unexpected character")]
    UnexpectedCharacter,
    /// A malformed number.
    #[error("malformed number")]
    Number,
    /// A malformed escape sequence in a string.
    #[error("malformed escape sequence")]
    Escape,
    /// An unescaped control character in a string.
    #[error("unescaped control character in a string")]
    ControlCharacter,
    /// Something other than whitespace follows the value.
    #[error("data after the value")]
    TrailingData,
}

/// Why input was not read. Offsets are byte positions in the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// The input is not UTF-8.
    #[error("invalid UTF-8 at byte {offset}")]
    InvalidUtf8 {
        /// Where the first invalid sequence starts.
        offset: usize,
    },
    /// The input is not JSON.
    #[error("{kind} at byte {offset}")]
    Syntax {
        /// Where the error was found.
        offset: usize,
        /// What is wrong.
        kind: SyntaxError,
    },
    /// A number with a fractional part; the encoding has integers only.
    #[error("number at byte {offset} is not an integer")]
    FractionalNumber {
        /// Where the number starts.
        offset: usize,
    },
    /// A `\u` escape naming half of a surrogate pair without the other half.
    #[error("unpaired surrogate escape at byte {offset}")]
    UnpairedSurrogate {
        /// Where the escape starts.
        offset: usize,
    },
    /// An object that repeats a key.
    #[error("duplicate object key at byte {offset}")]
    DuplicateKey {
        /// Where the repeated key starts.
        offset: usize,
    },
    /// A bound of [`Limits`] was exceeded.
    #[error("input exceeds a resource limit: {0}")]
    Limit(#[from] LimitExceeded),
}

/// Why input is not the canonical encoding of a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CanonicalError {
    /// The input could not be read at all.
    #[error(transparent)]
    Parse(#[from] ParseError),
    /// The input is JSON, but not written in canonical form.
    #[error("not in canonical form: differs from the canonical text at byte {offset}")]
    NotCanonical {
        /// The first byte at which the input and its canonical text differ.
        offset: usize,
    },
}

impl CanonicalError {
    /// The resource limit behind this error, if that is what it is.
    ///
    /// A limit is a property of this reader, not of the text: such input was
    /// not shown to be non-canonical.
    #[must_use]
    pub fn limit(&self) -> Option<LimitExceeded> {
        match self {
            Self::Parse(ParseError::Limit(limit)) => Some(*limit),
            _ => None,
        }
    }
}

/// Reads one JSON value, in any spelling, under `limits`.
pub fn parse(input: &[u8], limits: &Limits) -> Result<Value, ParseError> {
    if input.len() > limits.max_bytes {
        return Err(LimitExceeded::Bytes {
            limit: limits.max_bytes,
        }
        .into());
    }
    let text = std::str::from_utf8(input).map_err(|e| ParseError::InvalidUtf8 {
        offset: e.valid_up_to(),
    })?;
    let mut parser = Parser {
        text,
        bytes: input,
        pos: 0,
        values: 0,
        expansion: 0,
        limits,
    };
    parser.skip_whitespace();
    let value = parser.value(0)?;
    parser.skip_whitespace();
    if parser.pos < input.len() {
        return Err(parser.syntax(SyntaxError::TrailingData));
    }
    // Canonical text can be longer than the input: exponents are written out and some characters
    // are escaped. The bound holds for both.
    if value.canonical_len() > limits.max_bytes {
        return Err(LimitExceeded::Bytes {
            limit: limits.max_bytes,
        }
        .into());
    }
    Ok(value)
}

/// Reads one JSON value and refuses text that is not its canonical encoding.
pub fn parse_canonical(input: &[u8], limits: &Limits) -> Result<Value, CanonicalError> {
    let value = parse(input, limits)?;
    let canonical = value.to_canonical_string();
    let differs = input
        .iter()
        .zip(canonical.as_bytes())
        .position(|(a, b)| a != b);
    match differs {
        Some(offset) => Err(CanonicalError::NotCanonical { offset }),
        None if input.len() != canonical.len() => Err(CanonicalError::NotCanonical {
            offset: input.len().min(canonical.len()),
        }),
        None => Ok(value),
    }
}

struct Parser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
    values: usize,
    /// Zeros written out for exponents, so that numbers such as `1e4000`
    /// cannot multiply the input's size without bound while it is read. The
    /// whole canonical text is measured once the value is read.
    expansion: usize,
    limits: &'a Limits,
}

impl Parser<'_> {
    fn syntax(&self, kind: SyntaxError) -> ParseError {
        ParseError::Syntax {
            offset: self.pos,
            kind,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_whitespace(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.peek() {
            self.pos += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), ParseError> {
        match self.peek() {
            Some(b) if b == byte => {
                self.pos += 1;
                Ok(())
            }
            Some(_) => Err(self.syntax(SyntaxError::UnexpectedCharacter)),
            None => Err(self.syntax(SyntaxError::UnexpectedEnd)),
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, ParseError> {
        self.values += 1;
        if self.values > self.limits.max_values {
            return Err(LimitExceeded::Values {
                limit: self.limits.max_values,
            }
            .into());
        }
        match self.peek() {
            None => Err(self.syntax(SyntaxError::UnexpectedEnd)),
            Some(b'n') => self.literal("null", Value::Null),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'"') => self.string().map(Value::String),
            Some(b'-' | b'0'..=b'9') => self.number().map(Value::Integer),
            Some(b'[') => self.array(depth),
            Some(b'{') => self.object(depth),
            Some(_) => Err(self.syntax(SyntaxError::UnexpectedCharacter)),
        }
    }

    fn literal(&mut self, word: &str, value: Value) -> Result<Value, ParseError> {
        if self.bytes[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok(value)
        } else {
            Err(self.syntax(SyntaxError::UnexpectedCharacter))
        }
    }

    fn enter(&self, depth: usize) -> Result<usize, ParseError> {
        if depth >= self.limits.max_depth {
            Err(LimitExceeded::Depth {
                limit: self.limits.max_depth,
            }
            .into())
        } else {
            Ok(depth + 1)
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, ParseError> {
        let depth = self.enter(depth)?;
        self.pos += 1;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_whitespace();
            items.push(self.value(depth)?);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                }
                Some(_) => return Err(self.syntax(SyntaxError::UnexpectedCharacter)),
                None => return Err(self.syntax(SyntaxError::UnexpectedEnd)),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, ParseError> {
        let depth = self.enter(depth)?;
        self.pos += 1;
        let mut members: Vec<(usize, String, Value)> = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(Object::new()));
        }
        loop {
            self.skip_whitespace();
            let key_offset = self.pos;
            if self.peek() != Some(b'"') {
                return Err(match self.peek() {
                    Some(_) => self.syntax(SyntaxError::UnexpectedCharacter),
                    None => self.syntax(SyntaxError::UnexpectedEnd),
                });
            }
            let key = self.string()?;
            self.skip_whitespace();
            self.expect(b':')?;
            self.skip_whitespace();
            let value = self.value(depth)?;
            members.push((key_offset, key, value));
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                Some(_) => return Err(self.syntax(SyntaxError::UnexpectedCharacter)),
                None => return Err(self.syntax(SyntaxError::UnexpectedEnd)),
            }
        }
        // A stable sort keeps a repeated key's occurrences in input order, so
        // the offset reported is that of the first repetition.
        members.sort_by(|a, b| cmp_keys(&a.1, &b.1));
        if let Some(pair) = members.windows(2).find(|pair| pair[0].1 == pair[1].1) {
            return Err(ParseError::DuplicateKey { offset: pair[1].0 });
        }
        Ok(Value::Object(
            members
                .into_iter()
                .map(|(_, key, value)| (key, value))
                .collect(),
        ))
    }

    fn string(&mut self) -> Result<String, ParseError> {
        self.pos += 1; // opening quote
        let mut out = String::new();
        loop {
            let start = self.pos;
            while let Some(b) = self.peek() {
                if b == b'"' || b == b'\\' || b < 0x20 {
                    break;
                }
                self.pos += 1;
            }
            // `start` and `pos` sit on ASCII bytes or the ends of the text,
            // which are always character boundaries.
            out.push_str(&self.text[start..self.pos]);
            match self.peek() {
                None => return Err(self.syntax(SyntaxError::UnexpectedEnd)),
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => out.push(self.escape()?),
                Some(_) => return Err(self.syntax(SyntaxError::ControlCharacter)),
            }
        }
    }

    fn escape(&mut self) -> Result<char, ParseError> {
        let start = self.pos;
        self.pos += 1; // backslash
        let Some(kind) = self.peek() else {
            return Err(self.syntax(SyntaxError::UnexpectedEnd));
        };
        self.pos += 1;
        Ok(match kind {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{08}',
            b'f' => '\u{0c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let unit = self.hex4()?;
                match unit {
                    0xd800..=0xdbff => {
                        if !self.bytes[self.pos..].starts_with(b"\\u") {
                            return Err(ParseError::UnpairedSurrogate { offset: start });
                        }
                        self.pos += 2;
                        let low = self.hex4()?;
                        if !(0xdc00..=0xdfff).contains(&low) {
                            return Err(ParseError::UnpairedSurrogate { offset: start });
                        }
                        let scalar = 0x1_0000 + ((unit - 0xd800) << 10) + (low - 0xdc00);
                        char::from_u32(scalar)
                            .ok_or(ParseError::UnpairedSurrogate { offset: start })?
                    }
                    0xdc00..=0xdfff => {
                        return Err(ParseError::UnpairedSurrogate { offset: start });
                    }
                    _ => char::from_u32(unit)
                        .ok_or(ParseError::UnpairedSurrogate { offset: start })?,
                }
            }
            _ => {
                self.pos = start;
                return Err(self.syntax(SyntaxError::Escape));
            }
        })
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        let mut unit = 0u32;
        for _ in 0..4 {
            let digit = match self.peek() {
                Some(b @ b'0'..=b'9') => b - b'0',
                Some(b @ b'a'..=b'f') => b - b'a' + 10,
                Some(b @ b'A'..=b'F') => b - b'A' + 10,
                Some(_) => return Err(self.syntax(SyntaxError::Escape)),
                None => return Err(self.syntax(SyntaxError::UnexpectedEnd)),
            };
            unit = unit << 4 | u32::from(digit);
            self.pos += 1;
        }
        Ok(unit)
    }

    fn digits(&mut self) -> &str {
        let start = self.pos;
        while let Some(b'0'..=b'9') = self.peek() {
            self.pos += 1;
        }
        &self.text[start..self.pos]
    }

    /// Reads a JSON number and returns the integer it denotes.
    fn number(&mut self) -> Result<Integer, ParseError> {
        let start = self.pos;
        let negative = self.peek() == Some(b'-');
        if negative {
            self.pos += 1;
        }
        let whole = self.digits().to_owned();
        if whole.is_empty() || (whole.len() > 1 && whole.starts_with('0')) {
            self.pos = start;
            return Err(self.syntax(SyntaxError::Number));
        }
        let mut fraction = String::new();
        if self.peek() == Some(b'.') {
            self.pos += 1;
            self.digits().clone_into(&mut fraction);
            if fraction.is_empty() {
                return Err(self.syntax(SyntaxError::Number));
            }
        }
        let mut exponent: i64 = 0;
        if let Some(b'e' | b'E') = self.peek() {
            self.pos += 1;
            let negative_exponent = match self.peek() {
                Some(b'+') => {
                    self.pos += 1;
                    false
                }
                Some(b'-') => {
                    self.pos += 1;
                    true
                }
                _ => false,
            };
            let digits = self.digits();
            if digits.is_empty() {
                return Err(self.syntax(SyntaxError::Number));
            }
            // Saturation is harmless: anything this large is refused below.
            let magnitude = digits.bytes().fold(0i64, |acc, d| {
                acc.saturating_mul(10).saturating_add(i64::from(d - b'0'))
            });
            exponent = if negative_exponent {
                -magnitude
            } else {
                magnitude
            };
        }

        // The number is `digits × 10^shift`.
        let shift = exponent.saturating_sub(i64::try_from(fraction.len()).unwrap_or(i64::MAX));
        let mut digits = whole;
        digits.push_str(&fraction);
        let significant = digits.trim_start_matches('0');
        if significant.is_empty() {
            return Ok(Integer::from_canonical("0".to_owned()));
        }
        let mut digits = significant.to_owned();
        let limit = self.limits.max_integer_digits;
        let too_long = ParseError::Limit(LimitExceeded::IntegerDigits { limit });
        if shift >= 0 {
            let zeros = usize::try_from(shift).map_err(|_| too_long)?;
            if digits.len().saturating_add(zeros) > limit {
                return Err(too_long);
            }
            self.expansion = self.expansion.saturating_add(zeros);
            if self.expansion > self.limits.max_bytes {
                return Err(LimitExceeded::Bytes {
                    limit: self.limits.max_bytes,
                }
                .into());
            }
            digits.extend(std::iter::repeat_n('0', zeros));
        } else {
            let dropped = usize::try_from(shift.unsigned_abs()).unwrap_or(usize::MAX);
            let trailing_zeros = digits.len() - digits.trim_end_matches('0').len();
            if trailing_zeros < dropped {
                return Err(ParseError::FractionalNumber { offset: start });
            }
            digits.truncate(digits.len() - dropped);
        }
        if digits.len() > limit {
            return Err(too_long);
        }
        if negative {
            digits.insert(0, '-');
        }
        Ok(Integer::from_canonical(digits))
    }
}
