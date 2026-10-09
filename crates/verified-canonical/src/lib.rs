//! `verified-json-v1` canonical encoding and the commitments built on it.
//!
//! Every hash and signature in the Work Verification Protocol (WVP, a draft)
//! is taken over one byte form of a JSON value. This crate is that byte form:
//!
//! - [`parse`] reads untrusted JSON text into a [`Value`] under explicit
//!   [`Limits`];
//! - [`Value::to_canonical_string`] writes the one canonical text of a value;
//! - [`parse_canonical`] additionally refuses text that is not already in that
//!   form;
//! - [`Sha256Digest`] commits to canonical bytes;
//! - [`SigningDomain`] prepares domain-separated signing input.
//!
//! # The encoding
//!
//! `verified-json-v1` is **not** RFC 8785.
//!
//! - Object members are ordered by key, comparing UTF-16 code units.
//! - Arrays keep their order. `null` members stay.
//! - Numbers are integers of any size in plain decimal: no fraction, no
//!   exponent, no leading zero, no negative zero. Input spellings that denote
//!   an integer (`1.0`, `1e3`, `100e-2`, `-0`) are read as that integer; a
//!   number with a fractional part is refused.
//! - Strings are Unicode scalar values, never normalized. An unpaired
//!   surrogate escape is refused.
//! - Output is UTF-8 without a byte-order mark or insignificant whitespace.
//!   `"` and `\` are escaped, as are backspace, tab, line feed, form feed and
//!   carriage return (short forms); every other character in
//!   U+0000–U+001F and U+007F–U+009F is written as lowercase `\u00xx`. A
//!   solidus is not escaped.
//!
//! The value model has no duplicate keys, so [`parse`] refuses an object that
//! repeats one rather than choosing a winner.
//!
//! Plain `serde` serialization is deliberately not involved: its output is
//! not canonical, and its number model cannot hold these integers exactly.

mod digest;
mod domain;
mod encode;
mod parse;
mod value;

pub use digest::{DigestParseError, Sha256Digest};
pub use domain::{InvalidDomain, SigningDomain};
pub use parse::{
    CanonicalError, LimitExceeded, Limits, ParseError, SyntaxError, parse, parse_canonical,
};
pub use value::{Integer, Object, Value, cmp_keys};

/// The identifier of the canonical encoding this crate implements.
pub const CANONICAL_VERSION: &str = "verified-json-v1";
