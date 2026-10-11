// SPDX-License-Identifier: Apache-2.0

//! What the fuzz targets share: how one fuzz input is split into the
//! several texts a check takes.
//!
//! Canonical JSON holds no line break, so a line break separates texts
//! exactly. Each target documents which line is which. Configuration that a
//! relying party would supply (a trust registry, an anchor) is part of the
//! input as well, so that a seed is self-contained; the fuzzer changing it
//! is harmless, because a target asserts only what holds under any
//! configuration.

pub mod checks;
pub mod resign;

use verified_canonical::{Limits, Value, parse};

/// The limits the command line reads input under.
pub const LIMITS: Limits = Limits::DEFAULT;

/// The input's lines.
pub fn lines(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    data.split(|byte| *byte == b'\n')
}

/// The first line, and everything after its line break.
pub fn head(data: &[u8]) -> (&[u8], &[u8]) {
    match data.iter().position(|byte| *byte == b'\n') {
        Some(end) => (&data[..end], &data[end + 1..]),
        None => (data, &[]),
    }
}

/// A line read as JSON in any spelling, if it is JSON.
pub fn json(line: &[u8]) -> Option<Value> {
    parse(line, &LIMITS).ok()
}

/// A line that may be left empty to mean "not given".
pub fn optional(line: &[u8]) -> Option<&[u8]> {
    (!line.is_empty()).then_some(line)
}

/// A member of an object, if the value is an object that has it.
pub fn member<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    value.as_object()?.get(name)
}
