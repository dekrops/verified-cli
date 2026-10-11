// SPDX-License-Identifier: Apache-2.0

//! A segment of a registry's log, an anchor and a held entry: see
//! `checks::registry_log` for the input and what is asserted.
//!
//! Signed again: the first line holds test keys, `{ keyId: seedHex }`, and
//! every signature by one of them is made again over the content as the
//! fuzzer left it (`resign`). The rest is the unsigned target's input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use verified_fuzz::{checks, head, resign::Keys};

fuzz_target!(|data: &[u8]| {
    let (keys, rest) = head(data);
    checks::registry_log(&Keys::from_line(keys).resign_lines(rest));
});
