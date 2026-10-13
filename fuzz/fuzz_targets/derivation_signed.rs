// SPDX-License-Identifier: Apache-2.0

//! Replaying a recomputed authorization (draft), signed again. See
//! `checks::derivation` for what is asserted.
//!
//! The first line holds test keys, `{ keyId: seedHex }`; then a trust
//! registry; then a replay package. Every statement signed by one of the
//! keys is signed again over its content as the fuzzer left it, so the
//! preparation, the guards, the call into Cedar and the contract evaluation
//! see authentic statements with arbitrary content. A statement's body is
//! committed to by a digest inside the statement, which is not made again:
//! a changed body is read as a body that was not signed.

#![no_main]

use libfuzzer_sys::fuzz_target;
use verified_fuzz::{checks, head, json, resign::Keys};

fuzz_target!(|data: &[u8]| {
    let (keys, rest) = head(data);
    let (registry, package) = head(rest);
    let Some(package) = json(package) else {
        return;
    };
    let signed = Keys::from_line(keys).resign(&package).to_canonical_string();
    checks::derivation(registry, signed.as_bytes());
});
