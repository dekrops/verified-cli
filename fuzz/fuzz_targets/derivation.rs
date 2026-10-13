// SPDX-License-Identifier: Apache-2.0

//! Replaying a recomputed authorization (draft): a trust registry on the
//! first line, then a replay package.
//!
//! Beyond not panicking: a replay is a function of its input. Whatever it
//! arrives at, reproduced or not, it arrives at again.
//!
//! The fuzzer cannot sign, so nearly every changed package stops at its
//! first statement. `derivation_signed` signs again and reaches the rest.

#![no_main]

use libfuzzer_sys::fuzz_target;
use verified_fuzz::{checks, head};

fuzz_target!(|data: &[u8]| {
    let (registry, package) = head(data);
    checks::derivation(registry, package);
});
