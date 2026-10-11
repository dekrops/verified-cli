// SPDX-License-Identifier: Apache-2.0

//! A segment of a registry's log, an anchor and a held entry: see
//! `checks::registry_log` for the input and what is asserted.

#![no_main]

use libfuzzer_sys::fuzz_target;
use verified_fuzz::checks;

fuzz_target!(|data: &[u8]| {
    checks::registry_log(data);
});
