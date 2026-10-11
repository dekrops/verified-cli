// SPDX-License-Identifier: Apache-2.0

//! An audit of a registry's whole log: see `checks::registry_audit` for the
//! input and what is asserted.

#![no_main]

use libfuzzer_sys::fuzz_target;
use verified_fuzz::checks;

fuzz_target!(|data: &[u8]| {
    checks::registry_audit(data);
});
