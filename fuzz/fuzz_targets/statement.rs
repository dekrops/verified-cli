// SPDX-License-Identifier: Apache-2.0

//! Evidence statements: authentication, chains and admission. See
//! `checks::statement` for the input and what is asserted.

#![no_main]

use libfuzzer_sys::fuzz_target;
use verified_fuzz::checks;

fuzz_target!(|data: &[u8]| {
    checks::statement(data);
});
