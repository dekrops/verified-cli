// SPDX-License-Identifier: Apache-2.0

//! The unit of a registered claim.
//!
//! Input: the unit key in hexadecimal on the first line, then the signed
//! agreement, the signed claim and the claim's inputs, one per line.
//!
//! Beyond not panicking: the check is a function of its input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use verified_fuzz::lines;
use verified_work_unit::registered::check_registered_unit;

fuzz_target!(|data: &[u8]| {
    let mut lines = lines(data);
    let Ok(key) = std::str::from_utf8(lines.next().unwrap_or_default()) else {
        return;
    };
    let mut text = || lines.next().unwrap_or_default();
    let (agreement, claim, inputs) = (text(), text(), text());
    let checked = check_registered_unit(agreement, claim, inputs, key);
    assert_eq!(
        checked,
        check_registered_unit(agreement, claim, inputs, key),
        "the check is not repeatable"
    );
});
