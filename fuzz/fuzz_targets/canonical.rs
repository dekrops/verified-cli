// SPDX-License-Identifier: Apache-2.0

//! The JSON reader and the canonical encoding.
//!
//! Input: any bytes.
//!
//! Beyond not panicking: a value that was read encodes to canonical text
//! that reads back as the same value, and text is accepted as canonical
//! exactly when it is that encoding.

#![no_main]

use libfuzzer_sys::fuzz_target;
use verified_canonical::{parse, parse_canonical};
use verified_fuzz::LIMITS;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = parse(data, &LIMITS) else {
        assert!(
            parse_canonical(data, &LIMITS).is_err(),
            "text that is not JSON was accepted as canonical"
        );
        return;
    };
    let canonical = value.to_canonical_string();
    assert_eq!(
        parse_canonical(canonical.as_bytes(), &LIMITS).as_ref(),
        Ok(&value),
        "the canonical text of a value does not read back as that value"
    );
    assert_eq!(
        parse_canonical(data, &LIMITS).is_ok(),
        data == canonical.as_bytes(),
        "text is canonical exactly when it is the canonical encoding"
    );
    assert_eq!(
        value.digest(),
        parse(canonical.as_bytes(), &LIMITS)
            .map(|v| v.digest())
            .expect("read above")
    );
});
