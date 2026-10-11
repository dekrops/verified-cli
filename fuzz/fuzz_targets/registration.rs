// SPDX-License-Identifier: Apache-2.0

//! Claim registration: an agreement, a claim and a receipt.
//!
//! Input: a trust configuration on the first line, then the signed
//! agreement, the signed claim and the signed receipt, one per line.
//!
//! Beyond not panicking: a registration is a function of its input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use verified_fuzz::{json, lines};
use verified_verifier::registration::{RegistrationTrust, verify_registration};

fuzz_target!(|data: &[u8]| {
    let mut lines = lines(data);
    let trust = lines.next().and_then(json);
    let Some(Ok(trust)) = trust.map(|trust| RegistrationTrust::from_value(&trust)) else {
        return;
    };
    let mut text = || lines.next().unwrap_or_default();
    let (agreement, claim, receipt) = (text(), text(), text());
    let registration = verify_registration(agreement, claim, receipt, &trust);
    assert_eq!(
        registration,
        verify_registration(agreement, claim, receipt, &trust),
        "verification is not repeatable"
    );
});
