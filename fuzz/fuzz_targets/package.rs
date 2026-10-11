// SPDX-License-Identifier: Apache-2.0

//! Package verification and inspection.
//!
//! Input: a trust registry on the first line, then the package. A first
//! line that is not a registry means none is given.
//!
//! Beyond not panicking: verification is a function of its input, and
//! inspection refuses whatever verification refuses, for the same reason,
//! and otherwise carries the same report.

#![no_main]

use libfuzzer_sys::fuzz_target;
use verified_fuzz::{head, json};
use verified_verifier::{Options, Trust, inspect, verify};

fuzz_target!(|data: &[u8]| {
    let (registry, package) = head(data);
    let trust = json(registry).and_then(|registry| Trust::from_value(&registry).ok());
    // Without a registry first: every package is also read that way.
    for trust in [None, trust.as_ref()]
        .into_iter()
        .take(1 + usize::from(trust.is_some()))
    {
        let options = Options {
            trust,
            ..Options::default()
        };
        let verified = verify(package, &options);
        assert_eq!(
            verified,
            verify(package, &options),
            "verification is not repeatable"
        );
        match (verified, inspect(package, &options)) {
            (Ok(report), Ok(inspection)) => assert_eq!(report, inspection.report),
            (Err(verifying), Err(inspecting)) => assert_eq!(verifying, inspecting),
            (Err(refusal), Ok(_)) => {
                panic!("inspected a package that verification refuses: {refusal}")
            }
            // Inspection reads more of a package than verification needs,
            // and may refuse what it cannot read.
            (Ok(_), Err(_)) => {}
        }
    }
});
