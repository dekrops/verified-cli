// SPDX-License-Identifier: Apache-2.0

//! A segment of a registry's log, an anchor and a held entry.
//!
//! Input: a trust configuration on the first line, the anchor on the second
//! and the held entry on the third (either may be left empty), then one log
//! entry per line.
//!
//! Beyond not panicking: the check is a function of its input, and a held
//! entry only adds checks, so a segment is accepted without one whenever it
//! is accepted with one, and is then the same segment.

#![no_main]

use libfuzzer_sys::fuzz_target;
use verified_fuzz::{json, lines, optional};
use verified_verifier::registration::RegistrationTrust;
use verified_verifier::registration::log::check_log;

fuzz_target!(|data: &[u8]| {
    let mut lines = lines(data);
    let trust = lines.next().and_then(json);
    let Some(Ok(trust)) = trust.map(|trust| RegistrationTrust::from_value(&trust)) else {
        return;
    };
    let anchor = lines.next().and_then(optional);
    let held = lines.next().and_then(optional);
    let entries: Vec<&[u8]> = lines.collect();
    let checked = check_log(&entries, anchor, held, &trust);
    assert_eq!(
        checked,
        check_log(&entries, anchor, held, &trust),
        "the check is not repeatable"
    );
    if let Ok(checked) = checked {
        let Ok(alone) = check_log(&entries, anchor, None, &trust) else {
            panic!("a segment accepted with a held entry is refused without it");
        };
        assert_eq!(checked.segment, alone.segment);
        assert_eq!(checked.inclusion.is_some(), held.is_some());
    }
});
