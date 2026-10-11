// SPDX-License-Identifier: Apache-2.0

//! An audit of a registry's whole log.
//!
//! Input: a trust configuration on the first line, then one log entry per
//! line, an empty line, and one document per line.
//!
//! Beyond not panicking: a log that is audited is a segment from the start
//! of the log, the audit is a function of its input, and it reports one
//! claim per receipt.

#![no_main]

use libfuzzer_sys::fuzz_target;
use verified_fuzz::{json, lines};
use verified_verifier::registration::RegistrationTrust;
use verified_verifier::registration::audit::audit;
use verified_verifier::registration::log::check_log;

fuzz_target!(|data: &[u8]| {
    let mut lines = lines(data);
    let trust = lines.next().and_then(json);
    let Some(Ok(trust)) = trust.map(|trust| RegistrationTrust::from_value(&trust)) else {
        return;
    };
    let entries: Vec<&[u8]> = lines.by_ref().take_while(|line| !line.is_empty()).collect();
    let documents: Vec<&[u8]> = lines.collect();
    let audited = audit(&entries, &documents, &trust);
    assert_eq!(
        audited,
        audit(&entries, &documents, &trust),
        "an audit is not repeatable"
    );
    if let Ok(claims) = audited {
        assert!(
            check_log(&entries, None, None, &trust).is_ok(),
            "audited a log that is not a segment"
        );
        assert!(claims.len() <= entries.len(), "more claims than entries");
    }
});
