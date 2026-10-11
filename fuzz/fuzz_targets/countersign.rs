// SPDX-License-Identifier: Apache-2.0

//! Countersigning a package, and the bytes an issuer signs.
//!
//! Input: a trust registry on the first line, a list of countersignatures
//! `[{ keyId, encoded }…]` on the second, then the package.
//!
//! Beyond not panicking: a package that passes verification has a signing
//! input, and a countersigned package keeps its identifier and is accepted
//! by a verifier holding the same registry, with the same complete report
//! and an issuer signature that counts.

#![no_main]

use libfuzzer_sys::fuzz_target;
use verified_canonical::Value;
use verified_fuzz::{head, json, member};
use verified_verifier::issue::{Countersignature, countersign, decision_signing_input};
use verified_verifier::{IssuerSignature, Options, Trust, verify};

fuzz_target!(|data: &[u8]| {
    let (registry, rest) = head(data);
    let (signatures, package) = head(rest);
    let Some(Ok(trust)) = json(registry).map(|registry| Trust::from_value(&registry)) else {
        return;
    };
    let options = Options {
        trust: Some(&trust),
        ..Options::default()
    };
    let verified = verify(package, &options);
    let signing_input = decision_signing_input(package);
    if verified.is_ok() {
        assert!(
            signing_input.is_ok(),
            "a verified package has no signing input"
        );
    }

    let signatures = json(signatures).unwrap_or(Value::Null);
    let signatures: Vec<Countersignature<'_>> = signatures
        .as_array()
        .unwrap_or_default()
        .iter()
        .filter_map(|signature| {
            Some(Countersignature {
                key_id: member(signature, "keyId")?.as_str()?,
                encoded: member(signature, "encoded")?.as_str()?,
            })
        })
        .collect();
    let Ok(issued) = countersign(package, &signatures, &trust) else {
        return;
    };
    let report = verify(issued.package.as_bytes(), &options);
    assert_eq!(
        report.as_ref(),
        Ok(&issued.report),
        "a verifier does not accept the countersigned package"
    );
    assert!(issued.report.is_complete());
    assert!(matches!(
        issued.report.issuer_signature,
        IssuerSignature::Established { .. }
    ));
    if let Ok(original) = verified {
        assert_eq!(
            original.package_id, issued.report.package_id,
            "countersigning changed the identifier"
        );
    }
});
