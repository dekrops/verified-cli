// SPDX-License-Identifier: Apache-2.0

//! Issuing a `wvp-0.2` package from a draft.
//!
//! Input: a trust registry on the first line, then a draft as one object:
//! `{ tenant, contract, claim, claimant, inputs, submittedAt,
//! evidence: [[statement, body]…], evidenceSet, ingestedAt, assembledAt,
//! evaluatedAt }`.
//!
//! Beyond not panicking: issuing is repeatable, and an issued package is
//! canonical text that a verifier holding the same registry accepts with
//! the same complete report. It carries no issuer signature, so
//! countersigning it with none is not a countersigned package.

#![no_main]

use libfuzzer_sys::fuzz_target;
use verified_canonical::{Value, parse_canonical};
use verified_fuzz::{LIMITS, head, json, member};
use verified_protocol::ProtocolVersion;
use verified_verifier::issue::{Draft, IssueError, countersign, decision_signing_input, issue};
use verified_verifier::{IssuerSignature, Options, ProtocolSelection, Trust, verify};

fn text<'a>(draft: &'a Value, name: &str) -> Option<&'a str> {
    member(draft, name)?.as_str()
}

fuzz_target!(|data: &[u8]| {
    let (registry, draft) = head(data);
    let Some(Ok(trust)) = json(registry).map(|registry| Trust::from_value(&registry)) else {
        return;
    };
    let Some(draft) = json(draft) else { return };
    let Some(evidence) = member(&draft, "evidence").and_then(Value::as_array) else {
        return;
    };
    let Some(evidence) = evidence
        .iter()
        .map(|pair| match pair.as_array()? {
            [statement, body] => Some((statement, body)),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()
    else {
        return;
    };
    let (Some(contract), Some(inputs)) = (member(&draft, "contract"), member(&draft, "inputs"))
    else {
        return;
    };
    let texts = [
        "tenant",
        "claim",
        "claimant",
        "submittedAt",
        "evidenceSet",
        "ingestedAt",
        "assembledAt",
        "evaluatedAt",
    ]
    .map(|name| text(&draft, name).unwrap_or_default());
    let [
        tenant,
        claim,
        claimant,
        submitted_at,
        evidence_set,
        ingested_at,
        assembled_at,
        evaluated_at,
    ] = texts;
    let draft = Draft {
        tenant,
        contract,
        claim,
        claimant,
        inputs,
        submitted_at,
        evidence: &evidence,
        evidence_set,
        ingested_at,
        assembled_at,
        evaluated_at,
    };

    let issued = issue(&draft, &trust);
    assert_eq!(issued, issue(&draft, &trust), "issuing is not repeatable");
    let Ok(issued) = issued else { return };
    let package = issued.package.as_bytes();
    assert!(
        parse_canonical(package, &LIMITS).is_ok(),
        "an issued package is not canonical"
    );
    assert!(
        issued.report.is_complete(),
        "an issued package's report is incomplete"
    );
    assert_eq!(issued.report.issuer_signature, IssuerSignature::Absent);
    let options = Options {
        protocol: ProtocolSelection::Require(ProtocolVersion::V0_2),
        trust: Some(&trust),
        ..Options::default()
    };
    assert_eq!(
        verify(package, &options),
        Ok(issued.report),
        "a verifier with the issuer's registry does not accept what was issued"
    );
    assert!(decision_signing_input(package).is_ok());
    assert!(matches!(
        countersign(package, &[], &trust),
        Err(IssueError::Draft(_))
    ));
});
