// SPDX-License-Identifier: Apache-2.0

//! The checks the fuzz targets run, and what they assert. A target that signs
//! its input again (`*_signed`) runs the same check as the one that does not,
//! so the two differ only in what reaches it.

use verified_canonical::Value;
use verified_derivation::replay;
use verified_verifier::Trust;
use verified_verifier::evidence::{Anchor, admit, authenticate, verify_chain};
use verified_verifier::registration::RegistrationTrust;
use verified_verifier::registration::audit::audit;
use verified_verifier::registration::log::check_log;

use crate::{head, json, lines, member, optional};

/// A trust configuration on the first line, the anchor on the second and the
/// held entry on the third (either may be empty), then one log entry per
/// line. The check is repeatable, and a held entry only adds checks.
pub fn registry_log(data: &[u8]) {
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
}

/// A trust configuration on the first line, then one log entry per line, an
/// empty line, and one document per line. The audit is repeatable, and an
/// audited log is a segment from the start of the log.
pub fn registry_audit(data: &[u8]) {
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
}

fn anchor(context: &Value) -> Option<Anchor> {
    Anchor::from_value(member(context, "anchor")?).ok()
}

fn texts<'a>(context: &'a Value, name: &str) -> Vec<&'a str> {
    let list = member(context, name)
        .and_then(Value::as_array)
        .unwrap_or_default();
    list.iter().filter_map(Value::as_str).collect()
}

/// A trust registry on the first line; on the second an object
/// `{ tenant, claimed, bodies, anchor }`; then one signed statement per
/// line. An anchor that is read reads back from the form it is written in.
pub fn statement(data: &[u8]) {
    let (registry, rest) = head(data);
    let (context, statements) = head(rest);
    let Some(Ok(trust)) = json(registry).map(|registry| Trust::from_value(&registry)) else {
        return;
    };
    let context = json(context).unwrap_or(Value::Null);
    let statements: Vec<Value> = lines(statements).filter_map(json).collect();
    let bodies: Vec<Value> = texts(&context, "bodies")
        .into_iter()
        .filter_map(|body| json(body.as_bytes()))
        .collect();

    let Ok(authentic) = statements
        .iter()
        .map(|statement| authenticate(statement, &trust))
        .collect::<Result<Vec<_>, _>>()
    else {
        return;
    };
    let _ = verify_chain(&authentic, None);
    if let Some(anchor) = anchor(&context) {
        assert_eq!(Anchor::from_value(&anchor.to_value()).as_ref(), Ok(&anchor));
        let _ = verify_chain(&authentic, Some(&anchor));
    }
    let tenant = member(&context, "tenant")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let evidence: Vec<_> = authentic.into_iter().zip(&bodies).collect();
    if let Ok(admitted) = admit(tenant, &texts(&context, "claimed"), &evidence) {
        let _ = admitted.manifest(&Value::Null, &Value::Null, &Value::Null, &Value::Null);
    }
}

/// A trust registry and a replay package (draft). A replay is a function of
/// its input; and what it reports is consistent with itself: every
/// commitment is the digest of its core, a definite authorization names no
/// failed guard, and Cedar's own answer agrees with a definite outcome. So
/// no answer the engine gave beside an evaluation error is ever an outcome.
pub fn derivation(registry: &[u8], package: &[u8]) {
    let Some(Ok(trust)) = json(registry).map(|registry| Trust::from_value(&registry)) else {
        return;
    };
    let Some(package) = json(package) else {
        return;
    };
    let first = replay(&package, &trust);
    let again = replay(&package, &trust);
    assert_eq!(
        first
            .as_ref()
            .map(|replayed| (replayed.commitment, replayed.decision.clone())),
        again
            .as_ref()
            .map(|replayed| (replayed.commitment, replayed.decision.clone())),
        "a replay is not repeatable"
    );
    let Ok(replayed) = first else {
        return;
    };
    assert_eq!(replayed.core.digest(), replayed.commitment);
    for derivation in &replayed.derivations {
        assert_eq!(derivation.core.digest(), derivation.commitment);
        let errors = member(&derivation.diagnostics, "errors")
            .and_then(Value::as_array)
            .map_or(0, <[Value]>::len);
        match derivation.outcome {
            "ALLOW" => assert_eq!(derivation.engine_decision, Some("Allow")),
            "DENY" => assert_eq!(derivation.engine_decision, Some("Deny")),
            _ => assert!(
                !derivation.reasons.is_empty(),
                "undetermined without a reason"
            ),
        }
        if derivation.outcome != "UNDETERMINED" {
            assert!(
                derivation.reasons.is_empty(),
                "a definite outcome with a failed guard"
            );
            assert_eq!(errors, 0, "a definite outcome beside an evaluation error");
        }
    }
}
