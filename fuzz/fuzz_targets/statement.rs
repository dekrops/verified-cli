// SPDX-License-Identifier: Apache-2.0

//! Evidence statements: authentication, chains and admission.
//!
//! Input: a trust registry on the first line; on the second an object
//! `{ tenant, claimed, bodies, anchor }` holding what a relying party
//! supplies beside the statements (any member may be missing); then one
//! signed statement per line.
//!
//! Beyond not panicking: an anchor that is read reads back from the form it
//! is written in.

#![no_main]

use libfuzzer_sys::fuzz_target;
use verified_canonical::Value;
use verified_fuzz::{head, json, lines, member};
use verified_verifier::Trust;
use verified_verifier::evidence::{Anchor, admit, authenticate, verify_chain};

fn anchor(context: &Value) -> Option<Anchor> {
    Anchor::from_value(member(context, "anchor")?).ok()
}

fn texts<'a>(context: &'a Value, name: &str) -> Vec<&'a str> {
    let list = member(context, name)
        .and_then(Value::as_array)
        .unwrap_or_default();
    list.iter().filter_map(Value::as_str).collect()
}

fuzz_target!(|data: &[u8]| {
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
});
