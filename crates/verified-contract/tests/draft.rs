// SPDX-License-Identifier: Apache-2.0

//! Draft forms of WVP RFC 0011 (aggregates as terms, `mul`) and RFC 0012
//! (`appliesWhen`, `NOT_APPLICABLE`), behind the `draft-wvp-0011-0012`
//! feature. The RFCs' own vectors are proposals in dekrops/wvp#54 and #55;
//! these are a few of their cases, inline.
#![cfg(feature = "draft-wvp-0011-0012")]

use verified_canonical::{Limits, Value, parse};
use verified_contract::{Contract, Decision, Language};

fn json(text: &str) -> Value {
    parse(text.as_bytes(), &Limits::DEFAULT).expect("JSON")
}

/// A contract over invoices and their rate groups, with the given requirements.
fn contract(requires: &str) -> String {
    format!(
        r#"{{"evaluation":{{"semantics":"kleene-1"}},"evidence":{{"conflicts":"unknown","sources":{{"invoice":["erp"],"rateGroup":["erp"]}}}},"identity":{{"id":"draft","version":"1"}},"inputs":{{"invoice":{{"type":"text"}}}},"kinds":{{"invoice":{{"fields":{{"gross":{{"currency":"EUR","scale":2,"type":"money"}},"id":{{"type":"text"}},"reverseCharge":{{"type":"bool"}}}},"key":["id"]}},"rateGroup":{{"fields":{{"id":{{"type":"text"}},"invoice":{{"type":"text"}},"net":{{"currency":"EUR","scale":2,"type":"money"}},"rateBps":{{"type":"int"}},"tax":{{"currency":"EUR","scale":2,"type":"money"}}}},"key":["id"]}}}},"language":"work-contract-2","policy":{{}},"requires":{requires}}}"#
    )
}

const THE_INVOICE: &str =
    r#"{"cmp":"eq","left":{"field":"id","var":"i"},"right":{"input":"invoice"}}"#;
const OF_THIS: &str =
    r#"{"cmp":"eq","left":{"field":"invoice","var":"g"},"right":{"field":"id","var":"i"}}"#;

/// Σ net + Σ tax = gross, for the invoice asked about.
fn adds_up_predicate() -> String {
    let sum = |field: &str| {
        format!(
            r#"{{"aggregate":"sum","field":"{field}","in":"rateGroup","of":"g","where":{OF_THIS}}}"#
        )
    };
    format!(
        r#"{{"exists":"i","in":"invoice","where":{{"and":[{THE_INVOICE},{{"cmp":"eq","left":{{"add":[{},{}]}},"right":{{"field":"gross","var":"i"}}}}]}}}}"#,
        sum("net"),
        sum("tax")
    )
}

fn adds_up() -> String {
    format!(
        r#"[{{"id":"ADDS_UP","predicate":{}}}]"#,
        adds_up_predicate()
    )
}

fn environment(gross: &str, reverse_charge: bool, closed: bool) -> Value {
    let complete = if closed {
        r#"[{"asOf":"0","kind":"invoice","source":"erp"},{"asOf":"0","kind":"rateGroup","source":"erp"}]"#
    } else {
        r#"[{"asOf":"0","kind":"invoice","source":"erp"}]"#
    };
    json(&format!(
        r#"{{"complete":{complete},"facts":[{{"fields":{{"gross":"{gross}","id":"INV-1","reverseCharge":{reverse_charge}}},"id":"f1","kind":"invoice","source":"erp"}},{{"fields":{{"id":"G-1","invoice":"INV-1","net":"16803","rateBps":"1900","tax":"3193"}},"id":"f2","kind":"rateGroup","source":"erp"}}],"inputs":{{"invoice":"INV-1"}}}}"#
    ))
}

fn read(requires: &str) -> Result<Contract, verified_contract::Refusal> {
    Contract::read_as(&json(&contract(requires)), Language::Two)
}

#[test]
fn two_sums_added_compare_with_the_gross() {
    let c = read(&adds_up()).expect("well formed");
    let decide = |gross: &str, closed| {
        c.evaluate(&environment(gross, false, closed))
            .expect("evaluated")
            .decision
    };
    assert_eq!(decide("19996", true), Decision::Supported);
    assert_eq!(decide("19997", true), Decision::Contradicted);
    // Rate groups not closed: neither sum has a value.
    assert_eq!(decide("19996", false), Decision::Undetermined);
}

#[test]
fn mul_needs_an_int_operand() {
    let product = |left: &str| {
        format!(
            r#"[{{"id":"R","predicate":{{"forall":"g","in":"rateGroup","holds":{{"cmp":"le","left":{{"mul":[{left},{{"field":"net","var":"g"}}]}},"right":{{"field":"net","var":"g"}}}}}}}}]"#
        )
    };
    assert!(read(&product(r#"{"field":"rateBps","var":"g"}"#)).is_ok());
    let refused = read(&product(r#"{"field":"tax","var":"g"}"#)).expect_err("money times money");
    assert_eq!(refused.as_str(), "CONTRACT_ILL_FORMED");
}

#[test]
fn a_condition_that_is_false_makes_the_requirement_not_applicable() {
    let requires = format!(
        r#"[{{"appliesWhen":{{"exists":"i","in":"invoice","where":{{"and":[{THE_INVOICE},{{"cmp":"eq","left":{{"field":"reverseCharge","var":"i"}},"right":{{"lit":false,"of":{{"type":"bool"}}}}}}]}}}},"id":"ADDS_UP","predicate":{}}}]"#,
        adds_up_predicate()
    );
    let c = read(&requires).expect("well formed");
    // Under reverse charge the only requirement doesn't apply, whatever its
    // predicate says.
    let outcome = c
        .evaluate(&environment("1", true, true))
        .expect("evaluated");
    assert_eq!(outcome.decision, Decision::NotApplicable);
    assert_eq!(outcome.requirements[0].as_str(), "NOT_APPLICABLE");
    let outcome = c
        .evaluate(&environment("1", false, true))
        .expect("evaluated");
    assert_eq!(outcome.decision, Decision::Contradicted);
}

#[test]
fn language_1_reads_none_of_the_draft_forms() {
    let one = contract(&adds_up()).replace("work-contract-2", "work-contract-1");
    let refused = Contract::read_as(&json(&one), Language::One).expect_err("not Language 1");
    assert_eq!(refused.as_str(), "CONTRACT_MALFORMED");
}
