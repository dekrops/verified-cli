// SPDX-License-Identifier: Apache-2.0

//! Draft WVP RFC 0013 (completeness per group), behind the `draft-wvp-0013`
//! feature. The cases follow the examples the RFC's Lean model proves by
//! `decide` (`rfcs/0013/formal/WCL2G/Examples.lean`), and the refusals it
//! lists.
#![cfg(feature = "draft-wvp-0013")]

use verified_canonical::{Limits, Value, parse};
use verified_contract::{Contract, Decision, Language, Refusal};

fn json(text: &str) -> Value {
    parse(text.as_bytes(), &Limits::DEFAULT).expect("JSON")
}

const EUR: &str = r#"{"currency":"EUR","scale":2,"type":"money"}"#;

fn contract(requires: &str) -> Value {
    json(&format!(
        r#"{{"evaluation":{{"semantics":"kleene-1"}},"evidence":{{"conflicts":"unknown","sources":{{"approval":["erp"],"payment":["erp"]}}}},"identity":{{"id":"groups","version":"1"}},"inputs":{{"invoice":{{"type":"text"}}}},"kinds":{{"approval":{{"fields":{{"id":{{"type":"text"}},"invoice":{{"type":"text"}}}},"key":["id"]}},"payment":{{"fields":{{"amount":{EUR},"id":{{"type":"text"}},"invoice":{{"type":"text"}},"note":{{"optional":true,"type":"text"}}}},"key":["id"]}}}},"language":"work-contract-2","policy":{{}},"requires":{requires}}}"#
    ))
}

const THIS_INVOICE: &str = r#"{"input":"invoice"}"#;

fn per(field: &str, is: &str) -> String {
    format!(r#","per":{{"field":"{field}","is":{is}}}"#)
}

/// Σ payments of the invoice ≤ 100.00, over its group or (today's form) the
/// whole kind.
fn paid(grouped: bool) -> String {
    let group = if grouped {
        per("invoice", THIS_INVOICE)
    } else {
        String::new()
    };
    format!(
        r#"[{{"id":"PAID","predicate":{{"cmp":"le","left":{{"aggregate":"sum","field":"amount","in":"payment","of":"p"{group},"where":{{"cmp":"eq","left":{{"field":"invoice","var":"p"}},"right":{THIS_INVOICE}}}}},"right":{{"lit":"10000","of":{EUR}}}}}}}]"#
    )
}

/// Some approval of the invoice.
fn approved(grouped: bool) -> String {
    let group = if grouped {
        per("invoice", THIS_INVOICE)
    } else {
        String::new()
    };
    format!(
        r#"[{{"id":"APPROVED","predicate":{{"exists":"a","in":"approval"{group},"where":{{"cmp":"eq","left":{{"field":"invoice","var":"a"}},"right":{THIS_INVOICE}}}}}}}]"#
    )
}

fn payment(id: &str, invoice: &str, amount: &str) -> String {
    format!(
        r#"{{"fields":{{"amount":"{amount}","id":"{id}","invoice":"{invoice}"}},"id":"payment.{id}","kind":"payment","source":"erp"}}"#
    )
}

fn approval(id: &str, invoice: &str) -> String {
    format!(
        r#"{{"fields":{{"id":"{id}","invoice":"{invoice}"}},"id":"approval.{id}","kind":"approval","source":"erp"}}"#
    )
}

/// INV-01 paid 60.00 + 40.00, INV-02 25.00. Facts are sorted by id here.
fn payments() -> Vec<String> {
    vec![
        payment("P1", "INV-01", "6000"),
        payment("P2", "INV-01", "4000"),
        payment("P3", "INV-02", "2500"),
    ]
}

fn group_statement(kind: &str, covers: &str, values: &[&str]) -> String {
    let values: Vec<String> = values.iter().map(|v| format!(r#""{v}""#)).collect();
    format!(
        r#"{{"asOf":"0","{covers}":[{}],"kind":"{kind}","per":"invoice","source":"erp"}}"#,
        values.join(",")
    )
}

fn environment(invoice: &str, mut facts: Vec<String>, complete: &[String]) -> Value {
    // In order of the fact id, the last `"id"` member of each fact.
    facts.sort_by_key(|f| f.rfind(r#""id":""#).map(|at| f[at..].to_owned()));
    json(&format!(
        r#"{{"complete":[{}],"facts":[{}],"inputs":{{"invoice":"{invoice}"}}}}"#,
        complete.join(","),
        facts.join(",")
    ))
}

fn only_inv01() -> Vec<String> {
    vec![
        group_statement("approval", "only", &["INV-01"]),
        group_statement("payment", "only", &["INV-01"]),
    ]
}

fn read(requires: &str) -> Result<Contract, Refusal> {
    Contract::read_as(&contract(requires), Language::Two)
}

fn decide(requires: &str, env: &Value) -> Decision {
    read(requires)
        .expect("well formed")
        .evaluate(env)
        .expect("evaluated")
        .decision
}

#[test]
fn paid_within_approval_decided_with_per() {
    let env = environment("INV-01", payments(), &only_inv01());
    assert_eq!(decide(&paid(true), &env), Decision::Supported);
}

#[test]
fn today_form_stays_undetermined() {
    let env = environment("INV-01", payments(), &only_inv01());
    assert_eq!(decide(&paid(false), &env), Decision::Undetermined);
}

#[test]
fn group_not_covered_stays_undetermined() {
    let env = environment("INV-02", payments(), &only_inv01());
    assert_eq!(decide(&paid(true), &env), Decision::Undetermined);
}

#[test]
fn overpayment_in_a_complete_group_is_caught() {
    let mut facts = payments();
    facts.push(payment("P0", "INV-01", "3000"));
    let env = environment("INV-01", facts, &only_inv01());
    assert_eq!(decide(&paid(true), &env), Decision::Contradicted);
}

#[test]
fn missing_approval_found_only_with_per() {
    let mut facts = payments();
    facts.push(approval("A9", "INV-02"));
    let env = environment("INV-01", facts, &only_inv01());
    assert_eq!(decide(&approved(true), &env), Decision::Contradicted);
    assert_eq!(decide(&approved(false), &env), Decision::Undetermined);
}

#[test]
fn a_group_names_one_value() {
    let env = environment("INV-010", payments(), &only_inv01());
    assert_eq!(decide(&paid(true), &env), Decision::Undetermined);
}

#[test]
fn except_decides_every_other_group() {
    let complete = [group_statement("payment", "except", &["INV-02"])];
    let decide_for = |invoice| decide(&paid(true), &environment(invoice, payments(), &complete));
    assert_eq!(decide_for("INV-01"), Decision::Supported);
    // No payments at all, in a covered group: nothing paid.
    assert_eq!(decide_for("INV-03"), Decision::Supported);
    assert_eq!(decide_for("INV-02"), Decision::Undetermined);
}

#[test]
fn a_group_statement_is_per_kind() {
    let complete = [group_statement("payment", "only", &["INV-01"])];
    let env = environment("INV-01", payments(), &complete);
    assert_eq!(decide(&approved(true), &env), Decision::Undetermined);
}

#[test]
fn a_record_outside_a_closed_group_changes_nothing() {
    let complete = [group_statement("payment", "only", &["INV-01"])];
    let mut more = payments();
    more.push(payment("P4", "INV-02", "999999"));
    for facts in [payments(), more] {
        let env = environment("INV-01", facts, &complete);
        assert_eq!(decide(&paid(true), &env), Decision::Supported);
    }
}

#[test]
fn a_whole_kind_statement_still_closes_every_group() {
    let complete = [r#"{"asOf":"0","kind":"payment","source":"erp"}"#.to_owned()];
    let env = environment("INV-02", payments(), &complete);
    assert_eq!(decide(&paid(true), &env), Decision::Supported);
}

#[test]
fn an_unsettled_conflict_opens_every_group() {
    let mut facts = payments();
    // A second fact for P2 with another amount: a conflict, unsettled.
    facts.push(
        r#"{"fields":{"amount":"1","id":"P2","invoice":"INV-01"},"id":"payment.P2b","kind":"payment","source":"erp"}"#
            .to_owned(),
    );
    let env = environment("INV-01", facts, &only_inv01());
    assert_eq!(decide(&paid(true), &env), Decision::Undetermined);
}

#[test]
fn per_must_name_a_required_field_of_the_right_type() {
    let ill = |requires: String| {
        assert_eq!(
            read(&requires).expect_err("refused"),
            Refusal::ContractIllFormed
        );
    };
    // An optional field.
    ill(paid(true).replace(r#""field":"invoice","is""#, r#""field":"note","is""#));
    // An undeclared field.
    ill(paid(true).replace(r#""field":"invoice","is""#, r#""field":"order","is""#));
    // A term of another type.
    ill(paid(true).replace(
        r#""is":{"input":"invoice"}"#,
        &format!(r#""is":{{"lit":"1","of":{EUR}}}"#),
    ));
    // The quantifier's own variable, which isn't bound where `is` is read.
    ill(paid(true).replace(
        r#""is":{"input":"invoice"}"#,
        r#""is":{"field":"invoice","var":"p"}"#,
    ));
}

#[test]
fn per_has_exactly_field_and_is() {
    let malformed = paid(true).replace(
        r#""per":{"field":"invoice","#,
        r#""per":{"extra":"x","field":"invoice","#,
    );
    assert_eq!(
        read(&malformed).expect_err("refused"),
        Refusal::ContractMalformed
    );
}

#[test]
fn group_statements_are_checked() {
    let c = read(&paid(true)).expect("well formed");
    let evaluate = |complete: &str| {
        c.evaluate(&environment("INV-01", payments(), &[complete.to_owned()]))
            .map(|o| o.decision)
    };
    // Both `only` and `except`, or a field the kind doesn't declare.
    assert_eq!(
        evaluate(
            r#"{"asOf":"0","except":[],"kind":"payment","only":[],"per":"invoice","source":"erp"}"#
        ),
        Err(Refusal::EnvironmentMalformed)
    );
    assert_eq!(
        evaluate(r#"{"asOf":"0","kind":"payment","only":["INV-01"],"per":"order","source":"erp"}"#),
        Err(Refusal::EnvironmentNonconforming)
    );
    // An optional field, or a value of another type.
    assert_eq!(
        evaluate(r#"{"asOf":"0","kind":"payment","only":["x"],"per":"note","source":"erp"}"#),
        Err(Refusal::EnvironmentNonconforming)
    );
    assert_eq!(
        evaluate(r#"{"asOf":"0","kind":"payment","only":[true],"per":"invoice","source":"erp"}"#),
        Err(Refusal::EnvironmentNonconforming)
    );
}

#[test]
fn a_whole_kind_statement_comes_before_a_group_statement() {
    let c = read(&paid(true)).expect("well formed");
    let whole = r#"{"asOf":"0","kind":"payment","source":"erp"}"#.to_owned();
    let group = group_statement("payment", "only", &["INV-01"]);
    let evaluate = |complete: &[String]| {
        c.evaluate(&environment("INV-01", payments(), complete))
            .map(|o| o.decision)
    };
    assert_eq!(
        evaluate(&[whole.clone(), group.clone()]),
        Ok(Decision::Supported)
    );
    assert_eq!(
        evaluate(&[group, whole]),
        Err(Refusal::EnvironmentMalformed)
    );
}
