// SPDX-License-Identifier: Apache-2.0

//! Producing a relation: laying out the statement that carries it.
//!
//! An authority states how records it knows are related. The layout is
//! here, beside the reader that checks it, so that the two cannot disagree:
//! the body is read back with `Relation::from_value` and the statement with
//! the statement reader before either is returned. This module holds no
//! key. The caller signs over
//! [`verified_verifier::evidence::statement_signing_input`], attaches the
//! signature with [`verified_verifier::evidence::signed_statement`], and
//! can then [`crate::read`] the result as a relying party would.
//!
//! Laying out a relation says nothing about whether it is true, or whether
//! any relying party trusts the key it will be signed with.

use verified_canonical::{Object, Value};
use verified_protocol::relation::{RELATION_STATEMENT_KIND, RELATION_SUBJECT_KIND, Relation};
use verified_verifier::evidence::{
    EvidenceCode, EvidenceRefusal, StatementDraft, Step, prepare_statement,
};

/// The members an authority states besides those the relation fixes.
const STATED: [&str; 5] = ["id", "issuer", "observedAt", "source", "tenant"];

/// What a relation's statement is made from.
#[derive(Clone, Copy, Debug)]
pub struct RelationDraft<'a> {
    /// What the authority says.
    pub relation: &'a Relation<'a>,
    /// The members the authority states, as the statement carries them:
    /// exactly `id`, `issuer`, `observedAt`, `source` and `tenant`. The
    /// statement's `kind` and `subject` follow from the relation and the
    /// source, and are not taken from here.
    pub stated: &'a Value,
    /// The statement's place in the authority's stream. An authority that
    /// wants to show it has left nothing out chains its relations in a
    /// stream of their own.
    pub step: Step<'a>,
}

/// A relation laid out for signing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedRelation {
    /// The unsigned statement. Its payload commits to `body`.
    pub statement: Value,
    /// The relation body, which travels with the signed statement.
    pub body: Value,
}

fn malformed<T>(detail: impl Into<String>) -> Result<T, EvidenceRefusal> {
    Err(EvidenceRefusal {
        code: EvidenceCode::Malformed,
        detail: detail.into(),
    })
}

fn text(value: &str) -> Value {
    Value::String(value.to_owned())
}

fn object<const N: usize>(members: [(&str, Value); N]) -> Value {
    Value::Object(
        members
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect::<Object>(),
    )
}

/// The unsigned statement that carries `draft.relation`, with its body.
///
/// # Errors
///
/// `MALFORMED` for a relation the reader would refuse (for example a group
/// with no members, or with members out of order), for stated members other
/// than exactly the five, or for a statement the protocol's reader refuses.
pub fn prepare_relation(draft: &RelationDraft<'_>) -> Result<PreparedRelation, EvidenceRefusal> {
    let body = draft.relation.to_value();
    if Relation::from_value(&body).as_ref() != Ok(draft.relation) {
        return malformed("the relation is not one a reader accepts");
    }
    let Some(stated) = draft.stated.as_object().filter(|o| o.has_exactly(&STATED)) else {
        return malformed(format!(
            "a relation's stated members are exactly {STATED:?}"
        ));
    };
    let system = stated
        .get("source")
        .and_then(Value::as_object)
        .and_then(|source| source.get("system"))
        .and_then(Value::as_str);
    let Some(system) = system else {
        return malformed("source.system is text");
    };
    let mut members: Object = stated
        .iter()
        .map(|(name, value)| (name.to_owned(), value.clone()))
        .collect();
    members.insert(
        "kind",
        object([(RELATION_STATEMENT_KIND, Value::Object(Object::new()))]),
    );
    members.insert(
        "subject",
        object([
            ("key", text(draft.relation.key())),
            ("kind", text(RELATION_SUBJECT_KIND)),
            ("system", text(system)),
        ]),
    );
    let statement = prepare_statement(&StatementDraft {
        stated: &Value::Object(members),
        body: &body,
        step: draft.step,
    })?;
    Ok(PreparedRelation { statement, body })
}
