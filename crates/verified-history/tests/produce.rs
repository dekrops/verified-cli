// SPDX-License-Identifier: Apache-2.0

//! Producing a relation and reading it back, on synthetic records. Runs
//! without the corpus.

#[path = "../../verified-verifier/tests/support/mod.rs"]
mod support;

use support::{Key, STATEMENT_DOMAIN, TENANT, object, registry, string, uuid, wrapped};
use verified_canonical::{Sha256Digest, Value};
use verified_history::{Carried, RelationDraft, Standing, prepare_relation, read};
use verified_protocol::relation::{RecordKind, Reference, Relation};
use verified_verifier::Trust;
use verified_verifier::evidence::Step;

const SOURCE: &str = "application";
const STREAM: &str = "application/relations";

fn application_key() -> Key {
    Key::new("test-application", 9, &[SOURCE])
}

fn reference(kind: RecordKind, of: &str) -> Reference {
    Reference {
        kind,
        digest: Sha256Digest::of(of.as_bytes()),
    }
}

fn members() -> Vec<Reference> {
    let mut members = vec![
        reference(RecordKind::Package, "package 1"),
        reference(RecordKind::Package, "package 2"),
        reference(RecordKind::WorkRecord, "record 1"),
    ];
    members.sort_by(Reference::wire_order);
    members
}

fn stated(n: u32, key: &Key) -> Value {
    object([
        ("id", wrapped(uuid(n))),
        ("issuer", wrapped(key.issuer.clone())),
        ("observedAt", wrapped("2026-03-01T10:00:00Z")),
        (
            "source",
            object([
                ("observationId", string(format!("relation-{n}"))),
                ("system", string(SOURCE)),
            ]),
        ),
        ("tenant", wrapped(TENANT)),
    ])
}

/// The relation laid out, signed by `key`, as it travels.
fn signed(relation: &Relation<'_>, n: u32, key: &Key, step: Step<'_>) -> (Value, Value) {
    let prepared = prepare_relation(&RelationDraft {
        relation,
        stated: &stated(n, key),
        step,
    })
    .expect("the relation is laid out");
    let statement = object([
        ("signature", key.sign(STATEMENT_DOMAIN, &prepared.statement)),
        ("statement", prepared.statement),
    ]);
    (statement, prepared.body)
}

fn trust() -> Trust {
    Trust::from_value(&registry(&[&application_key()])).expect("a registry")
}

#[test]
fn a_produced_relation_is_one_the_reader_accepts() {
    let relation = Relation::Groups {
        group: "session-1",
        members: members(),
    };
    let (statement, body) = signed(&relation, 1, &application_key(), Step::Unchained);

    let reading = read(
        &[Carried {
            statement: &statement,
            body: &body,
        }],
        &[],
        &trust(),
    );

    let said = &reading.relations[0];
    assert_eq!(said.relation, Some("groups"));
    assert_eq!(said.source.as_deref(), Some(SOURCE));
    // Authentic and well carried; no record was given, so it is stated.
    assert_eq!(said.standing, Standing::Stated(members()));
    assert_eq!(Relation::from_value(&body), Ok(relation));
}

#[test]
fn relations_chained_in_a_stream_of_their_own_show_that_none_is_missing() {
    let key = application_key();
    let first = Relation::Groups {
        group: "session-1",
        members: members(),
    };
    let second = Relation::Groups {
        group: "session-2",
        members: members(),
    };
    let (a, a_body) = signed(&first, 1, &key, Step::First { stream: STREAM });
    let (b, b_body) = signed(&second, 2, &key, Step::After(&a));

    let both = [
        Carried {
            statement: &a,
            body: &a_body,
        },
        Carried {
            statement: &b,
            body: &b_body,
        },
    ];
    let whole = read(&both, &[], &trust());
    let tail = read(&both[1..], &[], &trust());

    assert_eq!(whole.streams[0].completeness, "UNINTERRUPTED");
    assert_eq!(whole.streams[0].last, Some(1));
    // Without the first statement, what came before is not known.
    assert_eq!(tail.streams[0].completeness, "UNKNOWN");
}

#[test]
fn a_relation_a_reader_would_refuse_is_not_laid_out() {
    let key = application_key();
    let mut unordered = members();
    unordered.reverse();
    let refused = [
        Relation::Groups {
            group: "session-1",
            members: unordered,
        },
        Relation::Groups {
            group: "session-1",
            members: vec![],
        },
        Relation::Groups {
            group: "",
            members: members(),
        },
        Relation::Recorded {
            record: reference(RecordKind::Package, "not a work record"),
            claim_id: "00000000-0000-4000-8000-000000000501",
        },
        Relation::Recorded {
            record: reference(RecordKind::WorkRecord, "record 1"),
            claim_id: "not a uuid",
        },
    ];

    for relation in &refused {
        let result = prepare_relation(&RelationDraft {
            relation,
            stated: &stated(1, &key),
            step: Step::Unchained,
        });
        assert_eq!(
            result.expect_err("refused").code.as_str(),
            "MALFORMED",
            "{relation:?}"
        );
    }
}

#[test]
fn the_statement_s_kind_and_subject_are_not_the_caller_s_to_state() {
    let key = application_key();
    let relation = Relation::Groups {
        group: "session-1",
        members: members(),
    };
    let mut with_kind = stated(1, &key);
    if let Value::Object(members) = &mut with_kind {
        members.insert("kind", object([("Event", object([]))]));
    }

    let result = prepare_relation(&RelationDraft {
        relation: &relation,
        stated: &with_kind,
        step: Step::Unchained,
    });

    assert_eq!(result.expect_err("refused").code.as_str(), "MALFORMED");
}

#[test]
fn a_key_the_registry_does_not_trust_for_the_source_says_nothing() {
    let stranger = Key::new("test-stranger", 10, &[SOURCE]);
    let relation = Relation::Groups {
        group: "session-1",
        members: members(),
    };
    let (statement, body) = signed(&relation, 1, &stranger, Step::Unchained);

    let reading = read(
        &[Carried {
            statement: &statement,
            body: &body,
        }],
        &[],
        &trust(),
    );

    assert_eq!(
        reading.relations[0].standing,
        Standing::Refused("UNKNOWN_KEY")
    );
}
