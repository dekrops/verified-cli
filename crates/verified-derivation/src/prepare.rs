// SPDX-License-Identifier: Apache-2.0

//! From admitted evidence to an authorization question, and from the answer to a derivation.

use std::collections::{BTreeMap, BTreeSet};

use verified_canonical::{Object, Sha256Digest, Value, cmp_keys};
use verified_contract::Contract;

use crate::cedar::{self, Question};
use crate::{Body, DERIVED_SOURCE, Item, digest, member, number, object, string, text};

const FORMAT: &str = "verified-recomputed-authorization-experimental-1";
pub(crate) const METHOD: &str = "verified-cedar-recomputation";
pub(crate) const METHOD_VERSION: &str = "0.2.0";
const FEATURES: &str = "cedar-static-no-context-1";
const POLICY_SET: &str = "cedarPolicySet";
const ENTITY: &str = "cedarEntity";
const MAX_STATEMENTS: usize = 10_000;

/// Which evidence an authorization question is read from.
pub(crate) struct Profile<'a> {
    event_kind: &'a str,
    event_sources: Vec<&'a str>,
    event_id: &'a str,
    principal_field: &'a str,
    resource_field: &'a str,
    time_field: &'a str,
    principal_type: &'a str,
    resource_type: &'a str,
    action: &'a str,
    policy_sources: Vec<&'a str>,
    entity_sources: Vec<&'a str>,
    language_version: &'a str,
}

fn strings<'a>(value: &'a Value, name: &str) -> Option<Vec<&'a str>> {
    member(value, name)?
        .as_array()?
        .iter()
        .map(Value::as_str)
        .collect()
}

fn list(values: &[&str]) -> Value {
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| cmp_keys(a, b));
    Value::Array(sorted.into_iter().map(text).collect())
}

impl<'a> Profile<'a> {
    /// A profile from its canonical value. A value that names other completeness rules, or
    /// carries anything else, is not a profile of this method.
    pub(crate) fn read(value: &'a Value) -> Option<Self> {
        let event = member(value, "event")?;
        let entities = member(value, "entities")?;
        let profile = Self {
            event_kind: string(event, "kind")?,
            event_sources: strings(event, "sources")?,
            event_id: string(event, "id")?,
            principal_field: string(event, "principal")?,
            resource_field: string(event, "resource")?,
            time_field: string(event, "time")?,
            principal_type: string(entities, "principalType")?,
            resource_type: string(entities, "resourceType")?,
            action: string(value, "action")?,
            policy_sources: strings(value, "policySources")?,
            entity_sources: strings(entities, "sources")?,
            language_version: string(value, "languageVersion")?,
        };
        (profile.value() == *value).then_some(profile)
    }

    fn value(&self) -> Value {
        object([
            (
                "event",
                object([
                    ("kind", text(self.event_kind)),
                    ("sources", list(&self.event_sources)),
                    ("id", text(self.event_id)),
                    ("principal", text(self.principal_field)),
                    ("resource", text(self.resource_field)),
                    ("time", text(self.time_field)),
                ]),
            ),
            (
                "entities",
                object([
                    ("principalType", text(self.principal_type)),
                    ("resourceType", text(self.resource_type)),
                    ("sources", list(&self.entity_sources)),
                ]),
            ),
            ("action", text(self.action)),
            ("policySources", list(&self.policy_sources)),
            ("languageVersion", text(self.language_version)),
            (
                "completeness",
                object([
                    (
                        "policySets",
                        text("source-of-the-policy-set-as-of-the-event"),
                    ),
                    ("entities", text("every-accepted-source-as-of-the-event")),
                    (
                        "derived",
                        text("every-accepted-event-source-and-every-event-decided"),
                    ),
                ]),
            ),
        ])
    }
}

/// One recomputed authorization.
#[derive(Debug, Clone)]
pub struct Derivation {
    /// What two implementations must agree on.
    pub core: Value,
    /// Its digest.
    pub commitment: Sha256Digest,
    /// This implementation's own account: its engine and its messages. Never compared.
    pub diagnostics: Value,
    /// The work event's identifier.
    pub correlation: String,
    /// `ALLOW`, `DENY` or `UNDETERMINED`.
    pub outcome: &'static str,
    /// The failed guards, sorted.
    pub reasons: Vec<&'static str>,
    /// What Cedar itself returned, when it was asked and answered. A diagnostic: `outcome` is
    /// the only thing that decides.
    pub engine_decision: Option<&'static str>,
    fact: Option<Value>,
}

impl Derivation {
    /// The identifier of the record this derivation yielded, if it yielded one.
    pub(crate) fn record(&self) -> Option<&str> {
        string(self.fact.as_ref()?, "id")
    }
}

type Failure = (&'static str, String);
type Records<'a> = Vec<(&'a Item<'a>, &'a Object)>;

/// The question, bound to the work event it was read from.
struct Asked {
    principal: String,
    resource: String,
    at: i128,
    principal_name: String,
    resource_name: String,
}

/// The statements a result rests on, by evidence identifier and role.
#[derive(Default)]
struct Used(BTreeMap<String, Value>);

impl Used {
    fn depend(&mut self, role: &str, item: &Item<'_>) {
        self.0
            .entry(format!("{}\u{0}{role}", item.fact_id()))
            .or_insert_with(|| {
                object([
                    ("role", text(role)),
                    ("evidence", text(&item.fact_id())),
                    ("source", text(item.source)),
                    ("statement", digest(&item.digest)),
                ])
            });
    }

    fn into_value(self) -> Value {
        let mut sorted: Vec<(String, Value)> = self.0.into_iter().collect();
        sorted.sort_by(|a, b| cmp_keys(&a.0, &b.0));
        Value::Array(sorted.into_iter().map(|(_, value)| value).collect())
    }
}

fn quoted(kind: &str, id: &str) -> String {
    format!("{kind}::{}", text(id).to_canonical_string())
}

fn field<'a>(fields: &'a Object, name: &str) -> Option<&'a str> {
    fields.get(name)?.as_str()
}

fn records<'a>(items: &'a [Item<'a>], kind: &str, sources: &[&str]) -> Records<'a> {
    items
        .iter()
        .filter_map(|item| match &item.body {
            Body::Record { kind: k, fields } if *k == kind && sources.contains(&item.source) => {
                Some((item, *fields))
            }
            _ => None,
        })
        .collect()
}

/// The request: exactly one account of the work event, from a source accepted for it.
fn request(
    profile: &Profile<'_>,
    correlation: &str,
    items: &[Item<'_>],
    used: &mut Used,
) -> Result<Asked, Failure> {
    let mut accounts: Vec<&Object> = Vec::new();
    for (item, fields) in records(items, profile.event_kind, &profile.event_sources) {
        if field(fields, profile.event_id) == Some(correlation) {
            used.depend("event", item);
            if !accounts.contains(&fields) {
                accounts.push(fields);
            }
        }
    }
    match accounts.as_slice() {
        [fields] => (|| {
            let principal = field(fields, profile.principal_field)?;
            let resource = field(fields, profile.resource_field)?;
            Some(Asked {
                principal: quoted(profile.principal_type, principal),
                resource: quoted(profile.resource_type, resource),
                at: number(fields.get(profile.time_field))?,
                principal_name: principal.to_owned(),
                resource_name: resource.to_owned(),
            })
        })()
        .ok_or_else(|| {
            let detail = format!("the record of {correlation} does not name a request");
            ("REQUEST_NOT_ESTABLISHED", detail)
        }),
        [] => Err((
            "REQUEST_NOT_ESTABLISHED",
            format!("no accepted record of {correlation}"),
        )),
        _ => Err((
            "CONFLICTING_EVIDENCE",
            format!("accepted records of {correlation} disagree"),
        )),
    }
}

/// The policy sets and entities that were valid at the time of the event, and what their
/// sources declared about them.
struct Selection<'a> {
    policy_sets: Records<'a>,
    /// The distinct policy sets among them, as text and schema.
    distinct: Vec<(Option<&'a str>, Option<&'a str>)>,
    in_force: bool,
    entities: Records<'a>,
    /// One account of each entity: the first, in the order of the statements.
    one: Vec<&'a Object>,
    disputed: bool,
    entities_complete: bool,
}

const ENTITY_MEMBERS: [&str; 5] = ["uid", "attrs", "parents", "absent", "tags"];

fn content(fields: &Object) -> Vec<(&'static str, Value)> {
    ENTITY_MEMBERS
        .into_iter()
        .filter_map(|name| fields.get(name).map(|value| (name, value.clone())))
        .collect()
}

fn select<'a>(
    profile: &Profile<'_>,
    items: &'a [Item<'a>],
    at: i128,
    used: &mut Used,
) -> Selection<'a> {
    let applies = |fields: &Object| {
        number(fields.get("validFrom")).is_some_and(|from| from <= at)
            && fields
                .get("validUntil")
                .is_none_or(|until| number(Some(until)).is_some_and(|until| at < until))
    };
    // The completeness statements that cover the time of the action, by kind and source.
    let complete: Vec<(&str, &Item<'_>)> = items
        .iter()
        .filter_map(|item| match &item.body {
            Body::Complete { kind, as_of }
                if number(Some(&text(as_of))).is_some_and(|as_of| as_of >= at) =>
            {
                Some((*kind, item))
            }
            _ => None,
        })
        .collect();
    let covered = |kind: &str, source: &str| {
        complete
            .iter()
            .any(|(k, item)| *k == kind && item.source == source)
    };
    for (kind, item) in &complete {
        if (*kind == POLICY_SET && profile.policy_sources.contains(&item.source))
            || (*kind == ENTITY && profile.entity_sources.contains(&item.source))
        {
            used.depend("completeness", item);
        }
    }

    // G1: one policy set applies at that time, and its source says it has no other.
    let mut policy_sets = records(items, POLICY_SET, &profile.policy_sources);
    policy_sets.retain(|(_, fields)| applies(fields));
    let mut distinct = Vec::new();
    for (item, fields) in &policy_sets {
        used.depend("policy-set", item);
        let set = (field(fields, "policies"), field(fields, "schema"));
        if !distinct.contains(&set) {
            distinct.push(set);
        }
    }
    let in_force = !policy_sets.is_empty()
        && policy_sets
            .iter()
            .all(|(item, _)| covered(POLICY_SET, item.source));

    // G3 and G5: the entities as they were, one account of each, from complete listings.
    let mut entities = records(items, ENTITY, &profile.entity_sources);
    entities.retain(|(_, fields)| applies(fields));
    let mut grouped: Vec<(Option<&Value>, Vec<&Object>)> = Vec::new();
    for (item, fields) in &entities {
        used.depend("entity", item);
        match grouped
            .iter_mut()
            .find(|(uid, _)| *uid == fields.get("uid"))
        {
            Some((_, accounts)) => accounts.push(fields),
            None => grouped.push((fields.get("uid"), vec![fields])),
        }
    }
    let disputed = grouped
        .iter()
        .any(|(_, accounts)| accounts.iter().any(|a| content(a) != content(accounts[0])));
    Selection {
        policy_sets,
        distinct,
        in_force,
        entities,
        one: grouped.iter().map(|(_, accounts)| accounts[0]).collect(),
        disputed,
        entities_complete: profile
            .entity_sources
            .iter()
            .all(|source| covered(ENTITY, source)),
    }
}

fn json(value: &Value) -> serde_json::Value {
    serde_json::from_str(&value.to_canonical_string()).unwrap_or_default()
}

/// Cedar's JSON list of entities, from one account of each.
fn cedar_entities(one: &[&Object]) -> serde_json::Value {
    serde_json::Value::Array(
        one.iter()
            .map(|fields| {
                let mut entity = serde_json::Map::new();
                entity.insert(
                    "uid".into(),
                    fields.get("uid").map(json).unwrap_or_default(),
                );
                let attrs = fields
                    .get("attrs")
                    .map_or_else(|| serde_json::json!({}), json);
                entity.insert("attrs".into(), attrs);
                let parents = fields
                    .get("parents")
                    .map_or_else(|| serde_json::json!([]), json);
                entity.insert("parents".into(), parents);
                // Carried so that the guard sees them and refuses: never dropped.
                if let Some(tags) = fields.get("tags").filter(|tags| **tags != Value::Null) {
                    entity.insert("tags".into(), json(tags));
                }
                serde_json::Value::Object(entity)
            })
            .collect(),
    )
}

/// Attributes a source states to have no value, by entity.
fn stated_absent(one: &[&Object]) -> BTreeMap<(String, String), BTreeSet<String>> {
    one.iter()
        .filter_map(|fields| {
            let uid = fields.get("uid")?;
            let names: BTreeSet<String> = fields
                .get("absent")
                .and_then(Value::as_array)
                .and_then(|names| {
                    names
                        .iter()
                        .map(|n| n.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            Some((
                (
                    string(uid, "type")?.to_owned(),
                    string(uid, "id")?.to_owned(),
                ),
                names,
            ))
        })
        .collect()
}

/// What the question was asked over, as the core commits to it.
struct Inputs {
    policy_set: Sha256Digest,
    schema: Sha256Digest,
    entities: Sha256Digest,
    applicability: Option<Value>,
}

fn inputs(selection: &Selection<'_>, policies: &str, schema: &str) -> Inputs {
    // Each entity as its record gives it, in the order of its canonical text.
    let mut asked_over: Vec<Value> = selection
        .one
        .iter()
        .map(|fields| {
            Value::Object(
                content(fields)
                    .into_iter()
                    .map(|(k, v)| (k.to_owned(), v))
                    .collect(),
            )
        })
        .collect();
    asked_over.sort_by(|a, b| cmp_keys(&a.to_canonical_string(), &b.to_canonical_string()));
    // The interval over which every record used held.
    let intervals = selection
        .policy_sets
        .iter()
        .chain(&selection.entities)
        .map(|(_, fields)| *fields);
    let from = intervals
        .clone()
        .filter_map(|f| number(f.get("validFrom")))
        .max();
    let until = intervals.filter_map(|f| number(f.get("validUntil"))).min();
    Inputs {
        policy_set: text(policies).digest(),
        schema: text(schema).digest(),
        entities: Value::Array(asked_over).digest(),
        applicability: from.map(|from| {
            object([
                ("from", text(&from.to_string())),
                (
                    "until",
                    until.map_or(Value::Null, |until| text(&until.to_string())),
                ),
            ])
        }),
    }
}

/// What the preparation established without the engine.
fn stated(selection: &Selection<'_>, at: i128) -> Vec<Failure> {
    let mut stated = Vec::new();
    if selection.policy_sets.is_empty() {
        stated.push((
            "POLICY_SET_NOT_IN_FORCE",
            format!("no accepted policy set covers {at}"),
        ));
    } else if !selection.in_force {
        let detail = format!("no completeness statement for policy sets covers {at}");
        stated.push(("POLICY_SET_NOT_IN_FORCE", detail));
    }
    if selection.distinct.len() > 1 {
        let detail = format!(
            "{} different policy sets cover {at}",
            selection.distinct.len()
        );
        stated.push(("CONFLICTING_EVIDENCE", detail));
    }
    stated
}

/// The engine's answer, or why it was not asked.
struct Decided {
    permitted: Option<bool>,
    reasons: BTreeSet<&'static str>,
    determining: Vec<String>,
    errors: Vec<String>,
    details: Vec<String>,
    inputs: Option<Inputs>,
    engine_decision: Option<&'static str>,
}

fn undecided(found: Vec<Failure>) -> Decided {
    Decided {
        permitted: None,
        reasons: found.iter().map(|(code, _)| *code).collect(),
        determining: Vec::new(),
        errors: Vec::new(),
        details: found
            .into_iter()
            .map(|(code, detail)| format!("{code}: {detail}"))
            .collect(),
        inputs: None,
        engine_decision: None,
    }
}

fn decide(profile: &Profile<'_>, asked: &Asked, selection: &Selection<'_>) -> Decided {
    let mut stated = stated(selection, asked.at);
    match selection.distinct.as_slice() {
        [(Some(policies), Some(schema))] => {
            let answer = cedar::authorize(&Question {
                policies,
                schema,
                entities: cedar_entities(&selection.one),
                principal: &asked.principal,
                action: profile.action,
                resource: &asked.resource,
                policy_set_in_force: selection.in_force,
                entities_complete: selection.entities_complete,
                conflicts: selection.disputed,
                language_version: profile.language_version,
                absent: stated_absent(&selection.one),
            });
            Decided {
                permitted: answer.permitted,
                reasons: answer.reasons,
                determining: answer.determining,
                errors: answer.errors,
                details: answer.details,
                inputs: Some(inputs(selection, policies, schema)),
                engine_decision: answer.engine_decision,
            }
        }
        // No policy set, several, or one that is not text: there is nothing to ask Cedar.
        sets => {
            if sets.len() == 1 {
                let detail = "the policy set record has no policies or no schema";
                stated.push(("INPUT_UNREADABLE", detail.to_owned()));
            }
            undecided(stated)
        }
    }
}

fn core(
    profile: &Profile<'_>,
    profile_digest: &Sha256Digest,
    correlation: &str,
    asked: Option<&Asked>,
    decided: &Decided,
    used: Used,
) -> Value {
    let optional = |digest_of: Option<&Sha256Digest>| digest_of.map_or(Value::Null, digest);
    let inputs = decided.inputs.as_ref();
    let outcome = outcome(decided.permitted);
    let reasons = if decided.permitted.is_some() {
        Vec::new()
    } else {
        decided.reasons.iter().collect()
    };
    object([
        ("format", text(FORMAT)),
        (
            "method",
            object([
                ("name", text(METHOD)),
                ("version", text(METHOD_VERSION)),
                ("languageVersion", text(&cedar::language_version())),
                ("features", text(FEATURES)),
                (
                    "canonicalization",
                    text(verified_canonical::CANONICAL_VERSION),
                ),
            ]),
        ),
        ("profile", digest(profile_digest)),
        ("correlation", text(correlation)),
        (
            "request",
            asked.map_or(Value::Null, |asked| {
                object([
                    ("principal", text(&asked.principal)),
                    ("action", text(profile.action)),
                    ("resource", text(&asked.resource)),
                    ("at", text(&asked.at.to_string())),
                    // Requests are evaluated without a context: the digest of the empty one.
                    ("context", digest(&Value::Object(Object::new()).digest())),
                ])
            }),
        ),
        (
            "inputs",
            object([
                ("policySet", optional(inputs.map(|i| &i.policy_set))),
                ("schema", optional(inputs.map(|i| &i.schema))),
                ("entities", optional(inputs.map(|i| &i.entities))),
                (
                    "applicability",
                    inputs
                        .and_then(|i| i.applicability.clone())
                        .unwrap_or(Value::Null),
                ),
            ]),
        ),
        ("dependencies", used.into_value()),
        ("outcome", text(outcome)),
        (
            "reasons",
            Value::Array(reasons.into_iter().map(|code| text(code)).collect()),
        ),
        (
            "determining",
            Value::Array(decided.determining.iter().map(|id| text(id)).collect()),
        ),
    ])
}

fn outcome(permitted: Option<bool>) -> &'static str {
    match permitted {
        Some(true) => "ALLOW",
        Some(false) => "DENY",
        None => "UNDETERMINED",
    }
}

/// A definite recomputation as a record of the contract's decision kind.
fn fact(
    profile: &Profile<'_>,
    correlation: &str,
    asked: Option<&Asked>,
    decided: &Decided,
    commitment: &Sha256Digest,
) -> Option<Value> {
    let (permitted, asked, inputs) = (decided.permitted?, asked?, decided.inputs.as_ref()?);
    let id = format!("d-{}", &commitment.to_hex()[..40]);
    let spelled = |d: &Sha256Digest| text(&format!("{}:{}", Sha256Digest::ALGORITHM, d.to_hex()));
    Some(object([
        ("id", text(&id)),
        ("request", text(correlation)),
        ("principal", text(&asked.principal_name)),
        ("action", text(profile.action)),
        ("resource", text(&asked.resource_name)),
        (
            "engineDecision",
            text(if permitted { "Allow" } else { "Deny" }),
        ),
        ("errors", text("0")),
        ("permitted", Value::Bool(permitted)),
        ("policySet", spelled(&inputs.policy_set)),
        ("schema", spelled(&inputs.schema)),
        // The method, not the binding that ran it: the record is the same from any implementation.
        ("engine", text(&format!("{METHOD} {METHOD_VERSION}"))),
        ("languageVersion", text(&cedar::language_version())),
        ("at", text(&asked.at.to_string())),
    ]))
}

/// Recompute the authorization of one work event from admitted evidence.
fn recompute(
    profile: &Profile<'_>,
    profile_digest: &Sha256Digest,
    correlation: &str,
    items: &[Item<'_>],
    not_read: &[String],
) -> Derivation {
    let limited = items.len() > MAX_STATEMENTS;
    let items = if limited { &[] } else { items };
    let mut details: Vec<String> = if limited {
        vec![format!(
            "LIMIT_EXCEEDED: more than {MAX_STATEMENTS} statements; none is read"
        )]
    } else {
        not_read.to_vec()
    };
    let mut used = Used::default();
    let asked = request(profile, correlation, items, &mut used);
    let decided = match &asked {
        Ok(asked) => decide(profile, asked, &select(profile, items, asked.at, &mut used)),
        Err(reason) => undecided(vec![reason.clone()]),
    };
    details.extend(decided.details.iter().cloned());
    let asked = asked.as_ref().ok();

    let core = core(profile, profile_digest, correlation, asked, &decided, used);
    let commitment = core.digest();
    let reasons: Vec<&'static str> = if decided.permitted.is_some() {
        Vec::new()
    } else {
        decided.reasons.iter().copied().collect()
    };
    // This implementation's account: what the engine returned, and what was made of it.
    let texts = |values: &[String]| Value::Array(values.iter().map(|v| text(v)).collect());
    let diagnostics = object([
        ("engine", text(cedar::ENGINE)),
        (
            "engineDecision",
            decided.engine_decision.map_or(Value::Null, text),
        ),
        ("determining", texts(&decided.determining)),
        ("errors", texts(&decided.errors)),
        (
            "interpretation",
            object([
                ("outcome", text(outcome(decided.permitted))),
                (
                    "reasons",
                    Value::Array(reasons.iter().map(|code| text(code)).collect()),
                ),
            ]),
        ),
        ("details", texts(&details)),
    ]);
    Derivation {
        fact: fact(profile, correlation, asked, &decided, &commitment),
        core,
        commitment,
        diagnostics,
        correlation: correlation.to_owned(),
        outcome: outcome(decided.permitted),
        reasons,
        engine_decision: decided.engine_decision,
    }
}

pub(crate) struct Evaluated {
    pub(crate) derivations: Vec<Derivation>,
    pub(crate) result: Value,
    pub(crate) decision: String,
}

type Facts = Vec<(String, Value)>;
type Latest = BTreeMap<(String, String), i128>;

/// The ordinary environment: one record per record statement, and the latest completeness
/// statement per kind and source.
fn signed_environment(items: &[Item<'_>]) -> (Facts, Latest) {
    let mut facts = Vec::new();
    let mut latest: Latest = BTreeMap::new();
    for item in items {
        match &item.body {
            Body::Record { kind, fields } => facts.push((
                item.fact_id(),
                object([
                    ("id", text(&item.fact_id())),
                    ("kind", text(kind)),
                    ("source", text(item.source)),
                    ("fields", Value::Object((*fields).clone())),
                ]),
            )),
            Body::Complete { kind, as_of } => {
                let at = number(Some(&text(as_of))).unwrap_or_default();
                let entry = latest
                    .entry(((*kind).to_owned(), item.source.to_owned()))
                    .or_insert(at);
                *entry = (*entry).max(at);
            }
        }
    }
    (facts, latest)
}

fn environment(inputs: &Value, mut facts: Facts, latest: Latest) -> Value {
    facts.sort_by(|a, b| a.0.cmp(&b.0));
    let mut complete: Vec<_> = latest.into_iter().collect();
    complete.sort_by(|a, b| cmp_keys(&a.0.0, &b.0.0).then_with(|| cmp_keys(&a.0.1, &b.0.1)));
    object([
        ("inputs", inputs.clone()),
        (
            "facts",
            Value::Array(facts.into_iter().map(|(_, fact)| fact).collect()),
        ),
        (
            "complete",
            Value::Array(
                complete
                    .into_iter()
                    .map(|((kind, source), as_of)| {
                        object([
                            ("kind", text(&kind)),
                            ("source", text(&source)),
                            ("asOf", text(&as_of.to_string())),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

/// Evaluate the contract over the admitted evidence, with one recomputed decision per work event.
pub(crate) fn evaluate(
    contract: &Contract,
    contract_value: &Value,
    inputs: &Value,
    decision_kind: &str,
    profile: &Profile<'_>,
    items: &[Item<'_>],
    not_read: &[String],
) -> Result<Evaluated, String> {
    let profile_digest = profile.value().digest();
    let (mut facts, mut latest) = signed_environment(items);

    // The work events, and one derivation for each identifier among them.
    let events = records(items, profile.event_kind, &profile.event_sources);
    let identified: Vec<&str> = events
        .iter()
        .filter_map(|(_, fields)| field(fields, profile.event_id))
        .collect();
    let mut correlations = identified.clone();
    correlations.sort_by(|a, b| cmp_keys(a, b));
    correlations.dedup();
    let derivations: Vec<Derivation> = correlations
        .iter()
        .map(|c| recompute(profile, &profile_digest, c, items, not_read))
        .collect();
    let decided: Vec<&Value> = derivations.iter().filter_map(|d| d.fact.as_ref()).collect();

    // Invariant: the profile reads events from exactly the sources the contract accepts for
    // them. Otherwise the derived listing is never closed.
    let accepted: Vec<&str> = member(contract_value, "evidence")
        .and_then(|evidence| member(evidence, "sources"))
        .and_then(|sources| strings(sources, profile.event_kind))
        .unwrap_or_default();
    let compatible = !accepted.is_empty()
        && accepted.iter().all(|s| profile.event_sources.contains(s))
        && profile.event_sources.iter().all(|s| accepted.contains(s));
    // A completeness statement from every source accepted for the events; the derived listing
    // is vouched for only as far back as the least recent of them.
    let declared: Vec<Option<i128>> = accepted
        .iter()
        .map(|s| {
            latest
                .get(&(profile.event_kind.to_owned(), (*s).to_owned()))
                .copied()
        })
        .collect();
    let closes = compatible
        && declared.iter().all(Option::is_some)
        && identified.len() == events.len()
        && decided.len() == derivations.len();

    for fact in &decided {
        let id = string(fact, "id").unwrap_or_default().to_owned();
        let record = object([
            ("id", text(&id)),
            ("kind", text(decision_kind)),
            ("source", text(DERIVED_SOURCE)),
            ("fields", (*fact).clone()),
        ]);
        facts.push((id, record));
    }
    if closes && let Some(least) = declared.iter().flatten().min() {
        latest.insert(
            (decision_kind.to_owned(), DERIVED_SOURCE.to_owned()),
            *least,
        );
    }
    let outcome = contract
        .evaluate(&environment(inputs, facts, latest))
        .map_err(|refusal| refusal.as_str().to_owned())?;
    Ok(Evaluated {
        derivations,
        result: outcome.to_value(),
        decision: outcome.decision.as_str().to_owned(),
    })
}
