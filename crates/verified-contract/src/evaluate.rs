//! Evaluating a well-formed contract against an environment.

use std::collections::{BTreeMap, BTreeSet};

use verified_canonical::{Object, Value};

use crate::model::{ConflictPolicy, Contract, Op, Pred, Quantifier, Term, Val, is_name, number};
use crate::{Decision, Refusal, Truth};

const MAX_FACTS: usize = 10_000;
const WORK_BOUND: u128 = 10_000_000;

/// The value of one requirement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequirementValue {
    /// The requirement's identifier.
    pub id: String,
    /// What its predicate evaluated to.
    pub value: Truth,
}

/// Accepted facts of one kind with equal key fields and differing contents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conflict {
    /// The kind of the conflicting facts.
    pub kind: String,
    /// The identifiers of the conflicting facts, in environment order.
    pub facts: Vec<String>,
    /// The fact the contract's conflict policy settled on, if it settled.
    pub resolved_to: Option<String>,
}

/// The result of an evaluation that was not refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// The decision.
    pub decision: Decision,
    /// The value of every requirement, in contract order.
    pub requirements: Vec<RequirementValue>,
    /// Facts the contract did not read: their kind is undeclared, or their
    /// source is not one it accepts for the kind.
    pub ignored: Vec<String>,
    /// The conflicts found among accepted facts.
    pub conflicts: Vec<Conflict>,
}

fn text(s: &str) -> Value {
    Value::String(s.to_owned())
}

fn texts(items: &[String]) -> Value {
    Value::Array(items.iter().map(|s| text(s)).collect())
}

impl Outcome {
    /// The language's result object: `{ decision, requirements, ignored,
    /// conflicts }`. An unsettled conflict has no `resolvedTo` member.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let requirements = self.requirements.iter().map(|r| {
            let mut o = Object::new();
            o.insert("id", text(&r.id));
            o.insert("value", text(r.value.as_str()));
            Value::Object(o)
        });
        let conflicts = self.conflicts.iter().map(|c| {
            let mut o = Object::new();
            o.insert("kind", text(&c.kind));
            o.insert("facts", texts(&c.facts));
            if let Some(resolved) = &c.resolved_to {
                o.insert("resolvedTo", text(resolved));
            }
            Value::Object(o)
        });
        let mut o = Object::new();
        o.insert("decision", text(self.decision.as_str()));
        o.insert("requirements", Value::Array(requirements.collect()));
        o.insert("ignored", texts(&self.ignored));
        o.insert("conflicts", Value::Array(conflicts.collect()));
        Value::Object(o)
    }
}

struct Fact<'a> {
    id: &'a str,
    kind: &'a str,
    source: &'a str,
    fields: &'a Object,
}

struct Completeness<'a> {
    kind: &'a str,
    source: &'a str,
    as_of: i64,
}

struct Environment<'a> {
    inputs: &'a Object,
    facts: Vec<Fact<'a>>,
    complete: Vec<Completeness<'a>>,
}

/// An accepted fact whose fields fit its kind.
struct Record<'a> {
    id: &'a str,
    kind: &'a str,
    source: &'a str,
    fields: BTreeMap<&'a str, Val>,
}

fn exactly<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Object> {
    value
        .as_object()
        .filter(|o| o.len() == keys.len() && keys.iter().all(|k| o.get(k).is_some()))
}

fn name<'a>(object: &'a Object, key: &str) -> Option<&'a str> {
    object.get(key)?.as_str().filter(|s| is_name(s))
}

fn read_fact(json: &Value) -> Option<Fact<'_>> {
    let o = exactly(json, &["id", "kind", "source", "fields"])?;
    let fields = o.get("fields")?.as_object()?;
    fields.keys().all(is_name).then_some(())?;
    Some(Fact {
        id: name(o, "id")?,
        kind: name(o, "kind")?,
        source: name(o, "source")?,
        fields,
    })
}

fn read_completeness(json: &Value) -> Option<Completeness<'_>> {
    let o = exactly(json, &["kind", "source", "asOf"])?;
    Some(Completeness {
        kind: name(o, "kind")?,
        source: name(o, "source")?,
        as_of: number(o.get("asOf")?).filter(|n| *n >= 0)?,
    })
}

fn read_environment(json: &Value) -> Option<Environment<'_>> {
    let root = exactly(json, &["inputs", "facts", "complete"])?;
    let inputs = root.get("inputs")?.as_object()?;
    let facts = root.get("facts")?.as_array()?;
    let complete = root.get("complete")?.as_array()?;
    let facts = facts.iter().map(read_fact).collect::<Option<Vec<_>>>()?;
    let complete = complete
        .iter()
        .map(read_completeness)
        .collect::<Option<Vec<_>>>()?;
    let ordered = facts.len() <= MAX_FACTS
        && inputs.keys().all(is_name)
        && facts.windows(2).all(|w| w[0].id < w[1].id)
        && complete
            .windows(2)
            .all(|w| (w[0].kind, w[0].source) < (w[1].kind, w[1].source));
    ordered.then_some(Environment {
        inputs,
        facts,
        complete,
    })
}

fn all(values: impl Iterator<Item = Truth>) -> Truth {
    let mut result = Truth::True;
    for value in values {
        match value {
            Truth::False => return Truth::False,
            Truth::Unknown => result = Truth::Unknown,
            Truth::True => {}
        }
    }
    result
}

fn any(values: impl Iterator<Item = Truth>) -> Truth {
    let mut result = Truth::False;
    for value in values {
        match value {
            Truth::True => return Truth::True,
            Truth::Unknown => result = Truth::Unknown,
            Truth::False => {}
        }
    }
    result
}

const fn not(value: Truth) -> Truth {
    match value {
        Truth::True => Truth::False,
        Truth::False => Truth::True,
        Truth::Unknown => Truth::Unknown,
    }
}

fn compare(op: Op, a: &Val, b: &Val) -> Truth {
    let holds = match op {
        Op::Eq => a == b,
        Op::Ne => a != b,
        Op::Lt => a < b,
        Op::Le => a <= b,
        Op::Gt => a > b,
        Op::Ge => a >= b,
    };
    if holds { Truth::True } else { Truth::False }
}

/// What requirements are evaluated against, after acceptance, conformance
/// and conflict settlement.
struct Settled<'a> {
    contract: &'a Contract,
    inputs: BTreeMap<&'a str, Val>,
    /// The records in use, by kind.
    records: BTreeMap<&'a str, Vec<&'a Record<'a>>>,
    /// The kinds a source the contract accepts declared complete.
    closed: BTreeSet<&'a str>,
}

impl<'a> Settled<'a> {
    fn pred(&self, predicate: &'a Pred, scope: &mut Vec<(&'a str, &'a Record<'a>)>) -> Truth {
        match predicate {
            Pred::Compare { op, left, right } => {
                match (self.value(left, scope), self.value(right, scope)) {
                    (Some(a), Some(b)) => compare(*op, a, b),
                    _ => Truth::Unknown,
                }
            }
            Pred::And(args) => all(args.iter().map(|arg| self.pred(arg, scope))),
            Pred::Or(args) => any(args.iter().map(|arg| self.pred(arg, scope))),
            Pred::Not(inner) => not(self.pred(inner, scope)),
            Pred::Quantified {
                quantifier,
                variable,
                kind,
                body,
            } => {
                let records = self
                    .records
                    .get(kind.as_str())
                    .map_or(&[][..], Vec::as_slice);
                let mut values = Vec::with_capacity(records.len());
                for record in records {
                    scope.push((variable, record));
                    values.push(self.pred(body, scope));
                    scope.pop();
                }
                // One record can prove an `exists` or disprove a `forall`.
                // The opposite answers are claims about every record, so
                // they hold only for a kind that is closed.
                let (seen, needs_closure) = match quantifier {
                    Quantifier::Exists => (any(values.into_iter()), Truth::False),
                    Quantifier::Forall => (all(values.into_iter()), Truth::True),
                };
                if seen == needs_closure && !self.closed.contains(kind.as_str()) {
                    Truth::Unknown
                } else {
                    seen
                }
            }
        }
    }

    /// The term's value, or `None` for an absent optional field.
    fn value<'s>(&'s self, term: &'s Term, scope: &[(&str, &'s Record<'_>)]) -> Option<&'s Val> {
        match term {
            Term::Literal { value, .. } => Some(value),
            Term::Input(name) => self.inputs.get(name.as_str()),
            Term::Parameter(name) => self.contract.policy.get(name).map(|p| &p.value),
            Term::Field { variable, field } => scope
                .iter()
                .find(|(bound, _)| bound == variable)
                .and_then(|(_, record)| record.fields.get(field.as_str())),
        }
    }
}

impl Contract {
    /// Evaluates the contract against an environment in the language's
    /// exchange form: `{ inputs, facts, complete }`.
    pub fn evaluate(&self, environment: &Value) -> Result<Outcome, Refusal> {
        const NONCONFORMING: Refusal = Refusal::EnvironmentNonconforming;
        let environment = read_environment(environment).ok_or(Refusal::EnvironmentMalformed)?;

        // Step 1: the inputs are exactly the declared ones, each fitting.
        if environment.inputs.len() != self.inputs.len() {
            return Err(NONCONFORMING);
        }
        let inputs = self
            .inputs
            .iter()
            .map(|(name, ty)| {
                let value = environment.inputs.get(name).and_then(|v| ty.value(v));
                value.map(|v| (name.as_str(), v)).ok_or(NONCONFORMING)
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        // Step 2: facts the contract does not read (an undeclared kind, or
        // a source it does not accept for the kind) take no further part.
        let (usable, ignored): (Vec<_>, Vec<_>) = environment
            .facts
            .iter()
            .partition(|fact| self.accepts(fact.kind, fact.source));
        let ignored = ignored.iter().map(|fact| fact.id.to_owned()).collect();

        // Step 3: every other fact fits its kind.
        let records = usable
            .iter()
            .map(|fact| self.conform(fact).ok_or(NONCONFORMING))
            .collect::<Result<Vec<_>, _>>()?;

        // Step 4: the work bound.
        let predicates = || self.requires.iter().map(|r| &r.predicate);
        let size: u64 = predicates().map(Pred::nodes).sum();
        let deepest = predicates().map(Pred::quantifier_depth).max().unwrap_or(0);
        let facts = u128::try_from(environment.facts.len().max(1)).unwrap_or(u128::MAX);
        if u128::from(size).saturating_mul(facts.saturating_pow(deepest)) > WORK_BOUND {
            return Err(Refusal::WorkLimit);
        }

        // Step 5: conflicts.
        let (settled, conflicts, open) = self.settle(&records);

        // Step 6: closed kinds.
        let cutoff = match &self.cutoff {
            Some(input) => match inputs.get(input.as_str()) {
                Some(Val::Number(at)) => Some(*at),
                _ => return Err(NONCONFORMING),
            },
            None => None,
        };
        let closed = environment
            .complete
            .iter()
            .filter(|c| self.accepts(c.kind, c.source) && cutoff.is_none_or(|at| c.as_of >= at))
            .map(|c| c.kind)
            .filter(|kind| !open.contains(kind))
            .collect();

        // Steps 7 and 8.
        let state = Settled {
            contract: self,
            inputs,
            records: settled,
            closed,
        };
        let requirements: Vec<_> = self
            .requires
            .iter()
            .map(|r| RequirementValue {
                id: r.id.clone(),
                value: state.pred(&r.predicate, &mut Vec::new()),
            })
            .collect();
        let has = |truth| requirements.iter().any(|r| r.value == truth);
        let decision = if has(Truth::False) {
            Decision::Contradicted
        } else if has(Truth::Unknown) {
            Decision::Undetermined
        } else {
            Decision::Supported
        };
        Ok(Outcome {
            decision,
            requirements,
            ignored,
            conflicts,
        })
    }

    /// The fact as a record of its kind: every field declared and fitting,
    /// every required field present.
    fn conform<'a>(&self, fact: &'a Fact<'a>) -> Option<Record<'a>> {
        let declared = &self.kinds.get(fact.kind)?.fields;
        let fields = fact
            .fields
            .iter()
            .map(|(name, value)| Some((name, declared.get(name)?.ty.value(value)?)))
            .collect::<Option<BTreeMap<_, _>>>()?;
        declared
            .iter()
            .all(|(name, field)| field.optional || fields.contains_key(name.as_str()))
            .then_some(Record {
                id: fact.id,
                kind: fact.kind,
                source: fact.source,
                fields,
            })
    }

    /// Groups records of one kind by key, reports the groups whose members
    /// differ, and settles them by the contract's conflict policy. Returns
    /// the records in use by kind, the conflicts, and the kinds left open.
    #[allow(clippy::type_complexity)] // one private call site
    fn settle<'a>(
        &'a self,
        records: &'a [Record<'a>],
    ) -> (
        BTreeMap<&'a str, Vec<&'a Record<'a>>>,
        Vec<Conflict>,
        BTreeSet<&'a str>,
    ) {
        let agreed = |group: &[&Record<'_>]| group.windows(2).all(|w| w[0].fields == w[1].fields);
        let mut settled = BTreeMap::new();
        let mut conflicts = Vec::new();
        let mut open = BTreeSet::new();
        for (kind, declared) in &self.kinds {
            // Groups in the order their first member appears.
            let mut groups: Vec<(Vec<Option<&Val>>, Vec<&Record<'_>>)> = Vec::new();
            for record in records.iter().filter(|r| r.kind == kind) {
                let key: Vec<_> = declared
                    .key
                    .iter()
                    .map(|field| record.fields.get(field.as_str()))
                    .collect();
                match groups.iter_mut().find(|(k, _)| *k == key) {
                    Some((_, members)) => members.push(record),
                    None => groups.push((key, vec![record])),
                }
            }
            let mut kept = Vec::new();
            for (_, group) in &groups {
                if agreed(group) {
                    kept.push(group[0]);
                    continue;
                }
                let preferred = match self.conflicts {
                    ConflictPolicy::Unknown => None,
                    // The facts from the source listed first for the kind,
                    // among those present, if they agree with one another.
                    ConflictPolicy::SourceOrder => self
                        .sources
                        .get(kind)
                        .and_then(|sources| {
                            sources
                                .iter()
                                .find(|s| group.iter().any(|r| r.source == s.as_str()))
                        })
                        .and_then(|first| {
                            let from_first: Vec<_> = group
                                .iter()
                                .copied()
                                .filter(|r| r.source == first.as_str())
                                .collect();
                            agreed(&from_first).then(|| from_first[0])
                        }),
                };
                match preferred {
                    Some(record) => kept.push(record),
                    None => {
                        open.insert(kind.as_str());
                    }
                }
                conflicts.push(Conflict {
                    kind: kind.clone(),
                    facts: group.iter().map(|r| r.id.to_owned()).collect(),
                    resolved_to: preferred.map(|r| r.id.to_owned()),
                });
            }
            settled.insert(kind.as_str(), kept);
        }
        (settled, conflicts, open)
    }
}
