// SPDX-License-Identifier: Apache-2.0

//! Evaluating a well-formed contract against an environment.

use std::collections::{BTreeMap, BTreeSet};

use verified_canonical::{Object, Value};

use crate::model::{
    Aggregation, ConflictPolicy, Contract, Function, Op, Pred, Quantifier, Term, Val, is_name,
    number,
};
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
    /// Draft RFC 0012: `false` when the requirement's condition is `FALSE`,
    /// so it doesn't apply; its value is then reported as `NOT_APPLICABLE`.
    #[cfg(feature = "draft-wvp-0011-0012")]
    pub applies: bool,
}

impl RequirementValue {
    /// The language's name for the requirement's value.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        #[cfg(feature = "draft-wvp-0011-0012")]
        if !self.applies {
            return "NOT_APPLICABLE";
        }
        self.value.as_str()
    }
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
            o.insert("value", text(r.as_str()));
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

/// A value arithmetic computed, if it lies in the range of numbers:
/// strictly between −2⁶³ and 2⁶³ (Language 2, `ARITHMETIC_RANGE`).
fn in_range(value: i128) -> Result<i64, Refusal> {
    i64::try_from(value)
        .ok()
        .filter(|n| *n != i64::MIN)
        .ok_or(Refusal::ArithmeticRange)
}

/// A number's value. The static rules make every arithmetic operand one.
fn wide(value: &Val) -> Option<i128> {
    match value {
        Val::Number(n) => Some(i128::from(*n)),
        Val::Text(_) | Val::Bool(_) => None,
    }
}

type Scope<'s, 'a> = Vec<(&'a str, &'s Record<'a>)>;

/// Language 2: an aggregate's value over the records whose body is `TRUE`,
/// for a closed kind with every body settled. A count is an `int`; a
/// distinct count counts the distinct values of its field, two values being
/// the same when `eq` holds; a sum is exact, and only the sum is checked
/// against the range, never a partial total.
fn aggregate(aggregation: &Aggregation, values: &[(Truth, &Record<'_>)]) -> Result<Val, Refusal> {
    let selected = values
        .iter()
        .filter(|(value, _)| *value == Truth::True)
        .map(|(_, record)| *record);
    let named = |record: &Record<'_>, field: &Option<String>| {
        field
            .as_deref()
            .and_then(|name| record.fields.get(name))
            .cloned()
    };
    let total: i128 = match aggregation.function {
        Function::Count => match &aggregation.distinct {
            None => selected.count(),
            Some(_) => selected
                .filter_map(|r| named(r, &aggregation.distinct))
                .collect::<BTreeSet<_>>()
                .len(),
        }
        .try_into()
        .map_err(|_| Refusal::ArithmeticRange)?,
        Function::Sum => selected
            .filter_map(|r| named(r, &aggregation.field))
            .filter_map(|v| wide(&v))
            .sum(),
    };
    in_range(total).map(Val::Number)
}

impl<'a> Settled<'a> {
    /// The predicate's value. Every term below it is evaluated, under every
    /// binding of every quantifier and aggregate, whatever the value of the
    /// predicates around it, so that whether an evaluation refuses
    /// (`ARITHMETIC_RANGE`) never depends on a short-circuit (Language 2,
    /// "What is evaluated"). Language 1 terms never refuse, so this changes
    /// nothing for Language 1.
    fn pred<'s>(&'s self, predicate: &'a Pred, scope: &mut Scope<'s, 'a>) -> Result<Truth, Refusal>
    where
        'a: 's,
    {
        Ok(match predicate {
            Pred::Compare { op, left, right } => {
                match (self.value(left, scope)?, self.value(right, scope)?) {
                    (Some(a), Some(b)) => compare(*op, &a, &b),
                    _ => Truth::Unknown,
                }
            }
            Pred::And(args) => all(self.preds(args, scope)?.into_iter()),
            Pred::Or(args) => any(self.preds(args, scope)?.into_iter()),
            Pred::Not(inner) => not(self.pred(inner, scope)?),
            Pred::Quantified {
                quantifier,
                variable,
                kind,
                body,
            } => {
                let values = self.bodies(variable, kind, body, scope)?;
                // One record can prove an `exists` or disprove a `forall`.
                // The opposite answers are claims about every record, so
                // they hold only for a kind that is closed.
                let values = values.into_iter().map(|(value, _)| value);
                let (seen, needs_closure) = match quantifier {
                    Quantifier::Exists => (any(values), Truth::False),
                    Quantifier::Forall => (all(values), Truth::True),
                };
                if seen == needs_closure && !self.closed.contains(kind.as_str()) {
                    Truth::Unknown
                } else {
                    seen
                }
            }
            Pred::Aggregate {
                aggregation,
                variable,
                kind,
                body,
                op,
                than,
            } => {
                let values = self.bodies(variable, kind, body, scope)?;
                let than = self.value(than, scope)?;
                // A value only over a closed kind with every body settled.
                let settled = self.closed.contains(kind.as_str())
                    && values.iter().all(|(value, _)| *value != Truth::Unknown);
                let computed = if settled {
                    Some(aggregate(aggregation, &values)?)
                } else {
                    None
                };
                match (computed, than) {
                    (Some(a), Some(b)) => compare(*op, &a, &b),
                    _ => Truth::Unknown,
                }
            }
        })
    }

    /// Every predicate's value, all of them evaluated.
    fn preds<'s>(
        &'s self,
        args: &'a [Pred],
        scope: &mut Scope<'s, 'a>,
    ) -> Result<Vec<Truth>, Refusal>
    where
        'a: 's,
    {
        args.iter().map(|arg| self.pred(arg, scope)).collect()
    }

    /// The body's value for each record of `kind` in use, bound to
    /// `variable`, with the record.
    fn bodies<'s>(
        &'s self,
        variable: &'a str,
        kind: &str,
        body: &'a Pred,
        scope: &mut Scope<'s, 'a>,
    ) -> Result<Vec<(Truth, &'s Record<'a>)>, Refusal>
    where
        'a: 's,
    {
        let records = self.records.get(kind).map_or(&[][..], Vec::as_slice);
        let mut values = Vec::with_capacity(records.len());
        for record in records {
            scope.push((variable, record));
            let value = self.pred(body, scope);
            scope.pop();
            values.push((value?, *record));
        }
        Ok(values)
    }

    /// The term's value, or `None` when it has none: an absent optional
    /// field, or arithmetic over one. Each arithmetic node that has a value
    /// is checked against the range, whatever its parent; one without a
    /// value computes nothing, but its operands are still evaluated.
    fn value<'s>(
        &'s self,
        term: &'a Term,
        scope: &mut Scope<'s, 'a>,
    ) -> Result<Option<Val>, Refusal>
    where
        'a: 's,
    {
        let number = |value: Option<Val>| value.as_ref().and_then(wide);
        let checked =
            |value: Option<i128>| value.map(in_range).transpose().map(|n| n.map(Val::Number));
        match term {
            Term::Literal { value, .. } => Ok(Some(value.clone())),
            Term::Input(name) => Ok(self.inputs.get(name.as_str()).cloned()),
            Term::Parameter(name) => Ok(self.contract.policy.get(name).map(|p| p.value.clone())),
            Term::Field { variable, field } => Ok(scope
                .iter()
                .find(|(bound, _)| bound == variable)
                .and_then(|(_, record)| record.fields.get(field.as_str()))
                .cloned()),
            Term::Add(a, b) => {
                let (a, b) = (number(self.value(a, scope)?), number(self.value(b, scope)?));
                checked(a.zip(b).map(|(a, b)| a + b))
            }
            Term::Sub(a, b) => {
                let (a, b) = (number(self.value(a, scope)?), number(self.value(b, scope)?));
                checked(a.zip(b).map(|(a, b)| a - b))
            }
            Term::Scale { factor, of } => {
                let of = number(self.value(of, scope)?);
                checked(of.zip(*factor).map(|(v, f)| v * i128::from(f)))
            }
            Term::Abs(of) => checked(number(self.value(of, scope)?).map(i128::abs)),
            // Draft RFC 0011. Both operands lie in the range of numbers, so
            // the product needs at most 126 bits.
            Term::Mul(a, b) => {
                let (a, b) = (number(self.value(a, scope)?), number(self.value(b, scope)?));
                checked(a.zip(b).map(|(a, b)| a * b))
            }
            // Draft RFC 0011: every body is evaluated; the value is the
            // aggregate predicate's, only over a closed kind with every body
            // settled.
            Term::Aggregate {
                aggregation,
                variable,
                kind,
                body,
            } => {
                let values = self.bodies(variable, kind, body, scope)?;
                let settled = self.closed.contains(kind.as_str())
                    && values.iter().all(|(value, _)| *value != Truth::Unknown);
                if settled {
                    aggregate(aggregation, &values).map(Some)
                } else {
                    Ok(None)
                }
            }
        }
    }
}

/// Draft RFC 0012's decision for a contract none of whose requirements
/// applies. Without the draft, every requirement applies, so this is never
/// reached.
#[cfg(feature = "draft-wvp-0011-0012")]
const fn not_applicable() -> Decision {
    Decision::NotApplicable
}

#[cfg(not(feature = "draft-wvp-0011-0012"))]
const fn not_applicable() -> Decision {
    Decision::Supported
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
        let requirements = self
            .requires
            .iter()
            .map(|r| {
                // Draft RFC 0012: the condition and the predicate are both
                // evaluated, whatever the condition's value.
                let condition = r
                    .applies_when
                    .as_ref()
                    .map(|c| state.pred(c, &mut Vec::new()))
                    .transpose()?;
                let value = state.pred(&r.predicate, &mut Vec::new())?;
                let value = match condition {
                    None | Some(Truth::True | Truth::False) => value,
                    Some(Truth::Unknown) => Truth::Unknown,
                };
                Ok(RequirementValue {
                    id: r.id.clone(),
                    value,
                    #[cfg(feature = "draft-wvp-0011-0012")]
                    applies: condition != Some(Truth::False),
                })
            })
            .collect::<Result<Vec<_>, Refusal>>()?;
        let applying = || {
            requirements
                .iter()
                .filter(|r| r.as_str() != "NOT_APPLICABLE")
        };
        let has = |truth| applying().any(|r| r.value == truth);
        let decision = if has(Truth::False) {
            Decision::Contradicted
        } else if has(Truth::Unknown) {
            Decision::Undetermined
        } else if applying().next().is_none() {
            // Draft RFC 0012: a contract none of whose requirements applies.
            // (A contract always has a requirement.)
            not_applicable()
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
