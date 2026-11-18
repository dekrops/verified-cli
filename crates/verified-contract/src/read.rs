// SPDX-License-Identifier: Apache-2.0

//! Reading a contract from JSON. Any failure here is `CONTRACT_MALFORMED`:
//! the value is not a contract of the language's forms.

use std::collections::BTreeMap;

use verified_canonical::{Object, Value};

use crate::model::{
    Aggregation, ConflictPolicy, Contract, Field, Function, Kind, Op, Parameter, Pred, Quantifier,
    Requirement, Term, Type,
};
use crate::{Language, Refusal};

type Read<T> = Result<T, Refusal>;

const MALFORMED: Refusal = Refusal::ContractMalformed;

/// A predicate node more than this many levels below its requirement is not
/// read at all, so that a reader's recursion is bounded before any rule is
/// checked.
const MAX_PREDICATE_DEPTH: usize = 64;

/// An object whose members are all among `allowed`.
fn only<'a>(value: &'a Value, allowed: &[&str]) -> Read<&'a Object> {
    value
        .as_object()
        .filter(|object| object.keys().all(|key| allowed.contains(&key)))
        .ok_or(MALFORMED)
}

/// The object, if its members are exactly `keys`.
fn exactly<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Object> {
    value
        .as_object()
        .filter(|object| object.len() == keys.len() && keys.iter().all(|k| object.get(k).is_some()))
}

fn need<'a>(object: &'a Object, key: &str) -> Read<&'a Value> {
    object.get(key).ok_or(MALFORMED)
}

fn string(value: &Value) -> Read<String> {
    value.as_str().map(str::to_owned).ok_or(MALFORMED)
}

fn list(value: &Value) -> Read<&[Value]> {
    value.as_array().ok_or(MALFORMED)
}

/// A scale: a JSON number with a whole value in the 32-bit range.
fn small(value: &Value) -> Read<i32> {
    value
        .as_integer()
        .and_then(verified_canonical::Integer::to_i64)
        .and_then(|n| i32::try_from(n).ok())
        .ok_or(MALFORMED)
}

fn table<T>(value: &Value, read: impl Fn(&Value) -> Read<T>) -> Read<BTreeMap<String, T>> {
    value
        .as_object()
        .ok_or(MALFORMED)?
        .iter()
        .map(|(name, member)| Ok((name.to_owned(), read(member)?)))
        .collect()
}

fn read_type(value: &Value, extra: &[&str]) -> Read<Type> {
    let object = value.as_object().ok_or(MALFORMED)?;
    let members = |own: &[&str]| only(value, &[own, extra].concat());
    match need(object, "type")?.as_str().ok_or(MALFORMED)? {
        name @ ("text" | "bool" | "int" | "time") => {
            members(&["type"])?;
            Ok(match name {
                "text" => Type::Text,
                "bool" => Type::Bool,
                "int" => Type::Int,
                _ => Type::Time,
            })
        }
        "decimal" => {
            members(&["type", "scale"])?;
            Ok(Type::Decimal {
                scale: small(need(object, "scale")?)?,
            })
        }
        "money" => {
            members(&["type", "scale", "currency"])?;
            Ok(Type::Money {
                scale: small(need(object, "scale")?)?,
                currency: string(need(object, "currency")?)?,
            })
        }
        _ => Err(MALFORMED),
    }
}

/// A field type: a type that may carry `"optional": true`. An omitted member
/// is the only spelling of "not optional".
fn read_field(value: &Value) -> Read<Field> {
    let ty = read_type(value, &["optional"])?;
    let optional = match value.as_object().and_then(|o| o.get("optional")) {
        None => false,
        Some(Value::Bool(true)) => true,
        Some(_) => return Err(MALFORMED),
    };
    Ok(Field { ty, optional })
}

/// A `scale` factor: a number string. One spelled as a number but outside
/// the range of numbers is read as `None`, for the static rules to refuse.
fn read_factor(value: &Value) -> Read<Option<i64>> {
    let text = value.as_str().ok_or(MALFORMED)?;
    let digits = text.strip_prefix('-').unwrap_or(text);
    let spelled = !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'))
        && text != "-0";
    if !spelled {
        return Err(MALFORMED);
    }
    Ok(text.parse::<i64>().ok().filter(|n| *n != i64::MIN))
}

/// A term. `depth` is the level of the term below its requirement; the
/// arithmetic nodes of Language 2 count toward the read depth as predicates
/// do.
fn read_term(value: &Value, depth: usize, language: Language) -> Read<Term> {
    if let Some(o) = exactly(value, &["lit", "of"]) {
        let of = read_type(need(o, "of")?, &[])?;
        let value = of.value(need(o, "lit")?).ok_or(MALFORMED)?;
        return Ok(Term::Literal { value, of });
    }
    if let Some(o) = exactly(value, &["input"]) {
        return Ok(Term::Input(string(need(o, "input")?)?));
    }
    if let Some(o) = exactly(value, &["param"]) {
        return Ok(Term::Parameter(string(need(o, "param")?)?));
    }
    if let Some(o) = exactly(value, &["var", "field"]) {
        return Ok(Term::Field {
            variable: string(need(o, "var")?)?,
            field: string(need(o, "field")?)?,
        });
    }
    if language != Language::Two || depth > MAX_PREDICATE_DEPTH {
        return Err(MALFORMED);
    }
    let next = |inner: &Value| read_term(inner, depth + 1, language).map(Box::new);
    let pair = |inner: &Value| match list(inner)? {
        [a, b] => Ok((next(a)?, next(b)?)),
        _ => Err(MALFORMED),
    };
    if let Some(o) = exactly(value, &["add"]) {
        let (a, b) = pair(need(o, "add")?)?;
        return Ok(Term::Add(a, b));
    }
    if let Some(o) = exactly(value, &["sub"]) {
        let (a, b) = pair(need(o, "sub")?)?;
        return Ok(Term::Sub(a, b));
    }
    if let Some(o) = exactly(value, &["scale", "of"]) {
        return Ok(Term::Scale {
            factor: read_factor(need(o, "scale")?)?,
            of: next(need(o, "of")?)?,
        });
    }
    if let Some(o) = exactly(value, &["abs"]) {
        return Ok(Term::Abs(next(need(o, "abs")?)?));
    }
    Err(MALFORMED)
}

/// Language 2's aggregate: `{ aggregate, of, in, where, cmp, than }`, with
/// `field` (for `sum`) and `distinct` (for `count`) where present. Which of
/// them an aggregation may carry is a static rule, not a reading one.
fn read_aggregate(o: &Object, depth: usize, language: Language) -> Read<Pred> {
    let optional = |key: &str| o.get(key).map(string).transpose();
    let (field, distinct) = (optional("field")?, optional("distinct")?);
    let function = match need(o, "aggregate")?.as_str() {
        Some("count") => Function::Count,
        Some("sum") => Function::Sum,
        _ => return Err(MALFORMED),
    };
    let aggregation = Aggregation {
        function,
        field,
        distinct,
    };
    Ok(Pred::Aggregate {
        aggregation,
        variable: string(need(o, "of")?)?,
        kind: string(need(o, "in")?)?,
        body: Box::new(read_pred(need(o, "where")?, depth + 1, language)?),
        op: read_op(need(o, "cmp")?)?,
        than: read_term(need(o, "than")?, depth + 1, language)?,
    })
}

fn read_op(value: &Value) -> Read<Op> {
    Ok(match value.as_str() {
        Some("eq") => Op::Eq,
        Some("ne") => Op::Ne,
        Some("lt") => Op::Lt,
        Some("le") => Op::Le,
        Some("gt") => Op::Gt,
        Some("ge") => Op::Ge,
        _ => return Err(MALFORMED),
    })
}

fn read_pred(value: &Value, depth: usize, language: Language) -> Read<Pred> {
    if depth > MAX_PREDICATE_DEPTH {
        return Err(MALFORMED);
    }
    let next = |inner: &Value| read_pred(inner, depth + 1, language);
    let term = |inner: &Value| read_term(inner, depth + 1, language);
    let all = |inner: &Value| list(inner)?.iter().map(next).collect::<Read<Vec<_>>>();
    let quantified = |quantifier, o: &Object, variable: &str, body: &str| {
        Ok(Pred::Quantified {
            quantifier,
            variable: string(need(o, variable)?)?,
            kind: string(need(o, "in")?)?,
            body: Box::new(next(need(o, body)?)?),
        })
    };
    if let Some(o) = exactly(value, &["cmp", "left", "right"]) {
        return Ok(Pred::Compare {
            op: read_op(need(o, "cmp")?)?,
            left: term(need(o, "left")?)?,
            right: term(need(o, "right")?)?,
        });
    }
    if let Some(o) = exactly(value, &["and"]) {
        return Ok(Pred::And(all(need(o, "and")?)?));
    }
    if let Some(o) = exactly(value, &["or"]) {
        return Ok(Pred::Or(all(need(o, "or")?)?));
    }
    if let Some(o) = exactly(value, &["not"]) {
        return Ok(Pred::Not(Box::new(next(need(o, "not")?)?)));
    }
    if let Some(o) = exactly(value, &["exists", "in", "where"]) {
        return quantified(Quantifier::Exists, o, "exists", "where");
    }
    if let Some(o) = exactly(value, &["forall", "in", "holds"]) {
        return quantified(Quantifier::Forall, o, "forall", "holds");
    }
    if language == Language::Two
        && let Some(o) = value.as_object().filter(|o| o.get("aggregate").is_some())
    {
        const MEMBERS: [&str; 6] = ["aggregate", "of", "in", "where", "cmp", "than"];
        only(value, &[&MEMBERS[..], &["field", "distinct"]].concat())?;
        if MEMBERS.iter().all(|key| o.get(key).is_some()) {
            return read_aggregate(o, depth, language);
        }
    }
    Err(MALFORMED)
}

fn read_kind(value: &Value) -> Read<Kind> {
    let kind = only(value, &["key", "fields"])?;
    Ok(Kind {
        key: list(need(kind, "key")?)?
            .iter()
            .map(string)
            .collect::<Read<_>>()?,
        fields: table(need(kind, "fields")?, read_field)?,
    })
}

fn read_parameter(value: &Value) -> Read<Parameter> {
    let parameter = only(value, &["policy", "type", "value"])?;
    let reference = only(need(parameter, "policy")?, &["id", "version"])?;
    let ty = read_type(need(parameter, "type")?, &[])?;
    let value = ty.value(need(parameter, "value")?).ok_or(MALFORMED)?;
    Ok(Parameter {
        id: string(need(reference, "id")?)?,
        version: string(need(reference, "version")?)?,
        ty,
        value,
    })
}

fn read_requirement(value: &Value, language: Language) -> Read<Requirement> {
    let requirement = only(value, &["id", "predicate"])?;
    Ok(Requirement {
        id: string(need(requirement, "id")?)?,
        predicate: read_pred(need(requirement, "predicate")?, 0, language)?,
    })
}

/// Reads a contract's forms as those of `language`, without checking the
/// static rules.
pub(crate) fn read_contract(json: &Value, language: Language) -> Read<Contract> {
    let root = only(
        json,
        &[
            "language",
            "identity",
            "inputs",
            "kinds",
            "evidence",
            "policy",
            "evaluation",
            "requires",
        ],
    )?;
    let identity = only(need(root, "identity")?, &["id", "version"])?;
    let evidence = only(need(root, "evidence")?, &["conflicts", "sources"])?;
    let evaluation = only(need(root, "evaluation")?, &["semantics", "cutoff"])?;
    let conflicts = match need(evidence, "conflicts")?.as_str() {
        Some("unknown") => ConflictPolicy::Unknown,
        Some("source-order") => ConflictPolicy::SourceOrder,
        _ => return Err(MALFORMED),
    };
    Ok(Contract {
        language: string(need(root, "language")?)?,
        id: string(need(identity, "id")?)?,
        version: string(need(identity, "version")?)?,
        inputs: table(need(root, "inputs")?, |t| read_type(t, &[]))?,
        kinds: table(need(root, "kinds")?, read_kind)?,
        conflicts,
        sources: table(need(evidence, "sources")?, |sources| {
            list(sources)?.iter().map(string).collect()
        })?,
        policy: table(need(root, "policy")?, read_parameter)?,
        semantics: string(need(evaluation, "semantics")?)?,
        cutoff: evaluation.get("cutoff").map(string).transpose()?,
        requires: list(need(root, "requires")?)?
            .iter()
            .map(|r| read_requirement(r, language))
            .collect::<Read<_>>()?,
    })
}
