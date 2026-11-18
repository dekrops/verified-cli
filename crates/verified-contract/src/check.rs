// SPDX-License-Identifier: Apache-2.0

//! The static rules: what makes a contract well formed. They are decidable
//! from the contract alone, and a contract that breaks one is never
//! evaluated (`CONTRACT_ILL_FORMED`).

use verified_canonical::Value;

use crate::model::{
    Aggregation, Contract, Function, Kind, Op, Pred, Term, Type, is_name, is_version,
};
use crate::read::read_contract;
use crate::{Language, Refusal, SEMANTICS};

const MAX_KINDS: usize = 32;
const MAX_FIELDS: usize = 32;
const MAX_REQUIREMENTS: usize = 64;
const MAX_PREDICATE_NODES: u64 = 512;
const MAX_QUANTIFIER_DEPTH: u32 = 3;

impl Contract {
    /// Reads a Language 1 contract and checks the language's static rules.
    ///
    /// The value must already be JSON under `verified-json-v1`; whether the
    /// text it came from was canonical is the caller's check.
    pub fn read(json: &Value) -> Result<Self, Refusal> {
        Self::read_as(json, Language::One)
    }

    /// Reads a contract of `language` and checks that language's static
    /// rules. A contract naming another language is `CONTRACT_ILL_FORMED`.
    pub fn read_as(json: &Value, language: Language) -> Result<Self, Refusal> {
        let contract = read_contract(json, language)?;
        if contract.is_well_formed(language) {
            Ok(contract)
        } else {
            Err(Refusal::ContractIllFormed)
        }
    }

    fn is_well_formed(&self, language: Language) -> bool {
        self.language == language.id()
            && self.semantics == SEMANTICS
            && is_name(&self.id)
            && is_version(&self.version)
            && self.declarations_are_well_formed()
            && self.requirements_are_well_formed()
    }

    fn declarations_are_well_formed(&self) -> bool {
        let names = |mut names: std::collections::btree_map::Keys<'_, String, _>| {
            names.all(|name| is_name(name))
        };
        names(self.inputs.keys())
            && self.inputs.values().all(Type::is_valid)
            && self.inputs.keys().all(|n| !self.policy.contains_key(n))
            && self.kinds.len() <= MAX_KINDS
            && self
                .kinds
                .iter()
                .all(|(name, kind)| is_name(name) && kind_is_well_formed(kind))
            // Every kind has accepted sources, and no other kind is named.
            && self.kinds.keys().all(|kind| {
                self.sources.get(kind).is_some_and(|sources| {
                    !sources.is_empty() && sources.iter().all(|s| is_name(s)) && distinct(sources)
                })
            })
            && self.sources.keys().all(|kind| self.kinds.contains_key(kind))
            && self.policy.iter().all(|(name, parameter)| {
                is_name(name)
                    && parameter.ty.is_valid()
                    && is_name(&parameter.id)
                    && is_version(&parameter.version)
            })
            && self
                .cutoff
                .as_ref()
                .is_none_or(|input| self.inputs.get(input) == Some(&Type::Time))
    }

    fn requirements_are_well_formed(&self) -> bool {
        let predicates = || self.requires.iter().map(|r| &r.predicate);
        // Draft RFC 0012: a condition follows a predicate's static rules,
        // and counts toward the node limit and the depth limit.
        let conditions = || self.requires.iter().filter_map(|r| r.applies_when.as_ref());
        !self.requires.is_empty()
            && self.requires.len() <= MAX_REQUIREMENTS
            && self.requires.iter().all(|r| is_name(&r.id))
            && self.requires.windows(2).all(|w| w[0].id < w[1].id)
            && predicates().chain(conditions()).map(Pred::nodes).sum::<u64>() <= MAX_PREDICATE_NODES
            && predicates()
                .chain(conditions())
                .all(|p| p.quantifier_depth() <= MAX_QUANTIFIER_DEPTH)
            && predicates()
                .chain(conditions())
                .all(|p| self.is_typed(&mut Vec::new(), p))
            && !predicates().any(is_contradictory)
            // No requirement is the negation of another.
            && !predicates().any(|p| match p {
                Pred::Not(negated) => predicates().any(|q| q == &**negated),
                _ => false,
            })
    }

    /// The term's type, if it is well typed. `scope` holds the bound
    /// variables with their kinds.
    fn term_type<'a>(
        &'a self,
        scope: &mut Vec<(&'a str, &'a str)>,
        term: &'a Term,
    ) -> Option<Type> {
        let numeric = |ty: Type| ty.is_numeric().then_some(ty);
        match term {
            Term::Literal { of, .. } => of.is_valid().then(|| of.clone()),
            Term::Input(name) => self.inputs.get(name).cloned(),
            Term::Parameter(name) => self.policy.get(name).map(|p| p.ty.clone()),
            Term::Field { variable, field } => {
                let (_, kind) = scope.iter().find(|(bound, _)| bound == variable)?;
                self.kinds
                    .get(*kind)?
                    .fields
                    .get(field)
                    .map(|f| f.ty.clone())
            }
            // Both operands of one numeric type, with that type.
            Term::Add(a, b) => {
                let ty = self.term_type(scope, a)?;
                (self.term_type(scope, b)? == ty)
                    .then_some(ty)
                    .and_then(numeric)
            }
            // The same, or two times, giving whole seconds.
            Term::Sub(a, b) => {
                let ty = self.term_type(scope, a)?;
                if self.term_type(scope, b)? != ty {
                    None
                } else if ty == Type::Time {
                    Some(Type::Int)
                } else {
                    numeric(ty)
                }
            }
            Term::Scale { factor, of } => factor
                .and_then(|_| self.term_type(scope, of))
                .and_then(numeric),
            Term::Abs(of) => self.term_type(scope, of).and_then(numeric),
            // Draft RFC 0011: at least one operand an `int`; the result has
            // the other operand's type, so units stay meaningful.
            Term::Mul(a, b) => {
                let (a, b) = (self.term_type(scope, a)?, self.term_type(scope, b)?);
                match (a, b) {
                    (Type::Int, other) | (other, Type::Int) => numeric(other),
                    _ => None,
                }
            }
            // Draft RFC 0011: an aggregate term, typed as the aggregate
            // predicate is, its variable bound in its body only.
            Term::Aggregate {
                aggregation,
                variable,
                kind,
                body,
            } => {
                if !is_name(variable)
                    || scope.iter().any(|(bound, _)| bound == variable)
                    || !self.kinds.contains_key(kind)
                {
                    return None;
                }
                let ty = self.aggregate_type(kind, aggregation)?;
                scope.push((variable, kind));
                let typed = self.is_typed(scope, body);
                scope.pop();
                typed.then_some(ty)
            }
        }
    }

    /// Language 2: the type an aggregation over `kind` yields, if its
    /// members fit it. `count` yields an `int` and names no field; with
    /// `distinct`, a non-optional field of the kind, of any type. `sum`
    /// names a non-optional numeric field and has the field's type.
    fn aggregate_type(&self, kind: &str, aggregation: &Aggregation) -> Option<Type> {
        let declared = |name: &str| {
            self.kinds
                .get(kind)?
                .fields
                .get(name)
                .filter(|field| !field.optional)
        };
        match (
            aggregation.function,
            &aggregation.field,
            &aggregation.distinct,
        ) {
            (Function::Count, None, None) => Some(Type::Int),
            (Function::Count, None, Some(name)) => declared(name).map(|_| Type::Int),
            (Function::Sum, Some(name), None) => declared(name)
                .map(|field| field.ty.clone())
                .filter(Type::is_numeric),
            _ => None,
        }
    }

    /// Whether every name in `predicate` is declared and every comparison is
    /// between identical types. `scope` holds the bound variables with their
    /// kinds.
    fn is_typed<'a>(&'a self, scope: &mut Vec<(&'a str, &'a str)>, predicate: &'a Pred) -> bool {
        match predicate {
            Pred::Compare { op, left, right } => {
                match (self.term_type(scope, left), self.term_type(scope, right)) {
                    (Some(a), Some(b)) => comparable(*op, &a, &b),
                    _ => false,
                }
            }
            Pred::And(args) | Pred::Or(args) => {
                !args.is_empty() && args.iter().all(|arg| self.is_typed(scope, arg))
            }
            Pred::Not(inner) => self.is_typed(scope, inner),
            Pred::Quantified {
                variable,
                kind,
                body,
                ..
            } => {
                if !is_name(variable)
                    || scope.iter().any(|(bound, _)| bound == variable)
                    || !self.kinds.contains_key(kind)
                {
                    return false;
                }
                scope.push((variable, kind));
                let typed = self.is_typed(scope, body);
                scope.pop();
                typed
            }
            // The variable is bound in the body only: `than` is typed in the
            // enclosing scope.
            Pred::Aggregate {
                aggregation,
                variable,
                kind,
                body,
                op,
                than,
            } => {
                if !is_name(variable)
                    || scope.iter().any(|(bound, _)| bound == variable)
                    || !self.kinds.contains_key(kind)
                {
                    return false;
                }
                let compared = match (
                    self.aggregate_type(kind, aggregation),
                    self.term_type(scope, than),
                ) {
                    (Some(a), Some(b)) => comparable(*op, &a, &b),
                    _ => false,
                };
                scope.push((variable, kind));
                let typed = self.is_typed(scope, body);
                scope.pop();
                compared && typed
            }
        }
    }
}

/// Language 1's comparison rule: identical types, ordered for `lt`, `le`,
/// `gt` and `ge`.
fn comparable(op: Op, a: &Type, b: &Type) -> bool {
    a == b && (matches!(op, Op::Eq | Op::Ne) || a.is_ordered())
}

fn distinct(names: &[String]) -> bool {
    names
        .iter()
        .enumerate()
        .all(|(i, name)| !names[..i].contains(name))
}

fn kind_is_well_formed(kind: &Kind) -> bool {
    !kind.fields.is_empty()
        && kind.fields.len() <= MAX_FIELDS
        && kind
            .fields
            .iter()
            .all(|(name, field)| is_name(name) && field.ty.is_valid())
        && !kind.key.is_empty()
        && distinct(&kind.key)
        && kind
            .key
            .iter()
            .all(|field| kind.fields.get(field).is_some_and(|f| !f.optional))
}

/// Whether some conjunction contains a predicate and its negation. This is
/// syntactic, not a satisfiability check.
fn is_contradictory(predicate: &Pred) -> bool {
    let here = match predicate {
        Pred::And(args) => args.iter().any(|arg| match arg {
            Pred::Not(negated) => args.iter().any(|other| other == &**negated),
            _ => false,
        }),
        _ => false,
    };
    here || predicate.children().iter().any(is_contradictory)
}
