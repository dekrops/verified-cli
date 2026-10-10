//! The static rules: what makes a contract well formed. They are decidable
//! from the contract alone, and a contract that breaks one is never
//! evaluated (`CONTRACT_ILL_FORMED`).

use verified_canonical::Value;

use crate::model::{Contract, Kind, Op, Pred, Term, Type, is_name, is_version};
use crate::read::read_contract;
use crate::{LANGUAGE, Refusal, SEMANTICS};

const MAX_KINDS: usize = 32;
const MAX_FIELDS: usize = 32;
const MAX_REQUIREMENTS: usize = 64;
const MAX_PREDICATE_NODES: u64 = 512;
const MAX_QUANTIFIER_DEPTH: u32 = 3;

impl Contract {
    /// Reads a contract and checks the language's static rules.
    ///
    /// The value must already be JSON under `verified-json-v1`; whether the
    /// text it came from was canonical is the caller's check.
    pub fn read(json: &Value) -> Result<Self, Refusal> {
        let contract = read_contract(json)?;
        if contract.is_well_formed() {
            Ok(contract)
        } else {
            Err(Refusal::ContractIllFormed)
        }
    }

    fn is_well_formed(&self) -> bool {
        self.language == LANGUAGE
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
        !self.requires.is_empty()
            && self.requires.len() <= MAX_REQUIREMENTS
            && self.requires.iter().all(|r| is_name(&r.id))
            && self.requires.windows(2).all(|w| w[0].id < w[1].id)
            && predicates().map(Pred::nodes).sum::<u64>() <= MAX_PREDICATE_NODES
            && predicates().all(|p| p.quantifier_depth() <= MAX_QUANTIFIER_DEPTH)
            && predicates().all(|p| self.is_typed(&mut Vec::new(), p))
            && !predicates().any(is_contradictory)
            // No requirement is the negation of another.
            && !predicates().any(|p| match p {
                Pred::Not(negated) => predicates().any(|q| q == &**negated),
                _ => false,
            })
    }

    fn term_type<'a>(&'a self, scope: &[(&str, &str)], term: &'a Term) -> Option<&'a Type> {
        match term {
            Term::Literal { of, .. } => of.is_valid().then_some(of),
            Term::Input(name) => self.inputs.get(name),
            Term::Parameter(name) => self.policy.get(name).map(|p| &p.ty),
            Term::Field { variable, field } => {
                let (_, kind) = scope.iter().find(|(bound, _)| bound == variable)?;
                self.kinds.get(*kind)?.fields.get(field).map(|f| &f.ty)
            }
        }
    }

    /// Whether every name in `predicate` is declared and every comparison is
    /// between identical types. `scope` holds the bound variables with their
    /// kinds.
    fn is_typed<'a>(&'a self, scope: &mut Vec<(&'a str, &'a str)>, predicate: &'a Pred) -> bool {
        match predicate {
            Pred::Compare { op, left, right } => {
                match (self.term_type(scope, left), self.term_type(scope, right)) {
                    (Some(a), Some(b)) => {
                        a == b && (matches!(op, Op::Eq | Op::Ne) || a.is_ordered())
                    }
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
        }
    }
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
