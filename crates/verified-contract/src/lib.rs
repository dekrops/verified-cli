// SPDX-License-Identifier: Apache-2.0

//! Work Contract Language 1 (`work-contract-1`, semantics `kleene-1`).
//!
//! The language is a **draft**. A work contract states, as data, what must be
//! true for a unit of work to count as done. This crate reads a contract,
//! checks the language's static rules, and evaluates a checked contract
//! against an environment of admitted records:
//!
//! - [`Contract::read`] refuses anything that is not a well-formed contract;
//! - [`Contract::evaluate`] yields an [`Outcome`] (one of three
//!   [`Decision`]s, with the value of every requirement) or a [`Refusal`].
//!
//! Evaluation is a pure function of the contract and the environment. It
//! reads no clock, random value, file or network, and contracts contain no
//! executable code, recursion or user-defined function.
//!
//! Who signed a record, and whether the signer may speak for the source it
//! names, is decided before evaluation. This crate sees only source names.
//!
//! A `SUPPORTED` decision means the records from the accepted sources
//! establish every requirement under this contract. It does not mean the
//! sources told the truth.

mod check;
mod evaluate;
mod model;
mod read;

use std::fmt;

pub use evaluate::{Conflict, Outcome, RequirementValue};
pub use model::Contract;

/// The identifier of the language this crate implements.
pub const LANGUAGE: &str = "work-contract-1";
/// The identifier of the evaluation semantics this crate implements.
pub const SEMANTICS: &str = "kleene-1";

/// Why a contract or an environment was refused. A refusal is not a
/// decision: it says nothing about the work.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// Not a contract of the language's forms.
    ContractMalformed,
    /// A contract that breaks a static rule.
    ContractIllFormed,
    /// Not an environment of the language's form.
    EnvironmentMalformed,
    /// Inputs or accepted facts that do not fit the contract.
    EnvironmentNonconforming,
    /// Evaluation would exceed the language's work bound.
    WorkLimit,
}

impl Refusal {
    /// The language's code for this refusal. Stable.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ContractMalformed => "CONTRACT_MALFORMED",
            Self::ContractIllFormed => "CONTRACT_ILL_FORMED",
            Self::EnvironmentMalformed => "ENVIRONMENT_MALFORMED",
            Self::EnvironmentNonconforming => "ENVIRONMENT_NONCONFORMING",
            Self::WorkLimit => "WORK_LIMIT",
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for Refusal {}

/// What a contract concludes about an environment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Decision {
    /// Every requirement is established by accepted evidence.
    Supported,
    /// At least one requirement is conclusively false under accepted
    /// evidence.
    Contradicted,
    /// The accepted evidence does not settle at least one requirement.
    Undetermined,
}

impl Decision {
    /// The language's name for this decision. Stable.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "SUPPORTED",
            Self::Contradicted => "CONTRADICTED",
            Self::Undetermined => "UNDETERMINED",
        }
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The value of a predicate under strong Kleene logic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Truth {
    /// Established.
    True,
    /// Conclusively not the case.
    False,
    /// Not settled by the accepted evidence.
    Unknown,
}

impl Truth {
    /// The language's name for this value. Stable.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::True => "TRUE",
            Self::False => "FALSE",
            Self::Unknown => "UNKNOWN",
        }
    }
}

impl fmt::Display for Truth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
