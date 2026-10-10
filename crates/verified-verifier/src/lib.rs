// SPDX-License-Identifier: Apache-2.0

//! Pure offline verification of Work Verification Protocol (WVP) packages.
//!
//! WVP is a **draft** protocol. [`verify`] takes the bytes of a package and
//! returns either a [`Report`] of what was established or a [`Rejection`].
//! It reads no file, opens no socket and consults no clock.
//!
//! # What is checked
//!
//! The protocol's thirteen checks, in order, stopping at the first failure:
//!
//! | Step | Check | Refusal |
//! | --- | --- | --- |
//! | 1 | canonical text | `NOT_CANONICAL` |
//! | 2 | package, protocol and encoding versions | `UNSUPPORTED_VERSION` |
//! | 3 | container members | `MALFORMED_COMPONENT` |
//! | 4 | the six components, in order | `COMPONENT_SET` |
//! | 5 | component digests | `COMPONENT_DIGEST` |
//! | 6 | package commitment and identifier | `COMMITMENT_MISMATCH` |
//! | 7 | every component well formed at every depth | `MALFORMED_COMPONENT` |
//! | 8 | the decision names this protocol's evaluator | `UNSUPPORTED_EVALUATOR` |
//! | 9 | each statement verifies under the registry | the statement's code |
//! | 10 | admission | the admission code |
//! | 11 | input conditions | `INPUT_MISMATCH` |
//! | 12 | the recomputed decision equals the recorded one | `DECISION_MISMATCH` |
//! | 13 | every issuer signature counts | `ISSUER_SIGNATURE_INVALID` |
//!
//! Steps 1 to 7 establish **package integrity**. Steps 8 to 13 need a trust
//! registry ([`Trust`]), which only the relying party can supply: a key
//! carried by a package is never trusted. Without a registry verification
//! stops after step 7 and the report says that signatures were not checked
//! and the decision was not reproduced.
//!
//! For `wvp-0.2` a relying party may also state [`Expectations`] (tenant,
//! contract digest, claim), checked after everything else.
//!
//! # What a report means
//!
//! A [`Report`] states each property separately. There is deliberately no
//! single "valid" flag. A reproduced decision says the signed records, from
//! signers the relying party's registry authorizes, lead to that decision
//! under the package's contract. It may be `CONTRADICTED` or `UNDETERMINED`.
//!
//! No check establishes that a source told the truth, that a completeness
//! statement was honest, or that the package holds everything its sources
//! know. Asserted times are not authenticated either: the holder of a
//! revoked key can backdate a statement into the key's validity period.
//!
//! # Statements outside a package
//!
//! [`evidence`] authenticates single statements, verifies that a list of
//! them is a run of an issuer's stream, and admits them as the evidence of
//! a claim. Verifying a package does not verify chains: a package's
//! statements may carry chain links, and only their structure is checked.

mod container;
pub mod evidence;
mod inspect;
mod json;
mod order_transition;
mod report;
mod statement;
mod trust;
mod verify;
mod work_contract;

pub use container::{Options, ProtocolSelection, Refusal, Rejection};
pub use inspect::{Inspection, StatedClaim, StatementSummary, inspect};
pub use report::{
    ComponentCommitment, Condition, ContractSummary, DecisionFinding, Evaluation, Expectations,
    Finding, IssuerSignature, NotChecked, Report, Reproduced,
};
pub use trust::{Trust, TrustError};
pub use verified_contract::{Conflict, RequirementValue, Truth};
pub use verify::verify;
