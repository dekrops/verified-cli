// SPDX-License-Identifier: Apache-2.0

//! Typed representations of Work Verification Protocol (WVP) structures.
//!
//! WVP is a **draft** protocol. This crate models what a verifier reads:
//! protocol versions, the package container, component paths, package
//! identifiers and refusal codes. It holds no storage, I/O or user-interface
//! code, and makes no decision about whether a package is acceptable: the
//! order of checks belongs to `verified-verifier`.
//!
//! Reading a structure checks its shape and nothing else. Whether a digest
//! matches, a signature verifies or a key is trusted are separate checks with
//! their own refusal codes.
//!
//! `wvp-0.1` and `wvp-0.2` have different components and different
//! semantics. They live in separate modules ([`v01`], [`v02`]) and nothing
//! converts between them.

mod component;
mod container;
mod decision;
mod evidence;
mod inputs;
mod refusal;
pub mod registration;
mod registry;
pub mod relation;
mod shape;
mod statement;
mod time;
pub mod v01;
pub mod v02;
mod version;

pub use component::ComponentPath;
pub use container::{
    Component, Container, DeclaredVersion, IssuerSignature, ManifestEntry, PackageId,
    PackageIdParseError, ShapeError, ShapeProblem, WireDigest,
};
pub use decision::{DECISION_SOURCE, Decision, Evaluator, RecordedDecision};
pub use evidence::Evidence;
pub use inputs::Inputs;
pub use refusal::RefusalCode;
pub use registry::{RegistryError, TrustRegistry, TrustedKey};
pub use statement::{
    ChainLink, EVIDENCE_KINDS, STATEMENT_DOMAIN, STATEMENT_PROTOCOL, SignedStatement,
};
pub use time::Instant;
pub use version::{PACKAGE_VERSION, ProtocolVersion, UnknownProtocol};
