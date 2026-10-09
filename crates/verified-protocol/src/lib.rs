//! Typed representations of Work Verification Protocol (WVP) structures.
//!
//! WVP is a **draft** protocol. This crate models what a verifier reads:
//! protocol versions, the package container, component paths, package
//! identifiers and refusal codes. It holds no storage, I/O or user-interface
//! code, and makes no decision about whether a package is acceptable: the
//! order of checks belongs to `verified-verifier`.
//!
//! This version covers the package container shared by `wvp-0.1` and
//! `wvp-0.2`. Component contents (claims, contracts, statements, decisions)
//! and trust registries are not modeled yet.

mod component;
mod container;
mod refusal;
mod version;

pub use component::ComponentPath;
pub use container::{
    Component, Container, DeclaredVersion, IssuerSignature, ManifestEntry, PackageId, ShapeError,
    ShapeProblem, WireDigest,
};
pub use refusal::RefusalCode;
pub use version::{PACKAGE_VERSION, ProtocolVersion, UnknownProtocol};
