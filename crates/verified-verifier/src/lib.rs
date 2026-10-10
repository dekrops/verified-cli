//! Pure offline verification of Work Verification Protocol (WVP) packages.
//!
//! WVP is a **draft** protocol. [`verify`] takes the bytes of a package and
//! returns either a [`Report`] of what was established or a [`Rejection`].
//! It reads no file, opens no socket and consults no clock.
//!
//! # What this version checks
//!
//! The container checks shared by `wvp-0.1` and `wvp-0.2`, in protocol order:
//!
//! 1. the text is the canonical encoding of a JSON value (`NOT_CANONICAL`);
//! 2. the package, protocol and canonical-encoding versions are supported
//!    (`UNSUPPORTED_VERSION`);
//! 3. the package has exactly the container's members (`MALFORMED_COMPONENT`);
//! 4. the components are exactly the protocol's six, in order
//!    (`COMPONENT_SET`);
//! 5. every component's digest is the one its manifest entry states
//!    (`COMPONENT_DIGEST`);
//! 6. the package commitment and identifier follow from the manifest
//!    (`COMMITMENT_MISMATCH`).
//!
//! # What it does not check
//!
//! Step 7 (every component well formed at every depth) and everything that
//! needs a trust registry: evidence signatures, signer authority, contract
//! evaluation, decision reproduction and issuer signatures. A [`Report`]
//! says so property by property, and **package integrity is not established**
//! until step 7 exists. There is deliberately no single "valid" flag.
//!
//! No check, in any version, establishes that a source told the truth.

mod container;
mod report;

pub use container::{Options, ProtocolSelection, Refusal, Rejection, verify};
pub use report::{ComponentCommitment, Finding, NotChecked, Report};
