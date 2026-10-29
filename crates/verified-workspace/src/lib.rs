// SPDX-License-Identifier: Apache-2.0

//! A local workspace: a cache of imported Work Verification Protocol (WVP)
//! packages, for inspection.
//!
//! A workspace is **authoritative for nothing**. It is not a ledger and not a
//! record of what anyone accepted:
//!
//! - Importing a package checks that its contents are the ones it commits to
//!   (package integrity) and stores its bytes. It checks no signature, trusts
//!   no key and reproduces no decision. Importing is not accepting.
//! - The import history is this machine's note of what it stored and when, by
//!   its own clock. Nothing signs it and nothing should rely on it.
//!
//! # Layout
//!
//! ```text
//! .verified/
//!   format                                   "verified-workspace-1"
//!   packages/<aa>/<62 hex>/<64 hex>          one stored package
//!   imports.log                              one import record per line
//! ```
//!
//! A stored package is the exact canonical text that was imported. Its
//! directory is named by the protocol's own package identifier and its file
//! by the SHA-256 of its bytes. Both are needed: the package identifier
//! commits to the manifest and through it to every component, but not to the
//! `signatures` member, so two different texts (with and without an issuer's
//! signature, say) can share one identifier.
//!
//! Every path is built from validated hexadecimal digests. No name from a
//! package reaches the file system. Symbolic links inside a workspace are
//! refused, objects are written atomically and never modified, and every
//! object is checked against both of its names each time it is read.

mod check;
mod error;
mod history;
mod store;

use std::fmt;
use std::path::{Path, PathBuf};

use verified_canonical::Sha256Digest;
use verified_protocol::{PackageId, ProtocolVersion};

pub use check::{Check, Problem};
pub use error::{Error, ImportError, ResolveError};
pub use history::{History, ImportRecord};
pub use store::process_tag;

/// The name of a workspace directory.
pub const DIRECTORY: &str = ".verified";

/// The identifier of the layout this crate reads and writes.
pub const FORMAT: &str = "verified-workspace-1";

/// The SHA-256 of a stored package's exact bytes.
///
/// It is written `object:sha-256:<hex>` so that it cannot be mistaken for a
/// protocol commitment: it is a name this workspace gives a file, and means
/// nothing outside one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectId(Sha256Digest);

impl ObjectId {
    /// What every object identifier starts with.
    pub const PREFIX: &'static str = "object:sha-256:";

    /// The identifier of these bytes.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256Digest::of(bytes))
    }

    /// The digest.
    #[must_use]
    pub const fn digest(&self) -> &Sha256Digest {
        &self.0
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", Self::PREFIX, self.0)
    }
}

/// One stored package: which package it is, and which exact text of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Stored {
    /// The protocol's identifier of the package.
    pub package: PackageId,
    /// The identifier of the stored bytes.
    pub object: ObjectId,
}

/// What an import did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Imported {
    /// What is now stored.
    pub stored: Stored,
    /// The protocol version the package declares.
    pub protocol: ProtocolVersion,
    /// Whether these exact bytes were stored already.
    pub already_present: bool,
}

/// An open workspace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Workspace {
    dir: PathBuf,
}

impl Workspace {
    /// The workspace directory itself (`…/.verified`).
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.dir
    }
}
