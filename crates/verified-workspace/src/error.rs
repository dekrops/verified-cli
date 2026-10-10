// SPDX-License-Identifier: Apache-2.0

//! What can go wrong with a workspace.

use std::path::PathBuf;

use verified_protocol::PackageId;
use verified_verifier::Rejection;

use crate::{ObjectId, Stored};

/// A workspace that cannot be used as asked.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The file system refused.
    #[error("{}: {source}", path.display())]
    Io {
        /// What was being read or written.
        path: PathBuf,
        /// Why it failed.
        source: std::io::Error,
    },
    /// No workspace here or in any parent directory.
    #[error("not in a Verified workspace (no {} in {} or its parents); run `verified init`", crate::DIRECTORY, start.display())]
    NotFound {
        /// Where the search started.
        start: PathBuf,
    },
    /// The directory is a workspace of a layout this version does not know.
    #[error("{}: workspace format {found:?} is not supported (this version reads {})", path.display(), crate::FORMAT)]
    UnsupportedFormat {
        /// The workspace directory.
        path: PathBuf,
        /// What its `format` file says.
        found: String,
    },
    /// Something in the workspace is not what this tool writes: a symbolic
    /// link, or a file where a directory belongs. Nothing is followed.
    #[error("{}: {what}; refusing to use it", path.display())]
    Unsafe {
        /// The offending path.
        path: PathBuf,
        /// What is wrong with it.
        what: &'static str,
    },
    /// A stored object is not the content its names commit to.
    #[error("{} is damaged: its content does not match its name (stored under {})", stored.object, stored.package)]
    Corrupt {
        /// The object.
        stored: Stored,
    },
    /// The import history is larger than this version reads. It was not
    /// read, so nothing is known about what it records.
    #[error("{}: the import history is larger than this version reads ({limit} bytes)", path.display())]
    HistoryTooLarge {
        /// The history file.
        path: PathBuf,
        /// The largest history that is read.
        limit: u64,
    },
    /// A stored object is larger than the reader's limit.
    #[error("{object} exceeds the size limit and was not read")]
    TooLarge {
        /// The object.
        object: ObjectId,
    },
}

/// An import that stored nothing.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    /// The package does not establish integrity, so it has no valid
    /// identifier to store it under.
    #[error("not imported: {0}")]
    Rejected(#[from] Rejection),
    /// The workspace could not be written.
    #[error(transparent)]
    Workspace(#[from] Error),
}

/// A name that does not select exactly one stored package.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// The text is not an identifier or a prefix of one.
    #[error(
        "{0:?} is not a package or object identifier, or at least 4 hexadecimal characters of one"
    )]
    Invalid(String),
    /// Nothing stored matches.
    #[error("no stored package matches {0:?}")]
    NotFound(String),
    /// Several packages match the prefix.
    #[error("{spec:?} is ambiguous: it matches {} packages", packages.len())]
    Ambiguous {
        /// What was asked for.
        spec: String,
        /// The packages it matches.
        packages: Vec<PackageId>,
    },
    /// One package is stored in several texts, which differ outside what the
    /// package identifier commits to (issuer signatures).
    #[error("{package} is stored in {} texts that differ in their issuer signatures; name one by its object identifier", objects.len())]
    Variants {
        /// The package.
        package: PackageId,
        /// Its stored texts.
        objects: Vec<ObjectId>,
    },
    /// The workspace could not be read.
    #[error(transparent)]
    Workspace(#[from] Error),
}
