// SPDX-License-Identifier: Apache-2.0

//! The object store: creating, finding, writing and reading stored packages.

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use verified_canonical::{Limits, Sha256Digest};
use verified_protocol::PackageId;
use verified_verifier::{Options, verify};

use crate::history::ImportRecord;
use crate::{
    DIRECTORY, Error, FORMAT, ImportError, Imported, ObjectId, ResolveError, Stored, Workspace,
};

pub(crate) const PACKAGES: &str = "packages";
pub(crate) const FORMAT_FILE: &str = "format";
pub(crate) const HISTORY_FILE: &str = "imports.log";
/// The shortest prefix of an identifier that may name a stored package.
const MIN_PREFIX: usize = 4;

pub(crate) fn io<T>(path: &Path, result: std::io::Result<T>) -> Result<T, Error> {
    result.map_err(|source| Error::Io {
        path: path.to_owned(),
        source,
    })
}

/// What is at a path, without following a symbolic link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Missing,
    File,
    Directory,
    /// A symbolic link, or something that is neither file nor directory.
    Other,
}

pub(crate) fn kind(path: &Path) -> Result<Kind, Error> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Ok(Kind::Other),
        Ok(metadata) if metadata.is_dir() => Ok(Kind::Directory),
        Ok(metadata) if metadata.is_file() => Ok(Kind::File),
        Ok(_) => Ok(Kind::Other),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Kind::Missing),
        Err(source) => Err(Error::Io {
            path: path.to_owned(),
            source,
        }),
    }
}

/// A directory that is really a directory, created if missing.
fn directory(path: &Path) -> Result<(), Error> {
    if kind(path)? == Kind::Missing {
        match std::fs::create_dir(path) {
            Err(error) if error.kind() != std::io::ErrorKind::AlreadyExists => {
                return io(path, Err(error));
            }
            _ => {}
        }
    }
    existing_directory(path)
}

fn existing_directory(path: &Path) -> Result<(), Error> {
    match kind(path)? {
        Kind::Directory => Ok(()),
        _ => Err(Error::Unsafe {
            path: path.to_owned(),
            what: "expected a directory and found a symbolic link or something else",
        }),
    }
}

fn is_hex(name: &str, len: usize) -> bool {
    name.len() == len && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Writes `bytes` to `path` so that the path holds either nothing or all of
/// them: a temporary file in the same directory, flushed, then renamed.
fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    let temporary = path.with_file_name(format!(".tmp-{}-{unique}", std::process::id()));
    let written = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    io(path, written)?;
    // Make the new name durable where the platform lets a directory be
    // synchronized. Failure here loses durability, not correctness.
    if let Some(parent) = path.parent()
        && let Ok(directory) = std::fs::File::open(parent)
    {
        let _ = directory.sync_all();
    }
    Ok(())
}

fn read_bounded(path: &Path, max_bytes: usize) -> Result<Option<Vec<u8>>, Error> {
    let file = io(path, std::fs::File::open(path))?;
    let cap = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::new();
    io(path, file.take(cap).read_to_end(&mut bytes))?;
    Ok((bytes.len() <= max_bytes).then_some(bytes))
}

impl Workspace {
    /// Creates a workspace in `parent`, or opens the one already there.
    /// Returns the workspace and whether it was created.
    pub fn init(parent: &Path) -> Result<(Self, bool), Error> {
        let dir = parent.join(DIRECTORY);
        if kind(&dir)? != Kind::Missing {
            return Self::open(&dir).map(|workspace| (workspace, false));
        }
        io(&dir, std::fs::create_dir(&dir))?;
        directory(&dir.join(PACKAGES))?;
        // The format file is written last: a directory without one is not
        // yet a workspace, and `open` says so.
        write_atomically(&dir.join(FORMAT_FILE), format!("{FORMAT}\n").as_bytes())?;
        Ok((Self { dir }, true))
    }

    /// Opens the workspace directory `dir` (`…/.verified`).
    pub fn open(dir: &Path) -> Result<Self, Error> {
        existing_directory(dir)?;
        let format = dir.join(FORMAT_FILE);
        let found = match kind(&format)? {
            Kind::File => read_bounded(&format, 256)?
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .unwrap_or_default(),
            Kind::Missing => String::new(),
            _ => {
                return Err(Error::Unsafe {
                    path: format,
                    what: "the format marker is not a regular file",
                });
            }
        };
        if found != format!("{FORMAT}\n") {
            return Err(Error::UnsupportedFormat {
                path: dir.to_owned(),
                found: found.trim_end().to_owned(),
            });
        }
        Ok(Self {
            dir: dir.to_owned(),
        })
    }

    /// Finds the workspace of `start`: in it, or in the nearest parent.
    pub fn discover(start: &Path) -> Result<Self, Error> {
        for ancestor in start.ancestors() {
            let candidate = ancestor.join(DIRECTORY);
            if kind(&candidate)? != Kind::Missing {
                return Self::open(&candidate);
            }
        }
        Err(Error::NotFound {
            start: start.to_owned(),
        })
    }

    fn package_directory(&self, package: &PackageId) -> (PathBuf, PathBuf) {
        let hex = package.commitment().to_hex();
        let fan_out = self.dir.join(PACKAGES).join(&hex[..2]);
        let directory = fan_out.join(&hex[2..]);
        (fan_out, directory)
    }

    fn object_path(&self, stored: &Stored) -> PathBuf {
        self.package_directory(&stored.package)
            .1
            .join(stored.object.digest().to_hex())
    }

    /// Stores a package, given as its exact canonical text.
    ///
    /// The package must establish integrity (protocol steps 1 to 7);
    /// otherwise nothing is stored. No signature is checked and no decision
    /// is reproduced: **importing is not accepting**, and a stored package
    /// is exactly as trustworthy as it was before.
    ///
    /// `imported_at_unix` is the caller's clock, recorded in the local
    /// import history and used for nothing else.
    pub fn import(
        &self,
        package: &[u8],
        imported_at_unix: u64,
        limits: &Limits,
    ) -> Result<Imported, ImportError> {
        let options = Options {
            limits: *limits,
            ..Options::default()
        };
        let report = verify(package, &options)?;
        let stored = Stored {
            package: report.package_id,
            object: ObjectId::of(package),
        };
        directory(&self.dir.join(PACKAGES))?;
        let (fan_out, package_directory) = self.package_directory(&stored.package);
        directory(&fan_out)?;
        directory(&package_directory)?;
        let path = self.object_path(&stored);
        let already_present = match kind(&path)? {
            Kind::Missing => {
                write_atomically(&path, package)?;
                false
            }
            // Objects are immutable. One that is already there must be this
            // one; anything else is damage, and is not overwritten.
            Kind::File => {
                if read_bounded(&path, limits.max_bytes)?.as_deref() != Some(package) {
                    return Err(Error::Corrupt { stored }.into());
                }
                true
            }
            _ => {
                return Err(Error::Unsafe {
                    path,
                    what: "a stored object is not a regular file",
                }
                .into());
            }
        };
        self.record(&ImportRecord {
            stored,
            protocol: report.protocol,
            imported_at_unix,
        })?;
        Ok(Imported {
            stored,
            protocol: report.protocol,
            already_present,
        })
    }

    /// Everything stored, in ascending order. Names this tool does not write
    /// are reported, not skipped; leftover temporary files are ignored.
    pub fn stored(&self) -> Result<Vec<Stored>, Error> {
        fn names(path: &Path) -> Result<Vec<String>, Error> {
            let mut names = Vec::new();
            for entry in io(path, std::fs::read_dir(path))? {
                let name = io(path, entry)?.file_name();
                let name = name
                    .to_str()
                    .map(str::to_owned)
                    .ok_or_else(|| Error::Unsafe {
                        path: path.to_owned(),
                        what: "holds a name this tool does not write",
                    })?;
                if !name.starts_with(".tmp-") {
                    names.push(name);
                }
            }
            names.sort();
            Ok(names)
        }
        let foreign = |path: PathBuf| Error::Unsafe {
            path,
            what: "is not something this tool writes",
        };
        let packages = self.dir.join(PACKAGES);
        existing_directory(&packages)?;
        let mut stored = Vec::new();
        for fan_out in names(&packages)? {
            let fan_out_path = packages.join(&fan_out);
            if !is_hex(&fan_out, 2) {
                return Err(foreign(fan_out_path));
            }
            existing_directory(&fan_out_path)?;
            for rest in names(&fan_out_path)? {
                let package_path = fan_out_path.join(&rest);
                let Ok(commitment) = format!("{fan_out}{rest}").parse::<Sha256Digest>() else {
                    return Err(foreign(package_path));
                };
                existing_directory(&package_path)?;
                for object in names(&package_path)? {
                    let Ok(digest) = object.parse::<Sha256Digest>() else {
                        return Err(foreign(package_path.join(&object)));
                    };
                    stored.push(Stored {
                        package: PackageId::from_commitment(commitment),
                        object: ObjectId(digest),
                    });
                }
            }
        }
        Ok(stored)
    }

    /// Finds the one stored package a name selects.
    ///
    /// A name is a package identifier (`wvp:sha-256:…`), an object
    /// identifier (`object:sha-256:…`), or at least four leading hexadecimal
    /// characters of either digest; bare hexadecimal names a package.
    pub fn resolve(&self, spec: &str) -> Result<Stored, ResolveError> {
        let (by_object, hex) = match spec.strip_prefix(ObjectId::PREFIX) {
            Some(hex) => (true, hex),
            None => (false, spec.strip_prefix(PackageId::PREFIX).unwrap_or(spec)),
        };
        let is_prefix = (MIN_PREFIX..=64).contains(&hex.len()) && is_hex(hex, hex.len());
        if !is_prefix {
            return Err(ResolveError::Invalid(spec.to_owned()));
        }
        let digest = |stored: &Stored| {
            if by_object {
                stored.object.digest().to_hex()
            } else {
                stored.package.commitment().to_hex()
            }
        };
        let matches: Vec<Stored> = self
            .stored()?
            .into_iter()
            .filter(|stored| digest(stored).starts_with(hex))
            .collect();
        let mut packages: Vec<PackageId> = matches.iter().map(|s| s.package).collect();
        packages.dedup();
        match (matches.as_slice(), packages.as_slice()) {
            ([], _) => Err(ResolveError::NotFound(spec.to_owned())),
            ([one], _) => Ok(*one),
            (several, [package]) => Err(ResolveError::Variants {
                package: *package,
                objects: several.iter().map(|s| s.object).collect(),
            }),
            _ => Err(ResolveError::Ambiguous {
                spec: spec.to_owned(),
                packages,
            }),
        }
    }

    /// Reads a stored package and checks it against both of its names: the
    /// bytes hash to the object identifier, and they are a package with the
    /// package identifier. A mismatch is damage, and nothing is returned.
    pub fn read(&self, stored: &Stored, limits: &Limits) -> Result<Vec<u8>, Error> {
        let (fan_out, package_directory) = self.package_directory(&stored.package);
        existing_directory(&self.dir.join(PACKAGES))?;
        existing_directory(&fan_out)?;
        existing_directory(&package_directory)?;
        let path = self.object_path(stored);
        if kind(&path)? != Kind::File {
            return Err(Error::Unsafe {
                path,
                what: "a stored object is not a regular file",
            });
        }
        let Some(bytes) = read_bounded(&path, limits.max_bytes)? else {
            return Err(Error::TooLarge {
                object: stored.object,
            });
        };
        let options = Options {
            limits: *limits,
            ..Options::default()
        };
        let intact = ObjectId::of(&bytes) == stored.object
            && verify(&bytes, &options).is_ok_and(|report| report.package_id == stored.package);
        if intact {
            Ok(bytes)
        } else {
            Err(Error::Corrupt { stored: *stored })
        }
    }
}
