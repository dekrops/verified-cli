// SPDX-License-Identifier: Apache-2.0

//! Checking a whole workspace: every object against its names, the history
//! against the objects, and everything else for not belonging.

use std::path::{Path, PathBuf};

use verified_canonical::{Limits, Sha256Digest};
use verified_protocol::PackageId;

use crate::history::ImportRecord;
use crate::store::{FORMAT_FILE, HISTORY_FILE, Kind, PACKAGES, io, kind};
use crate::{Error, ObjectId, Stored, Workspace};

/// Something a check found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Problem {
    /// A stored object is not the content its names commit to, or cannot be
    /// read.
    Damaged {
        /// The object.
        stored: Stored,
        /// What reading it reported.
        detail: String,
    },
    /// Something in the workspace that this tool does not write: a foreign
    /// file, a symbolic link, or a file where a directory belongs. Paths are
    /// relative to the workspace directory.
    Foreign {
        /// Where.
        path: PathBuf,
    },
    /// Lines of the import history that cannot be read as records.
    DamagedHistory {
        /// How many.
        lines: usize,
    },
    /// The history records an import of something that is not stored.
    MissingObject {
        /// The record.
        record: ImportRecord,
    },
    /// A temporary file left by an interrupted import. It is never read as
    /// an object.
    Leftover {
        /// Where, relative to the workspace directory.
        path: PathBuf,
    },
    /// An object no history record mentions: an import was interrupted after
    /// storing it and before recording it.
    Unrecorded {
        /// The object.
        stored: Stored,
    },
}

impl Problem {
    /// Whether this is damage, as opposed to the harmless trace of an
    /// interrupted import.
    #[must_use]
    pub const fn is_damage(&self) -> bool {
        !matches!(self, Self::Leftover { .. } | Self::Unrecorded { .. })
    }
}

/// The result of checking a workspace. Checking changes nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Check {
    /// How many stored objects were read and checked.
    pub objects: usize,
    /// How many history records were read.
    pub records: usize,
    /// Everything found, damage first.
    pub problems: Vec<Problem>,
}

impl Check {
    /// Whether any damage was found.
    #[must_use]
    pub fn has_damage(&self) -> bool {
        self.problems.iter().any(Problem::is_damage)
    }
}

/// The entries of a directory, sorted, with what each is.
fn entries(path: &Path) -> Result<Vec<(String, Kind)>, Error> {
    let mut entries = Vec::new();
    for entry in io(path, std::fs::read_dir(path))? {
        let entry = io(path, entry)?;
        // A name that is not Unicode is not one this tool writes; show it
        // as closely as it can be shown.
        let name = entry.file_name().to_string_lossy().into_owned();
        entries.push((name, kind(&entry.path())?));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(entries)
}

fn is_hex(name: &str, len: usize) -> bool {
    name.len() == len && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl Workspace {
    /// Walks the store, sorting what it finds into objects and problems.
    /// Unlike [`Workspace::stored`], it does not stop at the first thing
    /// that does not belong.
    fn scan(&self, problems: &mut Vec<Problem>) -> Result<Vec<Stored>, Error> {
        let mut stored = Vec::new();
        let mut note = |relative: &Path, name: &str| {
            let path = relative.join(name);
            problems.push(if name.starts_with(".tmp-") {
                Problem::Leftover { path }
            } else {
                Problem::Foreign { path }
            });
        };
        let root = Path::new("");
        for (name, kind) in entries(&self.dir)? {
            let expected = match name.as_str() {
                PACKAGES => Kind::Directory,
                FORMAT_FILE | HISTORY_FILE => Kind::File,
                _ => Kind::Missing,
            };
            if kind != expected {
                note(root, &name);
            }
        }
        let packages = Path::new(PACKAGES);
        if kind(&self.dir.join(packages))? != Kind::Directory {
            return Ok(stored);
        }
        for (fan_out, kind) in entries(&self.dir.join(packages))? {
            if kind != Kind::Directory || !is_hex(&fan_out, 2) {
                note(packages, &fan_out);
                continue;
            }
            let fan_out_path = packages.join(&fan_out);
            for (rest, kind) in entries(&self.dir.join(&fan_out_path))? {
                let commitment = format!("{fan_out}{rest}").parse::<Sha256Digest>();
                let (Kind::Directory, Ok(commitment)) = (kind, commitment) else {
                    note(&fan_out_path, &rest);
                    continue;
                };
                let package_path = fan_out_path.join(&rest);
                for (object, kind) in entries(&self.dir.join(&package_path))? {
                    match (kind, object.parse::<Sha256Digest>()) {
                        (Kind::File, Ok(digest)) => stored.push(Stored {
                            package: PackageId::from_commitment(commitment),
                            object: ObjectId(digest),
                        }),
                        _ => note(&package_path, &object),
                    }
                }
            }
        }
        Ok(stored)
    }

    /// Checks the whole workspace and changes nothing.
    ///
    /// Every stored object is read and checked against both of its names;
    /// the import history is read and compared with what is stored; anything
    /// this tool does not write is reported. An `Err` means the check itself
    /// could not be carried out.
    pub fn check(&self, limits: &Limits) -> Result<Check, Error> {
        let mut problems = Vec::new();
        let stored = self.scan(&mut problems)?;
        for object in &stored {
            match self.read(object, limits) {
                Ok(_) => {}
                Err(error @ Error::Io { .. }) => return Err(error),
                Err(error) => problems.push(Problem::Damaged {
                    stored: *object,
                    detail: error.to_string(),
                }),
            }
        }
        // A history that is not a regular file was reported by the scan.
        let history = match self.history() {
            Ok(history) => history,
            Err(Error::Unsafe { .. }) => crate::History::default(),
            Err(error) => return Err(error),
        };
        if history.damaged > 0 {
            problems.push(Problem::DamagedHistory {
                lines: history.damaged,
            });
        }
        // One finding per missing object, however often it was imported.
        let mut missing: Vec<ImportRecord> = Vec::new();
        for record in &history.records {
            let known = stored.contains(&record.stored)
                || missing
                    .iter()
                    .any(|earlier| earlier.stored == record.stored);
            if !known {
                missing.push(*record);
            }
        }
        problems.extend(
            missing
                .into_iter()
                .map(|record| Problem::MissingObject { record }),
        );
        let unrecorded = stored.iter().filter(|object| {
            !history
                .records
                .iter()
                .any(|record| record.stored == **object)
        });
        problems.extend(unrecorded.map(|object| Problem::Unrecorded { stored: *object }));

        problems.sort_by_key(|problem| !problem.is_damage());
        Ok(Check {
            objects: stored.len(),
            records: history.records.len(),
            problems,
        })
    }
}
