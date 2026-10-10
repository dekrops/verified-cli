// SPDX-License-Identifier: Apache-2.0

//! The import history: this machine's own note of what it stored, and when.
//!
//! It is local and unauthenticated. It is not an authenticated history of
//! work, and is never presented as one.

use std::io::Write as _;

use verified_canonical::{Integer, Limits, Object, Value, parse_canonical};
use verified_protocol::ProtocolVersion;

use crate::store::{Kind, io, kind};
use crate::{Error, ObjectId, Stored, Workspace};

/// The identifier of the record encoding. A record is a workspace's own
/// object, in its own versioned encoding; it is not a protocol structure.
const RECORD: &str = "verified-import-1";
use crate::store::HISTORY_FILE as FILE;
/// The history is read whole. Beyond this it is not read at all.
const MAX_BYTES: u64 = 64 * 1024 * 1024;

/// One import, as this machine recorded it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImportRecord {
    /// What was stored.
    pub stored: Stored,
    /// The protocol version the package declares.
    pub protocol: ProtocolVersion,
    /// When, in seconds since 1970-01-01T00:00:00Z by this machine's clock at
    /// the time. Not authenticated by anything.
    pub imported_at_unix: u64,
}

/// The import history of a workspace.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct History {
    /// The records, oldest first.
    pub records: Vec<ImportRecord>,
    /// How many lines of the history could not be read as records. They are
    /// counted, never guessed at.
    pub damaged: usize,
}

fn text(s: String) -> Value {
    Value::String(s)
}

impl ImportRecord {
    fn line(&self) -> String {
        let seconds = i64::try_from(self.imported_at_unix).unwrap_or(i64::MAX);
        let record: Object = [
            ("record", text(RECORD.to_owned())),
            ("importedAtUnix", Value::Integer(Integer::from(seconds))),
            ("package", text(self.stored.package.to_string())),
            ("object", text(self.stored.object.digest().to_hex())),
            ("protocol", text(self.protocol.identifier().to_owned())),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect();
        let mut line = Value::Object(record).to_canonical_string();
        line.push('\n');
        line
    }

    fn read(line: &[u8]) -> Option<Self> {
        let value = parse_canonical(line, &Limits::DEFAULT).ok()?;
        let record = value.as_object()?;
        let member = |name| record.get(name).and_then(Value::as_str);
        let exact =
            record.has_exactly(&["importedAtUnix", "object", "package", "protocol", "record"]);
        if !exact || member("record") != Some(RECORD) {
            return None;
        }
        let seconds = record.get("importedAtUnix")?.as_integer()?.to_i64()?;
        Some(Self {
            stored: Stored {
                package: member("package")?.parse().ok()?,
                object: ObjectId(member("object")?.parse().ok()?),
            },
            protocol: member("protocol")?.parse().ok()?,
            imported_at_unix: u64::try_from(seconds).ok()?,
        })
    }
}

impl Workspace {
    /// Reads the import history.
    pub fn history(&self) -> Result<History, Error> {
        let path = self.dir.join(FILE);
        match kind(&path)? {
            Kind::Missing => return Ok(History::default()),
            Kind::File => {}
            _ => {
                return Err(Error::Unsafe {
                    path,
                    what: "the import history is not a regular file",
                });
            }
        }
        let size = io(&path, std::fs::metadata(&path))?.len();
        if size > MAX_BYTES {
            return Err(Error::Unsafe {
                path,
                what: "the import history is larger than this version reads",
            });
        }
        let bytes = io(&path, std::fs::read(&path))?;
        let mut history = History::default();
        for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
            match ImportRecord::read(line) {
                Some(record) => history.records.push(record),
                None => history.damaged += 1,
            }
        }
        Ok(history)
    }

    /// Appends one record. A record is one short line written in one call,
    /// so an interrupted write leaves at most a damaged last line, which
    /// [`Workspace::history`] counts and skips.
    pub(crate) fn record(&self, record: &ImportRecord) -> Result<(), Error> {
        let path = self.dir.join(FILE);
        if !matches!(kind(&path)?, Kind::Missing | Kind::File) {
            return Err(Error::Unsafe {
                path,
                what: "the import history is not a regular file",
            });
        }
        let file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&path);
        let mut file = io(&path, file)?;
        io(&path, file.write_all(record.line().as_bytes()))?;
        io(&path, file.sync_data())
    }
}
