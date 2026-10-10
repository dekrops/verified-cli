// SPDX-License-Identifier: Apache-2.0

//! Reading input files, bounded.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::Context as _;
use verified_canonical::LimitExceeded;

/// Why input could not be read.
#[derive(Debug)]
pub(crate) enum InputError {
    /// The file could not be opened or read.
    Io(anyhow::Error),
    /// The file is larger than the limit. It was not read to the end.
    TooLarge(LimitExceeded),
}

/// Reads `path` (or standard input for `-`), refusing more than `max_bytes`.
///
/// The bound is enforced while reading, so an oversized or endless input is
/// never held in memory.
pub(crate) fn read(path: &Path, max_bytes: usize) -> Result<Vec<u8>, InputError> {
    let name = path.display();
    let mut bytes = Vec::new();
    let cap = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let read = if path == Path::new("-") {
        std::io::stdin()
            .lock()
            .take(cap)
            .read_to_end(&mut bytes)
            .context("cannot read standard input")
    } else {
        File::open(path)
            .with_context(|| format!("cannot open {name}"))
            .and_then(|file| {
                file.take(cap)
                    .read_to_end(&mut bytes)
                    .with_context(|| format!("cannot read {name}"))
            })
    };
    read.map_err(InputError::Io)?;
    if bytes.len() > max_bytes {
        return Err(InputError::TooLarge(LimitExceeded::Bytes {
            limit: max_bytes,
        }));
    }
    Ok(bytes)
}
