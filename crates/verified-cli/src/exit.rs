// SPDX-License-Identifier: Apache-2.0

//! Exit codes. They are part of the command-line interface: scripts rely on
//! them, so they change only with a major version.

use std::process::ExitCode;

/// What a run concluded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Exit {
    /// Every check the protocol defines ran, and the package was not refused.
    /// A reproduced `CONTRADICTED` or `UNDETERMINED` decision also ends here.
    Complete = 0,
    /// The package failed a protocol check, or `fsck` found damage in the
    /// workspace. Also: a registration or a registry's log was refused, or a
    /// log contradicts an entry held against it.
    Refused = 1,
    /// The command could not run: bad usage, an unreadable file, or input
    /// beyond a resource limit. Nothing was concluded about the package.
    Failed = 2,
    /// The package was not refused, but not every check ran. Also: a
    /// registry's log does not reach an entry held against it.
    Incomplete = 3,
    /// Every check ran and the package was not refused, but the decision it
    /// reproduced is not the one `--require-decision` asked for, or it was
    /// reproduced under a `wvp-0.2` contract the caller did not pin.
    DecisionNotRequired = 4,
}

impl From<Exit> for ExitCode {
    fn from(exit: Exit) -> Self {
        Self::from(exit as u8)
    }
}
