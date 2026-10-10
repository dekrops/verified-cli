// SPDX-License-Identifier: Apache-2.0

//! The command line.

use std::path::PathBuf;

use clap::{Args as ClapArgs, Parser, Subcommand};
use verified_canonical::Sha256Digest;
use verified_protocol::ProtocolVersion;

const AFTER_HELP: &str = "\
Exit codes:
  0  every protocol check ran and the package was not refused; the decision
     it reproduced may still be CONTRADICTED or UNDETERMINED
  1  the package was refused; the refusal code is printed
  2  the command could not run (usage, unreadable file, unusable registry,
     resource limit)
  3  verify: the package was not refused, but not every check ran

The Work Verification Protocol is a draft. No check establishes that a
source told the truth.";

/// Git-like tools for verifiable work.
///
/// Check portable records of machine work offline, without trusting the
/// system that produced them. Everything runs locally: no account, no
/// server, no network.
#[derive(Debug, Parser)]
#[command(name = "verified", version, propagate_version = true, after_help = AFTER_HELP)]
pub(crate) struct Args {
    #[command(flatten)]
    pub(crate) global: Global,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, ClapArgs)]
#[allow(clippy::struct_excessive_bools, clippy::doc_markdown)] // switches; help text, not Markdown
pub(crate) struct Global {
    /// Print results as JSON, with full identifiers
    #[arg(long, global = true)]
    pub(crate) json: bool,
    /// Print nothing on standard output; rely on the exit code
    #[arg(long, short, global = true, conflicts_with_all = ["json", "verbose"])]
    pub(crate) quiet: bool,
    /// Print full identifiers and component digests
    #[arg(long, short, global = true)]
    pub(crate) verbose: bool,
    /// Never use color (also honored: the NO_COLOR environment variable)
    #[arg(long, global = true)]
    pub(crate) no_color: bool,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Check a Work Verification Protocol package offline
    ///
    /// Runs the protocol's checks in order and stops at the first that
    /// fails. Without --trust only package integrity can be established:
    /// the components are well formed and are the ones the package commits
    /// to. Signatures, signer authority and the decision need a trust
    /// registry, which is yours to supply; a key inside a package is never
    /// trusted.
    ///
    /// Exit code 0 means every check ran, not that the claim is supported:
    /// read the decision.
    Verify(Verify),
    /// Create a local workspace for inspecting packages
    ///
    /// A workspace is a `.verified` directory holding the packages you
    /// import. It is a cache for inspection and authoritative for nothing:
    /// not a ledger, and not a record of what anyone accepted.
    Init(Init),
    /// Store a package in the workspace, without accepting it
    ///
    /// The package must have integrity (its contents are the ones it
    /// commits to); otherwise nothing is stored. No signature is checked, no
    /// key is trusted and no decision is reproduced. A stored package is
    /// exactly as trustworthy as it was before.
    Import(Import),
    /// Show what a stored package says about itself
    ///
    /// Everything shown is stated by the package and, apart from its
    /// integrity, checked by nobody. To check it, run `verified verify`.
    Show(Show),
    /// List what this workspace imported, newest first
    ///
    /// This is the workspace's own note, by this machine's clock. It is
    /// local and unauthenticated: not a history of work, and not evidence
    /// of anything.
    Log(Log),
}

#[derive(Debug, ClapArgs)]
pub(crate) struct Init {
    /// Where to create the workspace (default: the current directory)
    pub(crate) directory: Option<PathBuf>,
}

#[derive(Debug, ClapArgs)]
pub(crate) struct Import {
    /// The package file, or `-` for standard input
    pub(crate) package: PathBuf,
}

#[derive(Debug, ClapArgs)]
pub(crate) struct Show {
    /// A package identifier (`wvp:sha-256:…`), an object identifier
    /// (`object:sha-256:…`), or at least 4 leading hexadecimal characters
    pub(crate) package: String,
}

#[derive(Debug, ClapArgs)]
pub(crate) struct Log {}

#[derive(Debug, ClapArgs)]
pub(crate) struct Verify {
    /// The package: a file, `-` for standard input, or the identifier of a
    /// package stored in the workspace (`wvp:sha-256:…`, `object:sha-256:…`)
    pub(crate) package: PathBuf,
    /// Your trust registry: a JSON file of the keys you accept
    #[arg(long, value_name = "REGISTRY")]
    pub(crate) trust: Option<PathBuf>,
    /// Require this protocol version instead of detecting it
    #[arg(long, value_name = "VERSION", value_parser = protocol)]
    pub(crate) protocol: Option<ProtocolVersion>,
    /// Refuse a package evaluated for another tenant (wvp-0.2)
    #[arg(long, value_name = "TENANT")]
    pub(crate) expect_tenant: Option<String>,
    /// Refuse a package about another contract, by digest (wvp-0.2)
    #[arg(long, value_name = "SHA-256", value_parser = digest)]
    pub(crate) expect_contract: Option<Sha256Digest>,
    /// Refuse a package carrying another claim, by identifier (wvp-0.2)
    #[arg(long, value_name = "CLAIM")]
    pub(crate) expect_claim: Option<String>,
}

/// A SHA-256 digest: 64 lowercase hexadecimal characters, optionally after
/// `sha-256:`.
fn digest(text: &str) -> Result<Sha256Digest, String> {
    text.strip_prefix("sha-256:")
        .unwrap_or(text)
        .parse()
        .map_err(|e: verified_canonical::DigestParseError| e.to_string())
}

fn protocol(identifier: &str) -> Result<ProtocolVersion, String> {
    identifier
        .parse()
        .map_err(|e: verified_protocol::UnknownProtocol| e.to_string())
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;

    #[test]
    fn the_command_line_is_well_formed() {
        super::Args::command().debug_assert();
    }
}
