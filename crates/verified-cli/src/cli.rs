// SPDX-License-Identifier: Apache-2.0

//! The command line.

use std::path::PathBuf;

use clap::{Args as ClapArgs, Parser, Subcommand};
use verified_canonical::Sha256Digest;
use verified_protocol::{Decision, ProtocolVersion};

const AFTER_HELP: &str = "\
Exit codes:
  0  every protocol check ran and the package was not refused; the decision
     it reproduced may still be CONTRADICTED or UNDETERMINED, unless
     --require-decision was given
  1  the package was refused; the refusal code is printed
     fsck: damage was found in the workspace
     diff: the two packages differ
     replay: a package was refused or is damaged
  2  the command could not run (usage, unreadable file, unusable registry,
     resource limit)
  3  verify: the package was not refused, but not every check ran
  4  --require-decision: every check ran, but a reproduced decision is not
     the required one

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
    /// read the decision, or give --require-decision SUPPORTED so that any
    /// other outcome is a non-zero exit code.
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
    /// Show how the parts of one stored package relate
    ///
    /// The claim, the contract it names, the evidence it relies on, who is
    /// said to have signed each statement, and the decision. Only what the
    /// package itself contains is shown: a package links to no other package
    /// and carries no acceptance or ledger history, so none is drawn.
    ///
    /// Without --trust every link is the package's own statement. With it,
    /// the package is verified first and the links are the checked ones.
    Trace(Trace),
    /// Check every stored package and the import history
    ///
    /// Reads each stored package and checks it against its names, compares
    /// the import history with what is stored, and reports anything in the
    /// workspace this tool did not write. Nothing is repaired or changed.
    /// Exits 1 if damage is found.
    Fsck(Fsck),
    /// Write a stored package out, byte for byte
    ///
    /// The output is exactly the text that was imported. Nothing is added:
    /// no signature, no verification result, no claim of this tool's own.
    /// Whoever receives it verifies it as they would the original.
    Export(Export),
    /// Compare two packages
    ///
    /// Shows which components differ and what the two packages state
    /// differently. Both must have integrity; nothing else is checked, so
    /// every difference shown is between what two packages say. Exits 0 if
    /// the two texts are identical, 1 if they differ.
    Diff(Diff),
    /// Verify stored packages again, now, under your registry
    ///
    /// Nothing from an earlier run is reused: every result is computed in
    /// this run, under the registry given to this run. Without package
    /// names, every stored package is verified. Exits 1 if any package is
    /// refused or damaged.
    Replay(Replay),
}

#[derive(Debug, ClapArgs)]
pub(crate) struct Export {
    /// A package identifier, an object identifier, or a prefix of one
    pub(crate) package: String,
    /// Write to this file, which must not exist (default: standard output)
    #[arg(long, short, value_name = "FILE")]
    pub(crate) output: Option<PathBuf>,
}

#[derive(Debug, ClapArgs)]
pub(crate) struct Diff {
    /// The first package: a file, or the identifier of a stored package
    pub(crate) a: String,
    /// The second package
    pub(crate) b: String,
}

#[derive(Debug, ClapArgs)]
pub(crate) struct Replay {
    /// Your trust registry
    #[arg(long, value_name = "REGISTRY")]
    pub(crate) trust: PathBuf,
    /// Exit 4 unless every package reproduces this decision
    #[arg(long, value_name = "DECISION", value_parser = decision)]
    pub(crate) require_decision: Option<Decision>,
    /// The packages to verify (default: every stored package)
    pub(crate) packages: Vec<String>,
}

#[derive(Debug, ClapArgs)]
pub(crate) struct Trace {
    /// A package identifier (`wvp:sha-256:…`), an object identifier
    /// (`object:sha-256:…`), or at least 4 leading hexadecimal characters
    pub(crate) package: String,
    /// Your trust registry: verify the package before tracing it
    #[arg(long, value_name = "REGISTRY")]
    pub(crate) trust: Option<PathBuf>,
}

#[derive(Debug, ClapArgs)]
pub(crate) struct Fsck {}

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
    /// Exit 0 only if this decision was reproduced: SUPPORTED, CONTRADICTED
    /// or UNDETERMINED. Another reproduced decision exits 4
    #[arg(long, value_name = "DECISION", value_parser = decision)]
    pub(crate) require_decision: Option<Decision>,
    /// A work record you hold, as a JSON file: refuse a package the record
    /// is not about (wvp-0.2)
    #[arg(long, value_name = "RECORD")]
    pub(crate) record: Option<PathBuf>,
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

fn decision(name: &str) -> Result<Decision, String> {
    name.parse().map_err(|()| {
        format!("unknown decision {name:?}; one of SUPPORTED, CONTRADICTED, UNDETERMINED")
    })
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
