//! The command line.

use std::path::PathBuf;

use clap::{Args as ClapArgs, Parser, Subcommand};
use verified_protocol::ProtocolVersion;

const AFTER_HELP: &str = "\
Exit codes:
  0  every protocol check ran and the package was not refused
  1  the package was refused; the refusal code is printed
  2  the command could not run (usage, unreadable file, resource limit)
  3  the package was not refused, but not every check ran

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
    /// This version runs the container checks (protocol steps 1 to 6):
    /// canonical text, versions, container shape, component set, component
    /// digests and the package commitment. It does not yet check component
    /// shapes, signatures, signer authority or the decision, and says so in
    /// its report; it therefore never exits 0.
    Verify(Verify),
}

#[derive(Debug, ClapArgs)]
pub(crate) struct Verify {
    /// The package file, or `-` for standard input
    pub(crate) package: PathBuf,
    /// Require this protocol version instead of detecting it
    #[arg(long, value_name = "VERSION", value_parser = protocol)]
    pub(crate) protocol: Option<ProtocolVersion>,
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
