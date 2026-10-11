// SPDX-License-Identifier: Apache-2.0

//! The command line.

use std::path::PathBuf;

use clap::{Args as ClapArgs, Parser, Subcommand};
use verified_canonical::Sha256Digest;
use verified_protocol::{Decision, ProtocolVersion};

/// The top of `verified --help`: name and version, then what it is.
const HELP_TEMPLATE: &str = "\
{name} {version}
{about-with-newline}
{usage-heading} {usage}

{all-args}{after-help}";

const AFTER_HELP: &str = "\
Start here:
  verified verify package.json --trust registry.json
  verified --json verify package.json --trust registry.json
  verified init && verified import package.json && verified log

Exit codes:
  0  every protocol check ran and the package was not refused; the decision
     it reproduced may still be CONTRADICTED or UNDETERMINED, unless
     --require-decision was given
  1  the package was refused; the refusal code is printed
     fsck: damage was found in the workspace
     diff: the two packages differ
     replay: a package was refused or is damaged
     registration: the registration, the log, the audit or the unit check
     was refused, or the log contradicts the entry you hold
     evidence chain: the statements are refused, or are not one run
     trust show: the registry cannot be used
     issue, sign: a verifier would refuse the package; nothing is written
     evidence sign: the statement would be refused; nothing is written
  2  the command could not run (usage, unreadable file, unusable registry,
     resource limit)
  3  verify: the package was not refused, but not every check ran
     registration log: the log does not reach the entry you hold
  4  --require-decision: every check ran, but a reproduced decision is not
     the required one

The Work Verification Protocol is a draft. No check establishes that a
source told the truth.

Documentation, source and issues: https://github.com/dekrops/verified-cli";

/// Git-like tools for verifiable work.
///
/// Check portable records of machine work offline, without trusting the
/// system that produced them. Everything runs locally: no account, no
/// server, no network.
#[derive(Debug, Parser)]
#[command(
    name = "verified",
    version,
    propagate_version = true,
    help_template = HELP_TEMPLATE,
    after_help = AFTER_HELP
)]
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
    /// Check a claim registration, or a registry's log (draft protocol)
    ///
    /// Claim registration v1 is a draft, separate from the Work Verification
    /// Protocol: a claim is registered at a registry two parties agreed on,
    /// before any evidence is asked for.
    #[command(subcommand)]
    Registration(Registration),
    /// Check evidence statements held outside a package (draft protocol)
    #[command(subcommand)]
    Evidence(Evidence),
    /// Write and check the trust registry that --trust reads
    ///
    /// A registry is the list of keys you accept: for each, whose it is,
    /// which tenant, which source systems it may speak for, and when it is
    /// valid. It is yours, never a package's. Every change is checked as
    /// `verify` reads a registry, so a registry written here is one `verify`
    /// accepts.
    #[command(subcommand)]
    Trust(TrustCommand),
    /// Issue a package: evaluate a contract against signed evidence
    ///
    /// The draft is a JSON file: the contract, the claim, the signed
    /// evidence with its bodies, and the times. The decision is computed,
    /// never taken from the draft, and the package is written only if a
    /// verifier holding your registry reproduces it. Issuing is not
    /// verifying: a recipient checks the package under their own registry.
    Issue(Issue),
    /// Sign a package's decision as its issuer
    ///
    /// With --key, signs with a PEM private key (what `openssl genpkey
    /// -algorithm ed25519` writes); it is never printed. To keep the key
    /// elsewhere, write the bytes to sign with --signing-input-out, sign
    /// them there, and give the signature with --signature-file. The signed
    /// package is written only if the signature counts under your registry.
    Sign(Sign),
}

#[derive(Debug, Subcommand)]
pub(crate) enum TrustCommand {
    /// Create an empty registry
    ///
    /// Refuses to overwrite an existing file.
    Init(TrustInit),
    /// Add a key you accept
    ///
    /// The key is trusted for one issuer and one tenant, only for the
    /// source systems listed, from --valid-from. A key that may sign
    /// decisions as an issuer lists the source `wvp-decision`. Give the key
    /// as a PEM public key file (what `openssl pkey -pubout` writes) or as
    /// the registry's base64 form.
    Add(TrustAdd),
    /// Record that a key was revoked
    ///
    /// The key stays in the registry: statements it signed before the
    /// revocation still verify, and those after it are refused. The time a
    /// statement asserts is chosen by its signer, so a holder of the key can
    /// backdate one; revoke as early as you know.
    Revoke(TrustRevoke),
    /// Check a registry and explain each key
    ///
    /// Reads the registry as `verify` does. Exits 1 if `verify` could not
    /// use it.
    Show(TrustShow),
}

#[derive(Debug, ClapArgs)]
pub(crate) struct TrustInit {
    /// The registry file to create
    pub(crate) registry: PathBuf,
}

#[derive(Debug, ClapArgs)]
#[allow(clippy::doc_markdown)] // help text, not Markdown
pub(crate) struct TrustAdd {
    /// The registry file
    pub(crate) registry: PathBuf,
    /// A name for this key, unique in the registry
    #[arg(long, value_name = "ID")]
    pub(crate) key_id: String,
    /// A PEM file holding the Ed25519 public key
    #[arg(
        long,
        value_name = "FILE",
        conflicts_with = "public_key",
        required_unless_present = "public_key"
    )]
    pub(crate) public_key_file: Option<PathBuf>,
    /// The public key as the registry writes it: base64 of its DER
    /// SubjectPublicKeyInfo
    #[arg(long, value_name = "BASE64")]
    pub(crate) public_key: Option<String>,
    /// The actor the key belongs to (a UUID)
    #[arg(long, value_name = "UUID")]
    pub(crate) issuer: String,
    /// The tenant the key is trusted for
    #[arg(long, value_name = "TENANT")]
    pub(crate) tenant: String,
    /// A source system the key may speak for; repeat for several
    #[arg(long = "source", value_name = "SOURCE", required = true)]
    pub(crate) sources: Vec<String>,
    /// The first instant the key is valid at, e.g. 2026-01-01T00:00:00Z
    #[arg(long, value_name = "TIME")]
    pub(crate) valid_from: String,
    /// The first instant it is no longer valid at
    #[arg(long, value_name = "TIME")]
    pub(crate) valid_until: Option<String>,
}

#[derive(Debug, ClapArgs)]
pub(crate) struct TrustRevoke {
    /// The registry file
    pub(crate) registry: PathBuf,
    /// The key to revoke
    pub(crate) key_id: String,
    /// When it was revoked, e.g. 2026-06-01T00:00:00Z
    #[arg(long, value_name = "TIME")]
    pub(crate) at: String,
}

#[derive(Debug, ClapArgs)]
pub(crate) struct TrustShow {
    /// The registry file
    pub(crate) registry: PathBuf,
}

#[derive(Debug, ClapArgs)]
pub(crate) struct Issue {
    /// The draft: a JSON file (see docs/sdk/issuing.md)
    pub(crate) draft: PathBuf,
    /// The registry the issuer authenticates its evidence under
    #[arg(long, value_name = "REGISTRY")]
    pub(crate) trust: PathBuf,
    /// Where to write the package. An existing file is not overwritten
    #[arg(long, short, value_name = "FILE")]
    pub(crate) output: PathBuf,
}

#[derive(Debug, ClapArgs)]
pub(crate) struct Sign {
    /// The package whose decision to sign
    pub(crate) package: PathBuf,
    /// Write only the bytes to sign, for a signer elsewhere, and stop
    #[arg(long, value_name = "FILE", conflicts_with_all = ["key", "signature_file", "key_id", "trust", "output"])]
    pub(crate) signing_input_out: Option<PathBuf>,
    /// A PEM file holding the Ed25519 private key to sign with
    #[arg(long, value_name = "FILE", conflicts_with = "signature_file")]
    pub(crate) key: Option<PathBuf>,
    /// A file holding a signature made elsewhere over the bytes
    /// --signing-input-out wrote: standard base64 of 64 bytes
    #[arg(long, value_name = "FILE")]
    pub(crate) signature_file: Option<PathBuf>,
    /// The key's identifier in the registry
    #[arg(long, value_name = "ID", required_unless_present = "signing_input_out")]
    pub(crate) key_id: Option<String>,
    /// The registry the signature must count under
    #[arg(
        long,
        value_name = "REGISTRY",
        required_unless_present = "signing_input_out"
    )]
    pub(crate) trust: Option<PathBuf>,
    /// Where to write the signed package. An existing file is not
    /// overwritten
    #[arg(
        long,
        short,
        value_name = "FILE",
        required_unless_present = "signing_input_out"
    )]
    pub(crate) output: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Evidence {
    /// Check that statements are one unbroken run of an issuer's stream
    ///
    /// The statements are a file with one signed statement per line, in
    /// order. Each must be authentic under your registry. Without --anchor
    /// the run must start at the stream's first step; with it, at the step
    /// after the anchor. Exits 0 if no step between the first and the last
    /// was inserted, removed or altered, 1 otherwise.
    ///
    /// Steps after the last can always be left off unnoticed. To continue
    /// later, keep the head that --json prints and pass it as --anchor.
    Chain(EvidenceChain),
    /// Make a signed evidence statement: what a source observed
    ///
    /// The draft is a JSON file: the statement's stated members (id,
    /// issuer, kind, observedAt, source, subject, tenant) and the evidence
    /// body it commits to. Sign with a local key (--key), or keep the key
    /// elsewhere: write the bytes to sign with --signing-input-out and give
    /// the signature with --signature-file. --stream starts a chained
    /// stream; --after continues one from its last statement.
    ///
    /// The statement is written only if it is authentic under your
    /// registry and, if chained, follows the statement before it. A signed
    /// statement shows who said something, not that it is true.
    Sign(EvidenceSign),
}

#[derive(Debug, ClapArgs)]
pub(crate) struct EvidenceSign {
    /// The draft: the stated members and the body, as JSON
    pub(crate) draft: PathBuf,
    /// Start a stream of this name: the statement is its first step
    #[arg(long, value_name = "NAME", conflicts_with = "after")]
    pub(crate) stream: Option<String>,
    /// Continue a stream: the signed statement this one follows
    #[arg(long, value_name = "FILE")]
    pub(crate) after: Option<PathBuf>,
    /// Write only the bytes to sign, for a signer elsewhere, and stop
    #[arg(long, value_name = "FILE", conflicts_with_all = ["key", "signature_file", "key_id", "trust", "output"])]
    pub(crate) signing_input_out: Option<PathBuf>,
    /// A PEM file holding the Ed25519 private key to sign with
    #[arg(long, value_name = "FILE", conflicts_with = "signature_file")]
    pub(crate) key: Option<PathBuf>,
    /// A file holding a signature made elsewhere over the bytes
    /// --signing-input-out wrote: standard base64 of 64 bytes
    #[arg(long, value_name = "FILE")]
    pub(crate) signature_file: Option<PathBuf>,
    /// The key's identifier in the registry
    #[arg(long, value_name = "ID", required_unless_present = "signing_input_out")]
    pub(crate) key_id: Option<String>,
    /// The registry the statement must be authentic under
    #[arg(
        long,
        value_name = "REGISTRY",
        required_unless_present = "signing_input_out"
    )]
    pub(crate) trust: Option<PathBuf>,
    /// Where to write the signed statement. An existing file is not
    /// overwritten
    #[arg(
        long,
        short,
        value_name = "FILE",
        required_unless_present = "signing_input_out"
    )]
    pub(crate) output: Option<PathBuf>,
}

#[derive(Debug, ClapArgs)]
pub(crate) struct EvidenceChain {
    /// The statements: one signed statement per line, in order
    pub(crate) statements: PathBuf,
    /// Your trust registry: a JSON file of the keys you accept
    #[arg(long, value_name = "REGISTRY")]
    pub(crate) trust: PathBuf,
    /// A step you verified before, which the statements continue: the
    /// `head` of an earlier run's --json output. Only its form is checked:
    /// keep it where only you can change it
    #[arg(long, value_name = "FILE")]
    pub(crate) anchor: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Registration {
    /// Check that a claim was registered
    ///
    /// Takes the agreement both parties signed, the claim made under it and
    /// the registry's receipt, and applies the protocol's checks in order
    /// under keys you trust. Exit code 0 means the claim was made under that
    /// agreement and received by the registry it names. It does not mean
    /// the claim is true, or that the registry kept its own rules.
    Verify(RegistrationVerify),
    /// Check a run of a registry's log, and an entry you hold against it
    ///
    /// The log is a file with one signed entry per line, in order. Without
    /// --anchor it must start at the log's first entry. With --held, also
    /// reports whether the log has your entry at its position. Exits 1 if
    /// the log is refused or contradicts your entry, 3 if it does not reach
    /// your entry's position.
    Log(RegistrationLog),
    /// Audit a registry's whole log: each claim's state, and the registry's
    /// rules
    ///
    /// The log is a file with one signed entry per line, from the log's
    /// first entry. The other files hold the documents the log names, one
    /// per line, in any order: agreements, claims, responses, notices,
    /// dispute terms, disputes and resolutions. Documents the log does not
    /// name are ignored. Exits 1 if the audit is refused.
    ///
    /// A state is the log's, not a verification result: ANSWERED means
    /// evidence was offered, not that it supports the claim.
    Audit(RegistrationAudit),
    /// Check that a registered claim's unit belongs to its inputs
    ///
    /// For holders of the two parties' unit key. Takes the agreement, the
    /// claim, the claim's input values and the key, and checks that the
    /// claim's unit is the nullifier of the inputs the agreement's scope
    /// names. A respondent that finds a mismatch refuses the claim.
    ///
    /// No signature is checked: run `verified registration verify` first.
    /// The key is read from a file and never printed.
    Unit(RegistrationUnit),
}

#[derive(Debug, ClapArgs)]
pub(crate) struct RegistrationUnit {
    /// The signed agreement
    #[arg(long, value_name = "FILE")]
    pub(crate) agreement: PathBuf,
    /// The signed claim
    #[arg(long, value_name = "FILE")]
    pub(crate) claim: PathBuf,
    /// The claim's input values: a JSON object of strings
    #[arg(long, value_name = "FILE")]
    pub(crate) inputs: PathBuf,
    /// A file holding the unit key: 32 bytes as 64 lowercase hexadecimal
    /// characters. A secret; it is not accepted as an argument
    #[arg(long, value_name = "FILE")]
    pub(crate) unit_key: PathBuf,
}

#[derive(Debug, ClapArgs)]
pub(crate) struct RegistrationAudit {
    /// The log: one signed entry per line, from its first entry
    pub(crate) log: PathBuf,
    /// Files of the documents the log names, one document per line
    pub(crate) documents: Vec<PathBuf>,
    /// Your keys for parties and registries
    #[arg(long, value_name = "KEYS")]
    pub(crate) trust: PathBuf,
}

#[derive(Debug, ClapArgs)]
pub(crate) struct RegistrationVerify {
    /// The signed agreement
    #[arg(long, value_name = "FILE")]
    pub(crate) agreement: PathBuf,
    /// The signed claim
    #[arg(long, value_name = "FILE")]
    pub(crate) claim: PathBuf,
    /// The registry's signed receipt
    #[arg(long, value_name = "FILE")]
    pub(crate) receipt: PathBuf,
    /// Your keys for parties and registries
    #[arg(long, value_name = "KEYS")]
    pub(crate) trust: PathBuf,
}

#[derive(Debug, ClapArgs)]
pub(crate) struct RegistrationLog {
    /// The log: one signed entry per line
    pub(crate) log: PathBuf,
    /// Your keys for parties and registries
    #[arg(long, value_name = "KEYS")]
    pub(crate) trust: PathBuf,
    /// An entry you verified before, which the log continues
    #[arg(long, value_name = "FILE")]
    pub(crate) anchor: Option<PathBuf>,
    /// An entry you hold, to check against the log
    #[arg(long, value_name = "FILE")]
    pub(crate) held: Option<PathBuf>,
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
