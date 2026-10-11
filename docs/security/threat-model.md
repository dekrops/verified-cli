# Threat model

## What is protected

The reader's conclusion. The tool must never lead someone to believe more
about a package than the checks that ran can support.

## Adversary

Whoever produced the file. A package is hostile input: its author chooses
every byte, including the keys, digests and decision it carries, and wants it
reported as favorably as possible, or wants the tool to crash, hang, or touch
something it should not.

Not in scope: an adversary who controls the machine, the binary, or the
relying party's own trust registry.

## Defenses in place

| Threat | Defense |
| --- | --- |
| Oversized input | Input is read through a bounded reader (32 MiB); the bound is enforced while reading. |
| Deep nesting, stack exhaustion | Nesting depth is bounded (128) before recursion. |
| Memory exhaustion by many small values | Value count is bounded (two million). |
| Number bombs (`1e999999999`) | Integer length is bounded (4096 digits), and digits produced by exponents count against the byte limit in aggregate. |
| Two spellings, one meaning | Step 1 refuses any text that is not byte-for-byte canonical. Duplicate keys, fractions and unpaired surrogates are refused by the reader. |
| Substituted component | Every component digest is recomputed and compared with the manifest; the manifest is hashed into the package identifier. |
| Digest confusion | A stated digest matches only as algorithm `sha-256` with 64 lowercase hexadecimal characters. |
| Version confusion | The declared version is checked first. A package of one protocol version is never evaluated as another. |
| Keys smuggled inside the package | Nothing in a package is a trust input. A signature counts only under a key in the registry the relying party supplied, for that key's tenant, issuer, sources and validity period. |
| A signer speaking for a system it has no authority over | A statement verifies only if the registry authorizes its key for the source the statement names. In `wvp-0.2` the source reaching the contract is that name, never one taken from a record's body. |
| A favorable decision written into the package | The recorded decision is never reported. The decision is recomputed from the package's claim, contract, evidence and inputs and must equal the recorded one byte for byte. Without a registry no decision is reported at all. |
| A signature replayed across object kinds or protocol versions | Signing input is domain-separated: statements, `wvp-0.1` decisions and `wvp-0.2` decisions have different prefixes. |
| Forged or malleable signatures | Ed25519 by `ed25519-dalek`, strict verification; small-order keys are refused when the registry is loaded ([decision 0009](../decisions/0009-signature-verification.md)). |
| A genuine package about something else | `wvp-0.2` expectations: the relying party names the tenant, contract digest and claim it means, and a package about another is refused. |
| A contract that never finishes evaluating | Work Contract Language 1 has no code, recursion or unbounded quantifier; predicate size, nesting, fact count and total work are bounded before evaluation. |
| A misconfigured registry silently trusting more | Registry files are closed: an unknown or misspelt member, a duplicate key identifier or duplicate key material is an error. |
| A package steering the file system | Stored objects are named only by digests this tool computed. No name from a package or from the command line is joined to a path; symbolic links in a workspace are refused ([decision 0004](../decisions/0004-content-addressed-object-storage.md)). |
| A trace that implies more than a package holds | `trace` draws one package only, states that it links to nothing else, and labels its links as the package's own statements unless the package verified completely under a supplied registry in the same run. |
| A stale result presented as current | Nothing is cached. `replay` recomputes every result in the current run under the registry given to it. |
| A record passed off with another package | A supplied work record must match the package in every member, or the package is refused with the differing members named. |
| An export that vouches for something | `export` writes the imported bytes and adds nothing. |
| Damage that goes unnoticed | `fsck` reads and re-checks every stored object, compares the history with the objects and reports foreign files and symbolic links. It never repairs. |
| A stored package altered after import | Every read re-checks the bytes against the object name and the package identifier; damage is reported and nothing is shown. |
| Import mistaken for acceptance | `import` checks integrity only and says so; it reports no decision. `show` labels everything as stated by the package. Only `verify` under a supplied registry reports a decision. |
| Terminal control sequences in package text | Human output escapes control and bidirectional characters, so a tenant, source or key name cannot erase, recolor or reorder a report. |
| Overstated results | No single validity flag. Unchecked properties are reported as not checked. Exit code 0 is reserved for complete verification. |
| Code execution from artifacts | Packages are data. Nothing in one is executed, loaded or fetched. |
| Network exposure | The dependency graph has no network or async runtime; `deny.toml` bans them. |
| Memory safety | `unsafe` is forbidden in every crate of the workspace. |

## Not defended

- **Backdating.** Times in a statement are asserted by its signer and are not
  authenticated. The holder of a revoked or expired key can sign a statement
  dated inside the key's validity period, and it will verify. Freshness needs
  an external timestamp or witness, which the protocol does not have.
- **Withheld evidence.** A package can omit records its sources hold. The
  contract language answers with completeness statements, which are
  themselves only as honest as the source that signs them.
- **A wrong registry.** The tool cannot tell a relying party whom to trust.
  Revocation is only as fresh as the registry file supplied.
- **Exit code 0 read as "supported" by a script that did not ask.** Without
  `--require-decision`, exit 0 means every check ran, and the reproduced
  decision can be `CONTRADICTED` or `UNDETERMINED`. A script that gates on
  the exit code must pass `--require-decision SUPPORTED`, or read the
  decision from `--json`.
- **Chains of statements** are not verified when a package is: its
  statements are checked individually. The library verifies a chain of
  statements held outside a package (`verified_verifier::evidence`,
  `verified evidence chain`), and a
  verified chain still says nothing about steps after its last: whoever
  passes statements on can leave off the end.
- **A registration is not a verified claim.** `verify_registration`
  establishes that a claim was made under an agreement both parties signed
  and that a registry the relying party trusts received it at a stated time.
  It does not establish that the work was done, that the registry applied
  its own rules, or that nothing was removed from its log. The times the
  parties state are not authenticated; only the registry's receipt time is,
  and only as far as the relying party trusts that registry's clock.
- **A verified log segment says nothing about the end of the log.** A
  registry can withhold its latest entries, and nothing here detects that.
  A registry that removes an entry and renumbers the rest produces a log
  that verifies on its own; it is contradicted only by someone holding a
  signed entry from before the change (`--held`). The anchor of a segment
  is the relying party's own, like its keys.
- **An audit is of what it was shown.** It establishes that a log, up to its
  last entry, is a consistent history that kept the registry's rules. It
  cannot show that the log is complete, and it compares units as claims
  state them: that a unit belongs to a claim's inputs is checked only by
  holders of the unit key. A claim's state is the log's, never a
  verification result, and a claim with an open dispute is not ready to be
  acted on, whatever its state.
- **A chain anchor is trust configuration**, like the registry. One taken
  from the party whose statements are being checked proves nothing. The
  command reads an anchor from a file and checks only its form: keep the
  head a run printed where only you can change it.
- **A local attacker on the workspace directory.** The workspace refuses
  symbolic links and re-checks every object it reads, which covers what a
  package could cause and accidental damage. It does not defend against
  another process changing the directory while this one runs.
- **A forged import history.** `imports.log` is a plain local file. It is
  shown as local and unauthenticated, and nothing relies on it.
- **Fuzzing beyond what has run.** Property tests exercise the reader with
  arbitrary bytes and the verifier with arbitrary changes to consistently
  re-signed packages. Coverage-guided fuzz targets exist for every kind of
  untrusted input (`fuzz/`). Three of them sign statements and registration
  documents again after the fuzzer changes them, so the checks after a
  signature see arbitrary authentic content. Packages are not re-signed:
  their digests break first. CI runs each target for 30 seconds per change
  and for 10 minutes a week, from a corpus that grows. Fuzzing finds what it
  reaches in the time it has; nothing is claimed beyond that.
- **Timing side channels.** Nothing here is constant-time. Every value
  compared or verified is public.

## Limits of the method itself

A fully verified package establishes that signed records from sources the
relying party authorized support a decision under a stated contract. It does
not establish that a source told the truth, that a completeness statement was
honest, or that the package contains everything the sources know. No future
version of this tool will claim otherwise.

## Assurance

Not audited. Not certified. Not production-hardened. The protocol is a draft.
