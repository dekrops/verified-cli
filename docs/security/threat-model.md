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
- **Exit code 0 read as "supported".** Exit 0 means every check ran. The
  reproduced decision can be `CONTRADICTED` or `UNDETERMINED`; a script must
  read it (`--json`, `properties.decisionReproduced.decision`).
- **Chains of statements** are not verified: a package's statements are
  checked individually.
- **Local storage.** There is no workspace, so no path-traversal, symlink or
  atomic-write surface exists yet. Those defenses are requirements of the
  workspace design ([decision 0004](../decisions/0004-content-addressed-object-storage.md)).
- **Fuzzing.** Property tests exercise the reader with arbitrary bytes and
  the verifier with arbitrary changes to consistently re-signed packages;
  coverage-guided fuzz targets do not exist.
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
