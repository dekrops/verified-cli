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
| Keys smuggled inside the package | Carried issuer signatures are counted and reported as not checked. Nothing in a package is treated as a trust input. |
| Overstated results | No single validity flag. Unchecked properties are reported as not checked. Exit code 0 is reserved for complete verification. |
| Code execution from artifacts | Packages are data. Nothing in one is executed, loaded or fetched. |
| Network exposure | The dependency graph has no network or async runtime; `deny.toml` bans them. |
| Memory safety | `unsafe` is forbidden in every crate of the workspace. |

## Not yet defended, because not yet built

- **Signature verification, signer authority, decision reproduction.** Not
  implemented. The tool says so and cannot be used to establish them.
- **Local storage.** There is no workspace, so no path-traversal, symlink or
  atomic-write surface exists yet. Those defenses are requirements of the
  workspace design ([decision 0004](../decisions/0004-content-addressed-object-storage.md)).
- **Fuzzing.** Property tests exercise the reader and verifier with arbitrary
  bytes; coverage-guided fuzz targets are planned and do not exist.
- **Timing side channels.** Digest comparison is not constant-time. All
  compared values are public, so this is not believed to matter; it will be
  revisited when signatures are verified.

## Limits of the method itself

A fully verified package establishes that signed records from sources the
relying party authorized support a decision under a stated contract. It does
not establish that a source told the truth, that a completeness statement was
honest, or that the package contains everything the sources know. No future
version of this tool will claim otherwise.

## Assurance

Not audited. Not certified. Not production-hardened. The protocol is a draft.
