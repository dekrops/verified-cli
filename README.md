# Verified CLI

**Git-like tools for verifiable work.**

Inspect work claims, trace evidence, verify outcomes, and exchange portable
work records, without trusting the system that produced them.

> **Status: early foundation, private, pre-release.** One command exists,
> and it performs the first six of the protocol's thirteen checks. The
> protocol is a draft. Nothing here is audited, certified or
> production-hardened. The license is pending (see [`LICENSE`](LICENSE)).

## What it is

`verified` is a single local executable for checking *Work Proofs*: portable
packages in which a system states a claim about completed work, the contract
that defines "done", the signed evidence, and the decision it reached. The
format is the [Work Verification Protocol](docs/protocol/compatibility.md)
(WVP, draft).

It needs no account, server, API key, database or network connection.

## What a Work Proof establishes, and what it cannot

Fully verified under a trust registry *you* supply, a package establishes
that:

- its contents are the ones it commits to (integrity);
- each piece of evidence was signed by a key you authorized for that source;
- the decision (`SUPPORTED`, `CONTRADICTED` or `UNDETERMINED`) is what the
  contract yields from that evidence, recomputed on your machine.

It cannot establish that a source told the truth, that a completeness
statement was honest, or that the package holds everything the sources know.
A valid signature proves who said something, not that it is so. And a
reproduced `CONTRADICTED` is a successful verification of a claim that is not
supported, not an invalid package.

## What works today

```console
$ verified verify package.json
Work Verification Protocol package (wvp-0.2, draft)
package               wvp:sha-256:a2cc1e196acd…
container             consistent: canonical text, versions, component set, digests, commitment
component shapes      not checked: not implemented in this version
package integrity     NOT established: component shapes were not checked
evidence signatures   not checked: not implemented in this version
signer authority      not checked: not implemented in this version
decision reproduced   not checked: not implemented in this version
issuer signature      not checked: not implemented in this version
source truthfulness   NOT established: no check can establish it

incomplete: this version runs protocol steps 1 to 6 of 13; the package was not refused and is not verified
$ echo $?
3
```

A package that fails a check is refused with the protocol's own code:

```console
$ verified verify tampered.json
Work Verification Protocol package
refused               COMPONENT_DIGEST
                      evidence/bodies.json is not the content its manifest entry commits to
$ echo $?
1
```

`--json` prints the same result as structured data with full identifiers;
`--quiet` prints nothing and leaves the exit code; `--protocol wvp-0.2`
requires a version instead of detecting it; `-` reads standard input.

| Exit | Meaning |
| --- | --- |
| 0 | Every protocol check ran and the package was not refused. *Not reachable yet.* |
| 1 | Refused by a protocol check. |
| 2 | The command could not run (usage, unreadable input, resource limit). |
| 3 | Not refused, but not every check ran. |

### Try it

```sh
cargo build --release --locked
./target/release/verified verify path/to/package.json
```

There is no example package in this repository yet: the protocol's examples
and conformance vectors are in a private repository and await
[publication approval](docs/protocol/publication-review.md). With access to
them, see [`conformance/README.md`](conformance/README.md).

## Where it is going

```sh
verified init                                   # a local workspace for inspection
verified import invoice.wvp                     # importing is not accepting
verified log                                    # what this workspace has seen
verified show <id>
verified trace <id>                             # only relationships the artifact contains
verified verify invoice.wvp --trust trust.json  # complete verification under your registry
verified fsck
```

None of these exists except the partial `verify`. They arrive in order:

1. **Complete verifier**: component shapes, evidence signatures, trust
   registry, Work Contract evaluation, decision reproduction, issuer
   signatures, expectations. Full agreement with the conformance corpus.
2. **Workspace**: `init`, `import`, `show`, `log` over immutable
   content-addressed storage.
3. **Provenance and integrity**: `trace`, `fsck`.
4. **Portability**: `export`, `diff`, `replay` of authenticated histories.

## Relationship to WVP

WVP v0.1 and v0.2 are drafts, defined by specifications and a conformance
corpus maintained alongside the commercial Verified platform. Two verifiers
exist there (Scala and JavaScript). This is a third, written independently in
Rust from the specifications. It implements the protocol as specified and
does not extend it. The two versions have different semantics and are never
interchanged.

Exactly what is and is not implemented, and how it measures against the
corpus: [`docs/protocol/compatibility.md`](docs/protocol/compatibility.md).

## Architecture

```text
verified-cli        the `verified` binary: arguments, files, terminal
verified-verifier   pure verification: bytes in, report or refusal out
verified-protocol   typed protocol structures and refusal codes
verified-canonical  canonical encoding, SHA-256 commitments, signing input
```

Each crate depends only on those below it. The library crates do no I/O and
contain no `unsafe`. More in
[`docs/architecture/overview.md`](docs/architecture/overview.md) and the
[decision records](docs/decisions/).

## Libraries and SDKs

The crates are the Rust SDK and are meant to be depended on directly (not
through the binary). They are unpublished until the license is settled.
Python and TypeScript SDKs are planned and not started; their boundaries are
in [decision 0007](docs/decisions/0007-sdk-boundaries.md).

## Relationship to commercial Verified

Verified is a commercial platform that produces and records work proofs. This
project is the independent checking side: it needs nothing from the platform
to run, and is not a second platform or a second ledger. A local workspace,
when it exists, will be a cache for inspection and authoritative for nothing.

## Security and trust assumptions

- Every input file is treated as hostile: size, depth, value count and
  integer length are bounded.
- Trust comes only from you. Keys inside a package are never trusted, and
  there is no default registry.
- No network access, by construction: the dependency graph has no network
  crate and the build fails if one is added.

See [`SECURITY.md`](SECURITY.md) and the
[threat model](docs/security/threat-model.md).

## Contributing

[`CONTRIBUTING.md`](CONTRIBUTING.md) has the quality gate and the rules.

## Supported protocol versions

| Protocol | Status upstream | Here |
| --- | --- | --- |
| `wvp-0.1` | draft | container checks (steps 1 to 6) |
| `wvp-0.2` | draft | container checks (steps 1 to 6) |
