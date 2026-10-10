# Verified CLI

**Git-like tools for verifiable work.**

Inspect work claims, trace evidence, verify outcomes, and exchange portable
work records, without trusting the system that produced them.

> **Status: early, private, pre-release.** One command exists: `verify`,
> which runs all thirteen of the protocol's checks. The protocol is a draft.
> Nothing here is audited, certified or production-hardened. The license is
> pending (see [`LICENSE`](LICENSE)).

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

`verified verify` checks a package against a trust registry *you* supply:

```console
$ verified verify package.json --trust trust.json
Work Verification Protocol package (wvp-0.2, draft)
package               wvp:sha-256:d0982b73f310…
tenant                tenant-test
claim                 00000000-0000-4000-8000-000000000500
package integrity     established
contract              posting-test 1.0.0, sha-256:6a2c3b0bf581…
evidence signatures   established (1 of 1)
signer authority      established under the supplied registry
decision reproduced   SUPPORTED, matches the package
                        POSTED                      TRUE
issuer signature      absent
source truthfulness   NOT established: no check can establish it

complete: every protocol check ran; the decision SUPPORTED was reproduced
$ echo $?
0
```

(The package above is synthetic test data.)

Without a registry only integrity can be established, and the tool says so
instead of reporting the decision the package carries:

```console
$ verified verify package.json
…
package integrity     established
evidence signatures   not checked: no trust registry supplied
signer authority      not checked: no trust registry supplied
decision reproduced   not checked: no trust registry supplied
issuer signature      not checked: no trust registry supplied (0 carried)
source truthfulness   NOT established: no check can establish it

incomplete: no trust registry was supplied (--trust), so no signature was checked and the decision was not reproduced; the decision the package carries is its issuer's claim
$ echo $?
3
```

A package that fails a check is refused with the protocol's own code:

```console
$ verified verify tampered.json --trust trust.json
Work Verification Protocol package
refused               COMPONENT_DIGEST
                      evidence/bodies.json is not the content its manifest entry commits to
$ echo $?
1
```

| Option | Effect |
| --- | --- |
| `--trust <REGISTRY>` | Your trust registry: the keys you accept, for which issuer, tenant, sources and period. Keys inside a package are never trusted. |
| `--expect-tenant`, `--expect-contract`, `--expect-claim` | Refuse a `wvp-0.2` package that verifies but is about another tenant, contract (by digest) or claim than you meant. |
| `--protocol <VERSION>` | Require a protocol version instead of detecting it. |
| `--json` | The same result as structured data, with full identifiers. |
| `--quiet` | Print nothing; rely on the exit code. |
| `-` | Read the package from standard input. |

| Exit | Meaning |
| --- | --- |
| 0 | Every protocol check ran and the package was not refused. **The reproduced decision may still be `CONTRADICTED` or `UNDETERMINED`: read it.** |
| 1 | Refused by a protocol check. |
| 2 | The command could not run (usage, unreadable input, unusable registry, resource limit). |
| 3 | Not refused, but not every check ran (no registry). |

A trust registry is a JSON file:

```json
{ "keys": [ {
    "keyId": "erp-gateway-1",
    "algorithm": "Ed25519",
    "publicKey": "<base64 of the DER SubjectPublicKeyInfo>",
    "issuer": { "value": "<uuid of the signing actor>" },
    "tenant": { "value": "<tenant>" },
    "sources": ["erp"],
    "validFrom": { "value": "2026-01-01T00:00:00Z" },
    "validUntil": null,
    "revokedAt": null
} ] }
```

A key that may sign decisions as an issuer lists the source `wvp-decision`.

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

Only `verify` exists. The rest arrive in order:

1. **Workspace**: `init`, `import`, `show`, `log` over immutable
   content-addressed storage.
2. **Provenance and integrity**: `trace`, `fsck`.
3. **Portability**: `export`, `diff`, `replay` of authenticated histories,
   and comparison of a package with a work record.

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
verified-contract   Work Contract Language 1: read, check, evaluate
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
- Signatures are Ed25519, verified by `ed25519-dalek`; no cryptographic
  algorithm is implemented here.
- Times in a package are asserted, not authenticated: the holder of a revoked
  key can backdate a statement into the key's validity period.
- No network access, by construction: the dependency graph has no network
  crate and the build fails if one is added.

See [`SECURITY.md`](SECURITY.md) and the
[threat model](docs/security/threat-model.md).

## Contributing

[`CONTRIBUTING.md`](CONTRIBUTING.md) has the quality gate and the rules.

## Supported protocol versions

| Protocol | Status upstream | Here |
| --- | --- | --- |
| `wvp-0.1` | draft | all thirteen checks; `order-transition` evaluator |
| `wvp-0.2` | draft | all thirteen checks; Work Contract Language 1; expectations |
