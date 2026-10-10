# Verified CLI

**Git-like tools for verifiable work.**

Inspect work claims, trace evidence, verify outcomes, and exchange portable
work records, without trusting the system that produced them.

> **Status: early, pre-release.** `verify` runs all thirteen of the
> protocol's checks; `init`, `import`, `show`, `log`, `trace`, `fsck`, `export`,
> `diff` and `replay` keep, inspect and move packages in a local workspace.
> The protocol is a draft.
> Nothing here is audited, certified or production-hardened.
>
> **Open source under the [Apache License 2.0](LICENSE).** The repository is
> public; no revision is tagged and no package has been published.

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
| `--require-decision <DECISION>` | Exit 0 only if this decision (`SUPPORTED`, `CONTRADICTED` or `UNDETERMINED`) was reproduced; otherwise exit 4. Use it in scripts. |
| `--protocol <VERSION>` | Require a protocol version instead of detecting it. |
| `--json` | The same result as structured data, with full identifiers. |
| `--quiet` | Print nothing; rely on the exit code. |
| `-` | Read the package from standard input. |

| Exit | Meaning |
| --- | --- |
| 0 | Every protocol check ran and the package was not refused. **Without `--require-decision`, the reproduced decision may still be `CONTRADICTED` or `UNDETERMINED`.** |
| 1 | Refused by a protocol check. `fsck`: damage found. `diff`: the packages differ. `replay`: a package was refused or is damaged. |
| 2 | The command could not run (usage, unreadable input, unusable registry, resource limit). |
| 3 | `verify`: not refused, but not every check ran (no registry). |
| 4 | `--require-decision` (`verify`, `replay`): every check ran, but a reproduced decision is not the required one. |

### Gating a script on the decision

Exit code 0 follows the protocol: a reproduced `CONTRADICTED` or
`UNDETERMINED` is a successful verification of a claim that is not supported.
A script that acts on the exit code alone must therefore say which decision
it needs:

```sh
verified verify invoice.json --trust trust.json --require-decision SUPPORTED \
  && pay_invoice
```

With `--require-decision`, exit 0 means every check ran **and** that decision
was reproduced on this machine. Any other reproduced decision exits 4. The
decision a package merely carries never satisfies the requirement: without a
registry nothing is reproduced and the exit code is 3. The flag is opt-in;
without it the behaviour is unchanged.

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
./target/release/verified verify examples/invoice-posting/supported.json \
  --trust examples/invoice-posting/trust.json
```

[`examples/invoice-posting`](examples/invoice-posting/) holds six synthetic
packages (supported, undetermined, contradicted, and two that are refused)
with the registry to verify them under. They are synthetic test data, not the
protocol's conformance corpus: the official specifications, vectors and
examples are published in [`dekrops/wvp`](https://github.com/dekrops/wvp). To
run the tests against that corpus, see
[`conformance/README.md`](conformance/README.md).

## A local workspace

A workspace is a `.verified` directory holding packages you have imported. It
is a cache for inspection and **authoritative for nothing**: not a ledger, and
not a record of what anyone accepted.

```console
$ verified init
Initialized an empty Verified workspace in /work/invoices/.verified
It is a cache for inspection, and authoritative for nothing.
$ verified import package.json
package               wvp:sha-256:d0982b73f310… (wvp-0.2, draft), stored
package integrity     established

imported, not verified: importing is not accepting. No signature was checked and the decision was not reproduced. To check it: verified verify wvp:sha-256:d0982b73f310…972f84 --trust <registry>
$ verified log
Import history
(local and unauthenticated: this workspace's own note of what it imported, by this machine's clock; not a history of work)

2026-10-10T07:14:13Z  wvp:sha-256:d0982b73f310…  wvp-0.2
$ verified show d0982b73
Work Verification Protocol package (wvp-0.2, draft)
package               wvp:sha-256:d0982b73f310…
object                object:sha-256:4275b8e74c23…, 3930 bytes
package integrity     established

Stated by the package, and checked by nobody:
tenant                tenant-test
claim                 00000000-0000-4000-8000-000000000500
contract              posting-test 1.0.0, sha-256:6a2c3b0bf581…
recorded decision     SUPPORTED (the issuer's claim, not reproduced)
evidence statements   1 (signatures not checked)
                        00000000-0000-4000-8000-000000000001  Event  from erp  key test-erp-gateway  2026-03-01T10:00:00Z
issuer signatures     none
imported here         2026-10-10T07:14:13Z (this machine's clock)

not verified. To check it: verified verify wvp:sha-256:d0982b73f310…972f84 --trust <registry>
$ verified verify wvp:sha-256:d0982b73f310…972f84 --trust trust.json
```

(Identifiers in the two `verify` hints are printed in full; they are
shortened here.)

- **Importing is not accepting.** `import` stores a package that has
  integrity and refuses one that does not. It checks no signature, trusts no
  key and reports no decision.
- **`show` reports what the package says**, labelled as the package's own
  statement. The recorded decision is the issuer's claim until `verify`
  reproduces it under your registry.
- **`log` is import history**: this machine's note, by its own clock. It is
  not an authenticated history of work and is never shown as one.
- A stored package is named by its package identifier, or a prefix of at least
  four hexadecimal characters. Two texts of one package that differ only in
  their issuer signatures share that identifier, so each also has an
  `object:sha-256:…` name, and the tool asks which you mean instead of
  choosing.
- Stored packages are checked against their names every time they are read.
  A damaged one is reported, never shown.

### Tracing a package and checking the workspace

`trace` shows how the parts of one stored package relate. With your registry
it verifies the package first, and the links it draws are the checked ones:

```console
$ verified trace d0982b73 --trust trust.json
Trace of wvp:sha-256:d0982b73f310… (wvp-0.2, draft)
Only what this package contains is shown. It links to no other package and carries no acceptance, finalization or ledger history.
links                 checked: the package verified completely under the supplied registry

claim                 00000000-0000-4000-8000-000000000500 (tenant tenant-test)
  made against        contract posting-test 1.0.0, sha-256:6a2c3b0bf581…
  relies on           1 evidence statement(s)
  statement           00000000-0000-4000-8000-000000000001
    asserts           Event observed in erp at 2026-03-01T10:00:00Z
    signed with       key test-erp-gateway of issuer 00000000-0000-4000-8000-000000000101
    commits to        record of kind posting

decision recorded     SUPPORTED (the issuer's claim)
decision reproduced   SUPPORTED, matches the package
                        POSTED                      TRUE
issuer signature      absent
source truthfulness   NOT established: no check can establish it
```

- Without `--trust` the same picture is drawn from the package's own
  statements and labelled `stated by the package, not checked`.
- A trace never leaves the package. A standalone package names no other
  package, no acceptance and no ledger entry, so none is drawn or implied.
- With a registry, a `wvp-0.2` trace also marks evidence that is authentic but
  that the contract ignored, because it does not accept that source.
- If the package is refused under your registry, `trace` prints the refusal
  and exits 1. It does not fall back to an unchecked trace.

`fsck` reads every stored package, checks it against its names, compares the
import history with what is stored, and reports anything in the workspace the
tool did not write. It repairs nothing and exits 1 if it finds damage:

```console
$ verified fsck
Checked 1 stored package(s) and 1 import record(s).

no damage found. Every stored package is the content its names commit to; that says nothing about its signatures or its decision.
```

### Moving packages around

| Command | What it does |
| --- | --- |
| `verified export <id> [-o FILE]` | Writes a stored package out byte for byte, to standard output or to a file that must not exist. Nothing is added: no signature, no result, no claim of this tool's own. |
| `verified diff <a> <b>` | Compares two packages (files or stored ones): which components differ and what the two state differently. Both need integrity; nothing else is checked. Exits 0 if the texts are identical, 1 if not. |
| `verified replay --trust REGISTRY [id…]` | Verifies stored packages again, now, under the registry given now. Nothing from an earlier run is reused. Exits 1 if any is refused or damaged; with `--require-decision`, 4 if any reproduces another decision. |
| `verified verify <package> --record FILE` | Refuses (`RECORD_MISMATCH`) a `wvp-0.2` package that a work record you hold is not about, naming every member that differs. |

A **work record** states one verification of one package: the claim, the
digests of what was evaluated, the decision and the contract it was made
under. Every member is a function of the package, so two verifiers compute the
same record; `verify --json` prints it as `workRecord`. A record says a
decision was reached. It is not an acceptance.

## Where it is going

Every command of the original plan exists. What is not built:

- Verifying chains of evidence statements.
- Python and TypeScript SDKs. The contract they would be built on is
  [the JSON output](docs/sdk/json-output.md).
- Coverage-guided fuzzing, and Windows in CI.
- A first release: the repository is public, but untagged and unpublished.

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
verified-workspace  the local store of imported packages
verified-verifier   pure verification: bytes in, report or refusal out
verified-contract   Work Contract Language 1: read, check, evaluate
verified-work-unit  work-unit identity v1: which unit a claim is about (library only)
verified-protocol   typed protocol structures and refusal codes
verified-canonical  canonical encoding, SHA-256 commitments, signing input
```

Each crate depends only on those below it. No crate contains `unsafe`. Only
`verified-cli` and `verified-workspace` touch the file system; the others do
no I/O at all. More in
[`docs/architecture/overview.md`](docs/architecture/overview.md) and the
[decision records](docs/decisions/).

## Libraries and SDKs

The crates are the Rust SDK and are meant to be depended on directly (not
through the binary). They are Apache-2.0 and not yet published to crates.io.
Python and TypeScript SDKs are planned and not started; their boundaries are
in [decision 0007](docs/decisions/0007-sdk-boundaries.md). What a dependent
program may rely on is in the
[compatibility policy](docs/development/compatibility-policy.md); where this
project's responsibility ends is in
[consumers and boundaries](docs/architecture/consumers.md).

## Relationship to commercial Verified

Verified is a commercial platform that produces and records work proofs. This
project is the independent checking side, and it is genuinely independent:

- It is open source (Apache-2.0) and contains no source code of the platform.
  It was written from the protocol's specifications.
- It builds, tests and runs from a clean checkout with no access to any
  private repository, service, package or credential. CI does exactly that.
- It verifies any conforming package under any registry, whoever produced
  them. Nothing in it calls, requires or favors the platform.
- It is not a second platform or a second ledger. A local workspace is a
  cache for inspection and authoritative for nothing.

The protocol's specifications and conformance vectors are maintained with the
platform. After review ([publication review](docs/protocol/publication-review.md))
they are published in [`dekrops/wvp`](https://github.com/dekrops/wvp), under
CC BY 4.0 for the specifications and Apache-2.0 for the vectors and examples.
Nothing from it is copied here: the conformance
tests that need the corpus skip unless `VERIFIED_CONFORMANCE_DIR` points to it,
and everything else runs on synthetic data built in this repository.

## License

[Apache License 2.0](LICENSE). See [`NOTICE`](NOTICE). Contributions are
accepted under the same license ([`CONTRIBUTING.md`](CONTRIBUTING.md)).

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
