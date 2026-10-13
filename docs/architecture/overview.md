# Architecture

## Crates

```text
verified-cli        binary `verified`: arguments, files, terminal, exit codes
   │        │
   │   verified-workspace  the local store: objects and import history
   │        │
verified-verifier   verify(bytes, options) -> Report | Rejection   (pure)
   │        │
   │   verified-contract   Work Contract Language 1: read, check, evaluate
   │        │
verified-protocol   │      components of both versions, statements,
   │        │              trust registry, refusal codes
verified-canonical  ┘      verified-json-v1: parse, encode, SHA-256,
                           signing input
```

Dependencies point downward only. The four protocol crates (`canonical`,
`protocol`, `contract`, `verifier`) perform no I/O, read no clock and no
environment. `verified-workspace` reads and writes one directory and nothing
else; the clock is read only by `verified-cli`, once per import. Every crate
forbids `unsafe`.

External consumers (Agent Billing Center first) depend on the library crates,
never on the binary.

## What each crate owns

**`verified-canonical`** owns bytes. It has its own JSON reader because a
commitment depends on details a general-purpose reader does not promise:
exact integers of any size, refusal of fractions, of unpaired surrogates and
of duplicate keys, and hard resource limits. `Value` is the only
representation hashes are taken over; an object's members are held in
canonical order, so two equal values always encode identically.

**`verified-protocol`** owns names and shapes: the container, the components
of each protocol version (`v01`, `v02`, never mixed), signed statements, trust
registries, instants, refusal codes. Reading a structure checks that it is
closed and well typed at every depth and nothing else; it decides nothing
about acceptability.

**`verified-contract`** owns Work Contract Language 1. It knows nothing of
packages, signatures or tenants: it reads a contract, checks the language's
static rules, and evaluates a checked contract against an environment of
source-named records under strong Kleene logic. A `Contract` can only be
obtained by passing those checks.

**`verified-work-unit`** owns work-unit identity v1: given a scope the parties
declared, a tenant and a claim's inputs, the identity of the unit of work the
claim is about, and its keyed nullifier. It stands beside the verifier and
depends only on the canonical encoding. It answers "are these two claims about
the same unit?" and nothing else: it holds no state, so it cannot say whether
a unit was already billed, and no command uses it.

**`verified-derivation`** replays a recomputed authorization: a record a
verifier derives from signed evidence by asking the Cedar policy engine. It
stands above the verifier and the contract evaluator, authenticates every
statement itself, and compares its own result with the presented one only at
the end. It is the one crate that links Cedar. The step it performs is
proposed for the protocol and is not part of it; the crate is an exception to
ADR 0005 and outside the compatibility promise
([ADR 0016](../decisions/0016-derivation-replay.md)).

**`verified-history`** reads work relations (work relation v1, a draft):
signed statements by which a ledger or an application says how the records of
one unit of work are related. It stands above the verifier and uses it only to
authenticate a statement. It resolves references and compares what records
state; it verifies no record, and a record that was not given makes a relation
*stated*, never refused. `verified history read` prints its reading, and
`prepare_relation` lays out the statement that carries a relation, for a
caller to sign. It is outside the
compatibility promise while the specification is a draft
([ADR 0015](../decisions/0015-work-relations.md)).

**`verified-verifier`** owns order and trust. The protocol requires that
every verifier report the same first failure, so the checks run top to bottom
in specification order: the container (shared), then one module per protocol
version, then expectations. It is the only crate that verifies signatures,
and it does so only with keys from a `Trust` the caller built from their own
registry. Its `evidence` module applies the statement protocol's rules
to statements held outside a package, including chains, which verifying a
package does not check. Its `registration` module verifies a claim
registration, a separate draft protocol, under its own trust configuration.

**`verified-workspace`** owns the `.verified` directory: where an imported
package's bytes go, how they are named and re-checked, and the local import
history. It uses the verifier for exactly one thing, package integrity, and
never holds a registry: nothing it stores or reports is a verification
result ([decisions 0003](../decisions/0003-workspace-is-not-a-ledger.md) and
[0004](../decisions/0004-content-addressed-object-storage.md)).

**`verified-cli`** owns presentation. It maps a `Report` or `Rejection` to
text, JSON and an exit code and adds no conclusion of its own. Text that
comes from a package is shown with control and bidirectional characters
escaped, so that a package cannot redraw the report it appears in.

## The report

There is no boolean for "valid". A `Report` states each property the protocol
distinguishes on its own: package integrity, evidence signatures, signer
authority, the decision, the issuer signature. A property is established or
not checked, with the reason. A check that fails is not a finding: it is a
`Rejection`, and there is no report.

The decision a package carries is never copied into a report. A report holds
a decision only if the verifier recomputed it and found the recorded one
identical; then it also holds what the decision rests on (the conditions of
`wvp-0.1`, or the requirement values, ignored records and conflicts of
`wvp-0.2`).

Source truthfulness has no field, because no check can establish it. The CLI
prints that on every report.

A `Rejection` is `Refused` (a protocol refusal, with its code), `Limit` (this
tool declined to examine the input) or `ExpectationsUndefined` (the caller
asked for a check the package's protocol version does not define). Only the
first is a statement about the package.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Every protocol check ran; the package was not refused. A reproduced `CONTRADICTED` or `UNDETERMINED` also ends here. |
| 1 | Refused by a protocol check. `fsck`: damage found. `diff`: the packages differ. `replay`: a package was refused or is damaged. |
| 2 | The command could not run: usage, unreadable input, unusable registry, resource limit. |
| 3 | Not refused, but not every check ran. |
| 4 | `--require-decision` (`verify`, `replay`): every check ran, but a reproduced decision is not the required one. |

Code 3 is where upstream's CLI and this one differ on purpose: upstream exits
0 for integrity-only verification without a registry. Here, "not everything
was checked" is never spelled the same as "everything passed".

Code 0 follows the protocol: a reproduced `CONTRADICTED` or `UNDETERMINED` is
a successful verification of a package whose claim is not supported. That
makes a bare exit 0 unsafe as a gate. `--require-decision <DECISION>` is the
opt-in answer: with it, exit 0 also means that decision was reproduced, and
any other reproduced decision is exit 4. The default is unchanged so that the
tool keeps the protocol's meaning of success. Only a decision this run
reproduced can meet the requirement; without a registry the exit code stays
3.

## Not built yet

`verified-history` reads relations it is given; nothing stores them. The
workspace still holds packages only, `trace` is still a view of one package,
and `log` still shows import history only. `history read` reads one file
and keeps nothing. There is no container for a history: the specification
defines none, and the file the command reads is the reader's input written
down, as a ledger exports it.
