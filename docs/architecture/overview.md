# Architecture

## Crates

```text
verified-cli        binary `verified`: arguments, files, terminal, exit codes
   │
verified-verifier   verify(bytes, options) -> Report | Rejection   (pure)
   │        │
   │   verified-contract   Work Contract Language 1: read, check, evaluate
   │        │
verified-protocol   │      components of both versions, statements,
   │        │              trust registry, refusal codes
verified-canonical  ┘      verified-json-v1: parse, encode, SHA-256,
                           signing input
```

Dependencies point downward only. The four library crates perform no I/O,
read no clock and no environment, and forbid `unsafe`. Everything that touches
the outside world is in `verified-cli`.

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

**`verified-verifier`** owns order and trust. The protocol requires that
every verifier report the same first failure, so the checks run top to bottom
in specification order: the container (shared), then one module per protocol
version, then expectations. It is the only crate that verifies signatures,
and it does so only with keys from a `Trust` the caller built from their own
registry.

**`verified-cli`** owns presentation. It maps a `Report` or `Rejection` to
text, JSON and an exit code and adds no conclusion of its own.

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
| 1 | Refused by a protocol check. |
| 2 | The command could not run: usage, unreadable input, unusable registry, resource limit. |
| 3 | Not refused, but not every check ran. |

Code 3 is where upstream's CLI and this one differ on purpose: upstream exits
0 for integrity-only verification without a registry. Here, "not everything
was checked" is never spelled the same as "everything passed".

Code 0 follows the protocol: a reproduced `CONTRADICTED` or `UNDETERMINED` is
a successful verification of a package whose claim is not supported. That
makes exit 0 unsafe as a gate on its own; the decision is printed, is in the
JSON, and the help text says so. Whether to add an option that requires a
particular decision is an open question for the command-line interface.

## Not built yet

`verified-workspace` (local content-addressed store) and `verified-history`
(graph and provenance over imported artifacts) are designed in
[the decision records](../decisions/) and do not exist as crates. No command
that needs them is offered.
