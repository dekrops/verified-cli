# Architecture

## Crates

```text
verified-cli        binary `verified`: arguments, files, terminal, exit codes
   │
verified-verifier   verify(bytes, options) -> Report | Rejection   (pure)
   │
verified-protocol   container, component paths, versions, refusal codes
   │
verified-canonical  verified-json-v1: parse, encode, SHA-256, signing input
```

Dependencies point downward only. The three library crates perform no I/O,
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

**`verified-protocol`** owns names and shapes: what a container's members are,
what the six component paths are, how a refusal code is spelled. It decides
nothing about acceptability.

**`verified-verifier`** owns order. The protocol requires that every verifier
report the same first failure, so the sequence of checks is written in one
function, top to bottom, in specification order.

**`verified-cli`** owns presentation. It maps a `Report` or `Rejection` to
text, JSON and an exit code and adds no conclusion of its own.

## The report

There is no boolean for "valid". A `Report` has one `Finding` per property the
protocol distinguishes: container, component shapes, evidence signatures,
signer authority, decision reproduced, issuer signature. A finding is
`Established` or `NotChecked(reason)`. A check that fails is not a finding: it
is a `Rejection`, and there is no report.

Source truthfulness has no field, because no check can establish it. The CLI
prints that on every report.

A `Rejection` is either `Refused` (a protocol refusal, with its code) or
`Limit` (this tool declined to examine the input). The two are kept apart
because a limit is a fact about the tool, not about the package.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Every protocol check ran; the package was not refused. A reproduced `CONTRADICTED` or `UNDETERMINED` also ends here. |
| 1 | Refused by a protocol check. |
| 2 | The command could not run: usage, unreadable input, resource limit. |
| 3 | Not refused, but not every check ran. |

Code 3 is where upstream's CLI and this one differ on purpose: upstream exits
0 for integrity-only verification without a registry. Here, "not everything
was checked" is never spelled the same as "everything passed".

## Not built yet

`verified-workspace` (local content-addressed store) and `verified-history`
(graph and provenance over imported artifacts) are designed in
[the decision records](../decisions/) and do not exist as crates. No command
that needs them is offered.
