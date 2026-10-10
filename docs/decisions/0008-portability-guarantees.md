# 0008. Portability guarantees

Status: accepted and implemented.

## The benchmark

A package created outside this implementation can be verified by this tool
without access to its producer.

## What is guaranteed

- **Determinism.** The same bytes and the same options give the same result
  on every platform and every run. No clock, locale, environment variable or
  file-system state influences a library result.
- **Byte fidelity.** Verification reads the exact bytes supplied. Nothing is
  normalized, re-encoded or repaired before checking.
- **Stable interfaces.** Refusal codes are the protocol's. Exit codes and
  JSON member names are versioned with the tool; a breaking change to either
  is a major version.
- **Full identifiers in machine output.** Truncation is for people only.

## What is not

- Human-readable output is not an interface. Parse `--json`.
- The `detail` text of a refusal is for people and may change.
- A resource limit is this tool's own. Input beyond one is reported as not
  examined, never as refused by the protocol.

## Export, diff and replay

- **Export** writes the stored bytes unmodified: the exact canonical text that
  was imported, with no line end added. It adds no signature and no claim of
  its own, and never overwrites a file. The recipient verifies it exactly as
  they would the original. Nothing was imported alongside a package, so there
  is nothing else to export.
- **Diff** compares two packages that have integrity and reports what they
  state differently. It verifies nothing beyond integrity, and says so.
- **Replay** recomputes. It verifies stored packages in the current run under
  the registry given to the current run and reuses no earlier result, because
  nothing is cached to reuse ([decision 0003](0003-workspace-is-not-a-ledger.md)).
  It is not a replay of a ledger: a workspace has no authenticated history to
  replay, only packages to verify again.
