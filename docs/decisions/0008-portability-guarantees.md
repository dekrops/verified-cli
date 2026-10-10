# 0008. Portability guarantees

Status: accepted for verification; export is not implemented.

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

## Export (future)

An exported closure will be the original package bytes, unmodified, plus
whatever was imported alongside it. Export adds no signature and no claim of
its own: the recipient verifies it exactly as they would verify the original.
