# 0005. Conformance is measured against the upstream corpus

Status: accepted.

## Decision

- The protocol is defined by the upstream specifications and their vectors.
  This project implements it and does not extend, reinterpret or rename it.
- Check order, canonical bytes, signing domains and refusal codes are
  preserved exactly. Refusal-code strings are a public interface.
- An expected outcome in a vector is never edited. A disagreement is
  investigated in the specification and recorded in
  `docs/protocol/compatibility.md`.
- Partial implementations say so. A vector whose expected refusal belongs to
  an unimplemented check is counted as deferred, never as passing.
- `wvp-0.1` and `wvp-0.2` are distinct. No package is evaluated under the
  other version's rules.
- A new behavior is a new protocol version upstream, not a flag here.

## Consequences

The corpus was published in `dekrops/wvp` on 2026-10-10 (see the publication
review), so anyone can demonstrate conformance from a checkout of it. Public
CI does not run the corpus yet: it still runs only the synthetic tests, and
checking out the corpus at a pinned commit is the remaining step.
