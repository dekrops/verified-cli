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

Until the corpus is published (see the publication review), conformance can
only be demonstrated by someone with access to it. Public CI cannot show it.
A private interoperability workflow, using the corpus without exposing
credentials to public CI, is the interim plan.
