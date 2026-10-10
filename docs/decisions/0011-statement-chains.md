# 0011. Statement chains are verified outside packages, by the library

Status: accepted and implemented in `verified_verifier::evidence`.

## Context

Evidence Statement v1 defines three things: authenticating a signed
statement, verifying that a list of statements is a run of consecutive steps
of one issuer's stream, and admitting statements as the evidence of a claim.
The verifier applied the first and the third inside packages only. Nothing
verified chains, and the protocol's `evidence-statement/v1` vectors had never
been run against this implementation.

Neither version of WVP makes chain continuity one of a package's thirteen
checks, and neither upstream verifier checks it for a package.

## Decision

- Add a public module, `verified_verifier::evidence`, with the three
  operations for statements held outside a package. Each takes what the one
  before it produced: only an authenticated statement can be chained or
  admitted.
- **Verifying a package does not verify chains.** Adding the check would
  refuse packages the protocol accepts. A package's statements keep being
  checked individually, and the documentation says so.
- **An anchor is the relying party's.** A run that does not start at a
  stream's first step is accepted only as the continuation of a step the
  caller already verified. A verified run returns its last step in that
  form.
- **Its own codes.** The chain codes and `MALFORMED` are not refusal codes of
  WVP, so they are not added to `RefusalCode`. `EvidenceCode` holds them and
  wraps the codes the two protocols share.
- **No command yet.** A command needs a file format for "these statements,
  this anchor", which the protocol does not define. Inventing one is a
  separate decision.
- The platform's verification result, which the corpus states for accepted
  admissions, is not computed: it is not specified in the published material.

## Consequences

- The whole `evidence-statement/v1` corpus is reproduced, except that one
  object, and CI shows it.
- A consumer that receives an issuer's statements over time can check that
  nothing was inserted, removed or altered between two points. It cannot
  learn that nothing was left off the end; no offline check can.
- `SignedStatement` exposes a statement's chain link (`chain`) in place of
  the predecessor's digest alone (`chain_previous`). A consumer reading that
  field changes one name.
