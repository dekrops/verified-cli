# 0013. `wvp-0.2` packages are issued by the library that verifies them

Status: accepted and implemented in `verified_verifier::issue`.

## Context

This project read and verified packages and did not build them. Its tests
built them by hand (`tests/support`, which is not an interface), and so did
every consumer that needed one: Agent Compliance Center wrote a producer of
its own, including the environment of WVP v0.2 section 2, and the Python SDK
(`dekrops/verified-python`) wrote a second. Each is a further copy of layout
the verifier already contains, kept in step with it by hand.

Building a package needs exactly what verifying one computes: the input
conditions, the environment, the contract's outcome, the commitment to the
evidence and the decision document. A producer written anywhere else must
repeat all of it.

## Decision

- Add a public module, `verified_verifier::issue`, for `wvp-0.2`:
  `issue` (a `Draft` and the issuer's `Trust` to a package),
  `decision_signing_input`, and `countersign` (add issuer signatures made
  elsewhere).
- **One copy of every rule.** `issue` calls the function the verifier calls
  for step 11 and the evaluation (`work_contract::evaluate`), and writes the
  decision with the function the verifier compares against
  (`verify::decision_over`). The components it lays out are read back
  through `verified_protocol::v02::Components::read` before anything is
  evaluated.
- **Nothing is returned unverified.** The finished text is verified under
  the issuer's registry. What a verifier would refuse is an `IssueError`
  carrying that refusal, never a package.
- **A decision cannot be supplied.** A draft has no member for one.
- **A reproduced `CONTRADICTED` or `UNDETERMINED` is issued.** Those are
  results.
- **No keys.** Statements arrive signed; a countersignature arrives made.
  `decision_signing_input` gives a signer its bytes. Key custody stays with
  the caller, as ADR 0007 requires of an SDK.
- **`wvp-0.1` is not issued.** It names a fixed evaluator; new work uses
  contracts as data.
- **No command.** Issuing needs a signer and a source of evidence, which a
  command-line tool for verification has neither of. It is a library
  operation for SDKs and applications.

## What this changes in the boundary

[Consumers and boundaries](../architecture/consumers.md) listed producing
packages as the platform's. Operating evidence collection, retention and
governance still is. Laying out a package from evidence someone already
holds is protocol work, by that page's own test: a relying party who bills
nothing wants it done one way.

## Limits

- **Issuing is not verifying.** The report beside an issued package says
  what the *issuer's* registry establishes. A relying party verifies under
  its own.
- The issuer's check runs the full verifier once per call, and twice when
  countersigning. Packages are small; this is deliberate.
- Statements are not chained by this module, and chains are not verified
  when issuing, as when verifying.
