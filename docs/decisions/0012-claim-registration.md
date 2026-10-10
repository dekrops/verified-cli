# 0012. Claim registration is verified here, in stages, and no registry is run

Status: accepted. The first stage, verifying a registration, is implemented
in `verified_verifier::registration`.

## Context

Claim registration v1 is a draft published beside WVP. A claim is registered
at a registry two parties agreed on, before any evidence is asked for, so
that a party who never answers leaves a record. Its relying parties (the
claimant holding its receipts, an auditor, an arbitrator) need to check
registrations without the platform and without trusting the registry, which
is what this project is for.

The protocol is large: registrations, log segments and held receipts,
responses, closures, notices, disputes with their resolution, an audit of a
whole log, and a unit check for holders of the unit key. Its corpus has 123
cases in six files.

## Decision

- Verify claim registration here, as a relying party would. It is offline
  verification of signed objects under the relying party's own keys.
- **No registry.** Receiving claims, keeping the log and enforcing "one open
  claim per unit" is a service with state. This project checks what a
  registry signed; it does not become one, as the workspace is not a ledger
  (ADR 0003).
- **In stages, each with its vectors:** a registration (28 cases); then log
  segments and held receipts; then the audit, with responses, closures,
  notices and disputes; then the unit check. Commands come with the stage
  that makes them useful. Nothing unbuilt is described as supported.
- **In the verifier and protocol crates.** Structures are read in
  `verified_protocol::registration`, checks and signatures are in
  `verified_verifier::registration`, which stays the only place signatures
  are verified.
- **Its own codes and its own trust.** `RegistrationCode` is separate from
  WVP's `RefusalCode`, and `RegistrationTrust` (keys of parties and of
  registries) is separate from a trust registry of evidence issuers. A key
  trusted for one is not thereby trusted for the other.
- **Written from the published specification and vectors only.** Where the
  specification leaves room, the reading is recorded in
  `docs/protocol/compatibility.md`.
- The registration takes the three objects as text, because the protocol's
  first check is that the text is canonical.

## Consequences

- A claimant can check, offline, that a receipt it holds obliges the
  respondent under an agreement both signed, and by when.
- Until the later stages exist, nothing here checks a registry's log or its
  rules, and the documentation says so wherever a registration is described.
- `RegistrationCode` is marked non-exhaustive, because the later stages add
  codes.
