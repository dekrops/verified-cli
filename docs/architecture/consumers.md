# Consumers and boundaries

This project is a library and a tool that other software depends on. This
page records where its responsibility ends, as seen from its first consumer,
and what that consumer is likely to need next.

## The three parties

| Party | Owns | Never owns |
| --- | --- | --- |
| **Verified CLI** (this repository, Apache-2.0) | Reading and verifying WVP packages: canonical bytes, commitments, signatures, signer authority under a supplied registry, contract evaluation, refusal order, per-property reports. A local cache for inspecting packages. | Acceptance, payment, pricing, settlement, identity of customers or vendors, a ledger of work, evidence collection, whom to trust. |
| **Agent Billing Center** (`dekrops/agent-billing-center`, Apache-2.0) | Billing agreements, customer acceptance, eligibility, pricing, invoices, credits, settlement uniqueness in its own store, financial history. | A second verifier, canonicalizer or contract evaluator; a general ledger or graph of work. |
| **Verified platform** (`dekrops/verified`, proprietary) | Operating evidence collection and retention, work records and their governance, enterprise identity. | Being a required trust anchor: a relying party chooses its own. |

The dependency runs one way: Agent Billing Center depends on this project's
library crates. This project depends on neither of the others, at build time
or at run time, and must keep building and passing its tests from a clean
checkout with access to nothing else.

## What a consumer gets, and how to read it

- `verified_verifier::verify(bytes, options)` returns a `Report` or a
  `Rejection`. A report states properties one by one. **A consumer must check
  `Report::is_complete()` and the reproduced decision before acting**; nothing
  else in a report is a substitute.
- `verified_verifier::inspect` additionally returns what the package states.
  Stated values are covered by the package commitment and are otherwise only
  as trustworthy as the report beside them is complete.
- Trust is an input: a `Trust` built from the consumer's own registry.
  Expectations (tenant, contract digest, claim) are inputs too.
- The package identifier commits to the manifest and through it to every
  component. It does **not** cover the package's issuer signatures: one
  identifier can name a text with and without a signature. A consumer that
  requires an issuer signature must check `Report::issuer_signature`, not the
  identifier.

## What this project will not do for a consumer

These are deliberate, and requests for them belong in the consumer:

- Decide that verified work is payable, accepted or complete in a commercial
  sense. A reproduced `SUPPORTED` says the signed records from authorized
  sources establish the contract's requirements, and nothing about money.
- Map keys, tenants or claimants to customers or vendors.
- Guarantee that work was not billed elsewhere. Verification is offline and
  local; uniqueness across systems needs shared state this project has none
  of. `verified-work-unit` says whether two claims are about the same unit,
  never whether a unit was already settled.
- Generate, store or rotate a tenant's nullifier key.
- Establish when something really happened. Times in a package are asserted by
  its signers.
- Interpret a contract's inputs. They are returned in their protocol types;
  which input means "the invoice" is the consumer's profile.

## Where the boundary is likely to move

Each of these is protocol work, so it belongs here rather than in a consumer.
None is built.

| Likely need | Why it belongs here | State |
| --- | --- | --- |
| **Public availability** of the library crates, with a pinned revision or release | A consumer cannot ship a build that needs private access. | The repository is public (issue 6, closed), so a consumer can pin without credentials. Tagged `v0.1.0`; no published crate yet. |
| **A library compatibility policy and tagged revisions** | A consumer pins a commit today and absorbs every API change. | Policy written ([compatibility policy](../development/compatibility-policy.md)); first tag `v0.1.0`, which the known consumers pin together. |
| **Work-unit identity** (a stable identity for "the same unit of work" across contract versions, and its nullifier) | It is a protocol rule. A consumer inventing its own key cannot interoperate. | Built as a library, `verified-work-unit`: scope, identity, nullifier, key commitment. The consumer supplies the scope and holds the tenant key; this project stores neither. |
| **A work-unit registry** (has this unit been billed?) | It does not belong here. It is state with a first-write-wins rule, and it is the settling party's. | Not built, deliberately. |
| **Work record comparison** (`RECORD_MISMATCH`) | It is the protocol's way of binding a recorded verification to a package. | Built: `Report::work_record` and `Options::record`. A consumer storing a verification can store the record and later check a package against it. |
| **Statement chains** | Continuity of an issuer's stream is a protocol check. | Built as a library, `verified_verifier::evidence`: authenticate statements, verify a run from its first step or from an anchor, admit. No command, and not applied to a package's statements. |
| **Issuing packages** | Laying out a package repeats what verifying one computes. A producer anywhere else is a second copy. | Built as a library, `verified_verifier::issue` (ADR 0013): `wvp-0.2` only, no keys, and nothing is returned that the verifier would refuse. |
| **Freshness or revocation status at verification time** | Whether a key is still good now is a trust input with protocol consequences. | The protocol has no such input. This would be a protocol change, not a feature to add here on its own. |

## Keeping the boundary

- A change here that only one consumer's commercial rules need does not belong
  here. The test: would a relying party who bills nothing want it?
- A check a consumer performs on package fields by parsing them itself is a
  signal that this library is missing an accessor, as with the claimant and
  claim inputs (issue 5).
- Fixtures a consumer tests against should come from `examples/`, which are
  checked in and regenerated by a test, not from this repository's test
  support code, which is not an interface.
