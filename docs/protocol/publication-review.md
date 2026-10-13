# Publication review

Status: **decided.** All five decisions were made on 2026-10-10 by the
owner of `dekrops/verified`. The protocol material is published in its own
repository, [`dekrops/wvp`](https://github.com/dekrops/wvp), which was made
public on 2026-10-10. It is not copied into this repository.

This repository is licensed under Apache-2.0 and has been public since
2026-10-10.
This document began as the request to publish the protocol's specifications,
vectors and examples, which were then only in a private repository that grants
no license. Sections 1 to 3 are that request as it was made; section 4 records
the decisions.

No file from `dekrops/verified` or `dekrops/wvp` is copied here, with the one exception recorded as decision F. Independently
of this review, nothing is published to a package registry and no release is
made without explicit authorization.

## 1. Decisions requested

| # | Decision | Blocks |
| --- | --- | --- |
| A | License this repository under Apache-2.0. | Making it public; any release. |
| B | Publish the protocol specifications (list 2.1), marked draft. | `protocols/` in this repository; anyone outside implementing WVP. |
| C | Publish the conformance corpus (list 2.2). | Conformance tests in public CI; the benchmark that a third party can check this tool. |
| D | Publish the example package and registry (list 2.3). | The five-minute demonstration in the README. |
| E | Confirm that an independent Rust implementation written from the specifications may be published. | Publishing `verified-protocol` and `verified-verifier`, which state the protocol's wire names, check order and refusal codes. |

Decision E deserves a word. The code here was written from the
specifications, not translated from the Scala or JavaScript sources. But it
was written by someone who read those sources, and it necessarily reproduces
the protocol's identifiers. Whether that is acceptable to publish is a
question for the rights holder, so it is asked rather than assumed.

## 2. Files

Provenance for all: `dekrops/verified`, `origin/main`, commit `3d6f022a`, as
reviewed. The published export was taken at `880e419`, which has the same files
at the same paths; `PROVENANCE.md` in `dekrops/wvp` lists each file's digest.
Licensing status for all: all rights reserved (upstream `LICENSE`).

### 2.1 Specifications

| File | Needed for |
| --- | --- |
| `protocols/wvp/v0.1/SPEC.md` | wvp-0.1 verification |
| `protocols/wvp/v0.2/SPEC.md` | wvp-0.2 verification |
| `protocols/work-contract/v1/SPEC.md` | wvp-0.2 contract evaluation |
| `docs/spec/evidence-statement-v1.md` | statement signatures, registry, admission |
| `test-vectors/README.md` (canonical-encoding section) | `verified-json-v1` definition |
| `protocols/work-unit/v1/SPEC.md` | work-unit identity and nullifiers (`verified-work-unit`) |

The specifications link to ADRs 0019 to 0024, 0029 and 0032 to 0037. Those are
design history, not normative; publishing them is optional. Published copies
of the specifications would need their relative links adjusted, which is an
edit to review.

### 2.2 Conformance corpus

| Path | Files | Needed for |
| --- | --- | --- |
| `test-vectors/canonical-hash-v1.json` | 1 | canonical encoding |
| `test-vectors/wvp/v0.1/` | 26 | wvp-0.1 |
| `test-vectors/wvp/v0.2/` | 29 | wvp-0.2 |
| `test-vectors/work-contract/v1/` | 87 | contract evaluation |
| `test-vectors/evidence-statement/v1/` | 40 | statements, chains, admission |

Before approval, check: the corpus is stated to be synthetic and its keys
deterministic test keys derived from published seeds. Confirm no vector
carries customer data, real identifiers or a key used anywhere else.

### 2.3 Examples

`protocols/wvp/v0.2/examples/invoice-processing/{package.json,registry.json}`
and the v0.1 `order-transition` example.

### 2.4 Not requested

No Scala, JavaScript, Lean or Rust source. No schemas. Nothing from `apps/`,
`modules/`, `infra/` or `connectors/`.

## 3. What is already here, and why it is not an extraction

| Here | Basis |
| --- | --- |
| `verified-canonical` | Implements the encoding rules. Independent parser and encoder; shares no code with upstream's Rust checker, which wraps `serde_json` and `bigdecimal`. |
| `verified-protocol`, `verified-verifier` | Structures of both protocol versions, evidence statements and trust registries, and all thirteen checks with their refusal codes, written from the specifications. Subject to decision E. |
| `verified-work-unit` | Work-unit identity v1 (identity form, nullifier and key-commitment constructions, their domains), written from its specification. Subject to decision E. |
| `verified-contract` | Work Contract Language 1 (forms, static rules, evaluation, refusal codes), written from its specification. Subject to decision E. |
| Tests | Build synthetic packages in process, signed with throwaway keys derived from fixed seeds. The corpus is read from a path outside the repository when one is supplied. |
| Documentation | Describes the protocol in this project's own words and quotes identifiers (member names, refusal codes, signing domains). |

## 4. Record of approval

| Decision | Approved by | Date | Scope or conditions |
| --- | --- | --- | --- |
| A | Repository owner (licensing directive) | 2026-10-10 | Apache-2.0, repository-wide. Visibility, package publication and releases still need explicit authorization. |
| B | Repository owner | 2026-10-10 | Published in `dekrops/wvp`, exported from `dekrops/verified` at `880e419` with links to unpublished files removed. Licensed and made public on 2026-10-10: CC BY 4.0 for specifications and other prose, Apache-2.0 for vectors, examples and every other file. |
| C | Repository owner | 2026-10-10 | As B. Content reviewed before export: synthetic data only, invented names, test keys from published seeds. The work-unit vectors are included. |
| D | Repository owner | 2026-10-10 | As B, with the Work Contract Language 1 examples beside its specification. |
| E | Repository owner (licensing directive) | 2026-10-10 | The independent implementation is Apache-2.0. No proprietary source may be copied because the projects implement the same protocol. |
| F | Repository owner | 2026-10-13 | The draft replay of a recomputed authorization (ADR 0016). Two things come from `dekrops/verified`, where they were written for `dekrops/verified#143`: the Rust replayer, which was written there as a separate crate on this repository's public crates and is restructured here as `verified-derivation`; and the 23 example packages with their trust registry, in `examples/derivation-replay`, which are synthetic and use test keys from fixed seeds. Both are Apache-2.0 here. Nothing else is copied. |
