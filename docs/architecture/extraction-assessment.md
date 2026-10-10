# Extraction and protocol assessment

Status: assessment for the first pull request. Source examined:
`dekrops/verified` at `origin/main`, commit `3d6f022a` (fetched 2026-10-09).
Nothing was copied from it into this repository.

## 1. What exists upstream

| Area | Where | Notes |
| --- | --- | --- |
| WVP v0.1 specification (draft) | `protocols/wvp/v0.1/SPEC.md` | Package container, the `order-transition` evaluator, 13 ordered checks, refusal codes. |
| WVP v0.2 specification (draft) | `protocols/wvp/v0.2/SPEC.md` | v0.1 with the contract written in Work Contract Language 1; adds relying-party expectations and work records. |
| Work Contract Language 1 | `protocols/work-contract/v1/SPEC.md` | The evaluator v0.2 needs. Three-valued (`kleene-1`) semantics, with a Lean reference. |
| Work-unit identity v1 | `protocols/work-unit/v1/SPEC.md` | Identities and nullifiers. Not needed for package verification. |
| Evidence Statement v1 | `docs/spec/evidence-statement-v1.md` | Signed statements, trust registry, chains, admission. Both WVP versions build on it. |
| Canonical encoding | `test-vectors/README.md`, ADR 0019 | `verified-json-v1`. Not RFC 8785. |
| Scala implementation | `modules/portable`, `modules/evidence-protocol`, `apps/offline-cli` | The reference: generates the vectors, verifies packages, offline CLI (`verified verify`). |
| JavaScript implementation | `tooling/evidence-conformance.mjs`, `tooling/work-contract.mjs` | Shares no code with Scala; reproduces every vector, decisions included. |
| Rust | `crates/verified-canonical` | A canonical-encoding compatibility checker only (117 lines). No verifier. |
| Lean | `formal/lean` | Reference evaluator for the contract language. |
| Conformance corpus | `test-vectors/` | 54 WVP package vectors (26 v0.1 files, 29 v0.2 files including expectations), 87 contract-language files, 40 evidence-statement files, 17 canonical-encoding cases. |

Upstream's own statement of maturity, which this project repeats rather than
improves on: both WVP versions are drafts; two verifiers agree on the vectors;
no product flow produces v0.2 packages; all vector and example data is
synthetic.

## 2. Licensing

`dekrops/verified/LICENSE` reads, in full substance: all rights reserved, no
license granted, no project license selected. Every file above is therefore
proprietary until its owner says otherwise. See
[the publication review](../protocol/publication-review.md) for the file-level
request.

## 3. Protocol facts this implementation must preserve

- **Canonical form.** Keys by UTF-16 code unit; integers only, in plain
  decimal at any size; specified escapes (C0, DEL and C1 as `\u00xx`, five
  short forms); no normalization.
- **Container.** `{ files, manifest, packageCommitment, packageId, signatures }`;
  manifest `{ canonicalVersion, files, packageVersion: 2, protocol }`; six
  components in fixed order; `packageCommitment` is the SHA-256 of the
  canonical manifest; `packageId` is `wvp:sha-256:<hex>`.
- **Order of checks**, first failure wins: canonical text, versions, container
  members, component set, component digests, commitment, component shapes
  (integrity ends here), evaluator, statements, admission, input conditions,
  decision, issuer signatures, then (v0.2) relying-party expectations.
- **Versions are checked before shape.** Both upstream verifiers read the
  manifest's three version members leniently and refuse
  `UNSUPPORTED_VERSION` before any shape check.
- **Signing domains.** `verified:evidence-statement:v1\n`,
  `verified:wvp-decision:v0.1\n`, `verified:wvp-decision:v0.2\n`, each
  followed by canonical bytes. Ed25519, verified strictly.
- **Trust is external.** A registry is verifier configuration; nothing in a
  package can add to it. Without one a verifier establishes integrity only.
- **A reproduced `CONTRADICTED` or `UNDETERMINED` is a successful
  verification.** Upstream's CLI exits 0 for it.
- **Source truthfulness is never established.**

## 4. Version compatibility

| | wvp-0.1 | wvp-0.2 |
| --- | --- | --- |
| Container, canonical form, check order | shared | shared |
| Contract | names evaluator `order-transition` 1 | Work Contract Language 1 data |
| Claim | `contractId`, subject, outcome | `contract` digest, declared inputs |
| Bodies | five tagged cases | `record` or `complete` |
| Decision | four conditions | per-requirement values, ignored, conflicts |
| Issuer signing domain | `…:v0.1\n` | `…:v0.2\n` |
| Expectations, work record | no | yes |

Each verifier refuses the other version's packages. Nothing converts between
them.

## 5. Open questions found while reading

Recorded in [compatibility notes](../protocol/compatibility.md): how a stated
digest with a wrong algorithm name is refused, how a non-string component path
is refused, and duplicate keys. None is covered by a vector.

## 6. Proposed public crate boundaries

```text
verified-canonical   encoding, digests, signing input         (built)
verified-protocol    typed structures, refusal codes          (built)
verified-contract    Work Contract Language 1                 (built)
verified-verifier    pure verification                        (built: all thirteen checks)
verified-cli         the `verified` binary                    (built: `verify`)
verified-workspace   local content-addressed store            (later)
verified-history     graph and provenance over imports        (later)
```

Dependencies point one way: `cli → verifier → {contract, protocol} →
canonical`. The two later crates are not created until they hold
functionality.

The contract-language evaluator has its own specification and corpus and
depends on nothing but the canonical encoding, so it became its own crate
when it was written.
