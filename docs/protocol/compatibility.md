# Protocol compatibility

The Work Verification Protocol is a **draft** in both versions. This page
states exactly how much of it this implementation performs.

## Supported

| | wvp-0.1 | wvp-0.2 |
| --- | --- | --- |
| Canonical encoding `verified-json-v1` | yes | yes |
| Step 1: canonical text (`NOT_CANONICAL`) | yes | yes |
| Step 2: versions (`UNSUPPORTED_VERSION`) | yes | yes |
| Step 3: container members (`MALFORMED_COMPONENT`) | yes | yes |
| Step 4: component set (`COMPONENT_SET`) | yes | yes |
| Step 5: component digests (`COMPONENT_DIGEST`) | yes | yes |
| Step 6: commitment and identifier (`COMMITMENT_MISMATCH`) | yes | yes |
| Step 7: component shapes | **no** | **no** |
| Package integrity (steps 1 to 7) | **not established** | **not established** |
| Steps 8 to 13: evaluator, signatures, admission, input conditions, decision, issuer signature | **no** | **no** |
| Relying-party expectations | n/a | **no** |
| Work record comparison | n/a | **no** |

Because step 7 is missing, this implementation never reports package
integrity as established, and `verified verify` never exits 0.

## Measured against the corpus

Run on 2026-10-09 against `dekrops/verified` at `3d6f022a`
(see [`conformance/README.md`](../../conformance/README.md) for how):

| Corpus | Result |
| --- | --- |
| `canonical-hash-v1.json` | 12 of 12 valid cases reproduce bytes and digest; 5 of 5 invalid cases refused. |
| `wvp/v0.1` and `wvp/v0.2`, 54 vectors | 7 refusals reproduced exactly; 17 accepted packages pass the container checks; 30 refusals belong to checks not implemented and are **deferred**, not counted as conforming. No vector produced a wrong code. |

This is partial agreement on part of the protocol. It is not conformance.

## Deliberate strictness and open questions

Places where the specification leaves room and no vector decides. Each is a
question for the specification, to be resolved there rather than here.

1. **Duplicate object keys.** The canonical-encoding notes put them outside
   the object model. This implementation refuses them when parsing. For a
   package the outcome is `NOT_CANONICAL` either way, since text with a
   repeated key cannot equal its own canonical re-encoding.
2. **A stated digest with another algorithm name.** A manifest entry whose
   `hex` is right but whose `algorithm` is not `sha-256` is refused here as
   `COMPONENT_DIGEST`. The JavaScript verifier compares `hex` only at step 5
   and would accept it; for `packageCommitment` it does check the algorithm
   (`COMMITMENT_MISMATCH`), as does this implementation.
3. **A component path that is not a string.** Refused here at step 3 as
   `MALFORMED_COMPONENT` (a value of the wrong type), which is what a typed
   decoder does. The JavaScript verifier does not type-check `path` at step 3
   and would reach step 4 (`COMPONENT_SET`).
4. **Integers beyond 4096 digits** are not examined (a resource limit of this
   tool, reported as such and not as a protocol refusal). The specification
   bounds package integers to 32 bits, so no well-formed package is affected.

## Versions are never interchanged

`verify` detects the declared version and reports it, or is told which to
require. A package of one version is never checked under the rules of the
other, and nothing converts between them.
