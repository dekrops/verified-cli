# Protocol compatibility

The Work Verification Protocol is a **draft** in both versions. This page
states exactly how much of it this implementation performs.

## Supported

| | wvp-0.1 | wvp-0.2 |
| --- | --- | --- |
| Canonical encoding `verified-json-v1` | yes | yes |
| Steps 1 to 6: canonical text, versions, container, component set, digests, commitment | yes | yes |
| Step 7: component shapes at every depth | yes | yes |
| Step 8: evaluator (`UNSUPPORTED_EVALUATOR`) | `order-transition` 1 | `work-contract` 1 |
| Step 9: evidence statements under the registry (ten codes) | yes | yes |
| Step 10: admission (five codes) | yes | yes |
| Step 11: input conditions (`INPUT_MISMATCH`) | yes | yes |
| Step 12: decision reproduced (`DECISION_MISMATCH`) | yes | yes |
| Step 13: issuer signatures (`ISSUER_SIGNATURE_INVALID`) | yes | yes |
| Relying-party expectations | not defined by the protocol | yes |
| Work Contract Language 1 (`kleene-1`) | n/a | yes |
| Work record: computed from the package, and compared with one supplied (`RECORD_MISMATCH`) | not defined by the protocol | yes |
| Chains of statements (evidence statement v1) | **no** | **no** |
| Work-unit identity v1: identity, nullifier, key commitment | n/a (claims have no inputs) | yes, as a library (`verified-work-unit`) |
| Work-unit registry ("was this unit already billed?") | **no**, by design | **no**, by design |

The missing verification item is not one of the thirteen checks. A package's statements
may carry chain links; their shape is checked and their continuity is not,
which is also what the two upstream verifiers do for packages.

## Measured against the corpus

Run on 2026-10-10 against `dekrops/verified` at `3d6f022a`
(see [`conformance/README.md`](../../conformance/README.md) for how). Every
expectation is compared in full, never by refusal code alone.

| Corpus | Result |
| --- | --- |
| `canonical-hash-v1.json` | 12 of 12 valid cases reproduce bytes and digest; 5 of 5 invalid cases refused. |
| `wvp/v0.1`, 26 vectors | 26 reproduced: each refusal code, and for each accepted package the decision, statement count and issuer-signature state. |
| `wvp/v0.2`, 28 vectors | 28 reproduced: as above, plus the contract summary and the value of every requirement. |
| `wvp/v0.2/expectations.json`, 7 cases | 7 reproduced. |
| The two worked examples beside the specifications | Both verify completely as `SUPPORTED` under their registries. |
| `work-contract/v1`, 82 case files and 5 differential batches | 641 cases reproduced, from 81 case files and the 5 batches. 1 case file cannot be represented (below). |
| `work-unit/v1/vectors.json` | 3 of 3 key commitments and 10 of 10 identities and nullifiers reproduced. |
| `evidence-statement/v1` | **Not run.** Its statement and admission rules are exercised through the package vectors; its chain vectors need chain verification, which does not exist here. |

One case is not reproduced because it cannot reach the evaluator:
`72-scale-not-whole` gives a type a fractional `scale`. `verified-json-v1`
has no fractions, so this implementation's reader refuses the file's text.
Inside a package the same text is refused at step 1 (`NOT_CANONICAL`) by
every verifier, before any contract is read.

Agreement on a corpus is evidence of conformance, not proof of it. The corpus
exercises few of the statement-level codes (`UNKNOWN_KEY`, `KEY_NOT_VALID`,
`ISSUER_MISMATCH` and others); those are covered here by this repository's
own synthetic tests, which no other implementation has run.

## Deliberate strictness and open questions

Places where the specification leaves room and no vector decides, or where
the two upstream verifiers differ. Each is a question for the specification,
to be resolved there rather than here.

1. **Duplicate object keys.** The canonical-encoding notes put them outside
   the object model. This implementation refuses them when parsing. For a
   package the outcome is `NOT_CANONICAL` either way.
2. **A stated digest with another algorithm name.** A manifest entry whose
   `hex` is right but whose `algorithm` is not `sha-256` is refused here as
   `COMPONENT_DIGEST`. The JavaScript verifier compares `hex` only at step 5.
3. **A component path that is not a string.** Refused here at step 3 as
   `MALFORMED_COMPONENT`. The JavaScript verifier reaches step 4
   (`COMPONENT_SET`).
4. **Integers beyond 4096 digits** are not examined (a resource limit of this
   tool, not a protocol refusal).
5. **Integers beyond 2⁵³.** The canonical encoding allows integers of any
   size. The JavaScript verifier cannot represent them and refuses the
   package as `NOT_CANONICAL`. Here such a package is canonical; a statement's
   `chain.sequence` must fit 64 bits and every other protocol integer 32
   bits, or step 7 refuses it.
6. **Dates that are not instants** (`2026-02-30`, `24:00:00`, a leap second).
   Refused here at step 7. The JavaScript verifier delegates this to its
   engine's date parser; no vector covers these spellings.
7. **A completeness statement observed before 1970.** "The second in which
   its statement was observed" is taken as the floor of the instant. The
   JavaScript verifier truncates toward zero, which differs only for a
   statement observed in a fractional second before the epoch.
8. **Signature strictness.** The statement specification asks for strict
   Ed25519 verification "by the platform library". This implementation uses
   `ed25519-dalek`'s strict verification, which also rejects small-order keys
   and non-canonical encodings; a registry holding a small-order key is
   refused when loaded. Another library may accept edge-case signatures this
   one rejects. No disagreement in the other direction is known.
9. **Base64.** Signatures and keys must be standard, padded base64 with no
   stray bits. The JavaScript verifier's decoder is lenient. A signature in a
   lenient spelling is `SIGNATURE_INVALID` here.
10. **Registry files.** `validUntil` and `revokedAt` may be `null` or absent;
    any member the registry does not define is refused, so a misspelt
    revocation is an error rather than silently no revocation. Times must be
    in the protocol's canonical spelling.
11. **Expectations without a registry.** The specification checks
    expectations "after every check above has passed". Without a registry
    this implementation still checks them against the package's own content
    and refuses on a mismatch; the report remains incomplete.
12. **Expectations for `wvp-0.1`.** Not defined by the protocol. Giving them
    is an error (exit 2), as in the upstream CLI, never a silent no-op.

## Work records

No published vector covers work records, so agreement here rests on the
specification and on reading the two upstream verifiers, not on a corpus.

16. **Compared last.** A supplied record is compared after the package
    verified and after expectations, as the upstream CLI orders it. Without a
    registry it is still compared, like an expectation; the report stays
    incomplete.
17. **`claimId` is the claim's identifier object** (`{ "value": … }`), as the
    JavaScript verifier computes it; `contractId` and `contractVersion` are
    text.
18. **A record for `wvp-0.1`** is not defined by the protocol. Giving one is an
    error, not ignored.
19. **The computed record is available without a registry.** It is a function
    of the package. It records a verification only when the report beside it
    is complete; the library and the JSON output say so.

## Work-unit identity

Work-unit identity v1 is a draft, separate from WVP, and nothing in a package
refers to it. `verified-work-unit` computes identities, nullifiers and key
commitments; it is not part of `verify` and has no command.

Readings taken where the specification leaves room:

13. **Identifying values are text or booleans.** The specification says one
    value per input the scope names. Claim inputs in Work Contract Language 1
    are never anything else (numbers are written as text), so any other JSON
    value is refused rather than encoded.
14. **A scope's digest is not computed.** The specification says an approval
    covers the scope's digest and calls the scope a versioned object, without
    fixing the digest's input or a version member. Until it does, this
    implementation reads a scope and does not commit to one.
15. **Names are not validated.** Tenant, scope and operation are any text, as
    in the vectors.

The registry the specification proposes (who holds a unit, first write wins)
is stateful, is marked there as not implemented, and is not built here: it
belongs to whoever settles.

## Files and packages

A package is canonical text, which has no trailing line end. A package *file*
conventionally has one. `verified verify` treats exactly one final line end
(`\n` or `\r\n`) as the file's, as the upstream CLI does; the library's
`verify` takes the package text itself and is strict.

## Versions are never interchanged

`verify` detects the declared version and reports it, or is told which to
require. A package of one version is never checked under the rules of the
other, a decision naming the other version's evaluator is refused, and a
signature over a decision of one version does not verify as one over the
other (the signing domains differ). Nothing converts between them.
