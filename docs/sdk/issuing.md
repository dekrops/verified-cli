# Issuing a package

`verified issue` turns a **draft** into a `wvp-0.2` package. `verified sign`
adds the issuer's signature over its decision. Both write a package only if
a verifier holding the registry you give accepts it; otherwise they exit 1
and write nothing.

Issuing is not verifying. A package you issue states *your* claim. Whoever
receives it verifies it under *their* registry.

## Making the evidence

Evidence is signed by its source, where the observation is made: an ERP
gateway, a payment processor's webhook, a sensor. `verified evidence sign`
makes such a statement from a statement draft:

```json
{
  "id": { "value": "00000000-0000-4000-8000-000000000001" },
  "tenant": { "value": "acme" },
  "issuer": { "value": "00000000-0000-4000-8000-000000000101" },
  "kind": { "Event": {} },
  "observedAt": { "value": "2026-03-01T10:00:00Z" },
  "source": { "system": "erp", "observationId": "obs-1" },
  "subject": { "system": "erp", "kind": "order", "key": "SO-1" },
  "body": { "record": { "kind": "posting", "fields": { "invoice": "INV-1", "document": "D-1" } } }
}
```

```sh
verified evidence sign posting.json --key-id erp-gateway --key erp.key \
    --trust trust.json -o statement.json
# A stream: start one, then continue from its last statement.
verified evidence sign first.json  … --stream erp/postings -o s0.json
verified evidence sign second.json … --after s0.json      -o s1.json
```

The statement commits to the body by its digest. It is written only if it
is authentic under the registry given (the key, its tenant, issuer, source
and validity) and, when chained, follows the statement before it. As with
`verified sign`, `--signing-input-out` and `--signature-file` keep the key
elsewhere.

In an issue draft, each evidence item is `{ "statement": <the signed
statement>, "body": <its body> }`.

## The draft

One JSON object with exactly these members. Spelling and order do not
matter; the package is written in canonical form.

| Member | What it is |
| --- | --- |
| `tenant` | The tenant the claim and its evaluation are for |
| `contract` | The Work Contract Language 1 contract, inline |
| `claim` | The claim's identifier (a lowercase UUID) |
| `claimant` | Who makes the claim (a UUID) |
| `inputs` | The values the claim supplies for the contract's inputs |
| `submittedAt` | When the claim was submitted, e.g. `2026-03-01T12:30:00Z` |
| `evidence` | A list of `{ "statement": …, "body": … }`: each signed evidence statement with the body its payload commits to, in any order |
| `evidenceSet` | The identifier of this evaluation's evidence set (a UUID) |
| `ingestedAt`, `assembledAt`, `evaluatedAt` | When the evidence was ingested, assembled, and the contract evaluated |

There is no member for the decision: it is computed from the contract and
the evidence, and may be `SUPPORTED`, `CONTRADICTED` or `UNDETERMINED`. All
three are issued.

The statements arrive signed, by their sources. A statement's key must be
in your registry, for its tenant, issuer and source, or the package is not
issued (`UNKNOWN_KEY`, `SOURCE_NOT_AUTHORIZED`, …).

A draft for every example package can be read off the package itself:
`crates/verified-cli/tests/issue.rs` does so, and issuing it gives the
example back byte for byte.

## Signing the decision

```sh
# With a key on this machine (a PEM PKCS #8 Ed25519 key):
openssl genpkey -algorithm ed25519 -out issuer.key
verified sign package.json --key-id my-issuer-key --key issuer.key \
    --trust trust.json -o signed.json

# With a key elsewhere (an HSM, a KMS, another machine):
verified sign package.json --signing-input-out input.bin
#   … sign input.bin with the issuer's Ed25519 key; write the signature
#   as standard base64 to signature.txt …
verified sign package.json --key-id my-issuer-key --signature-file signature.txt \
    --trust trust.json -o signed.json
```

The key must be in the registry with the source `wvp-decision`. A key that
may only speak for evidence sources cannot sign a decision
(`ISSUER_SIGNATURE_INVALID`). The private key is never printed; prefer the
second form wherever the key can stay where it is.
