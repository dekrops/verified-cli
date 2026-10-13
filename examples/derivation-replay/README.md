# Synthetic packages for replaying a recomputed authorization (draft)

Twenty-one replay packages and the trust registry to replay them under. They
are **synthetic**: the tenant, systems, people, records and keys name nothing
real, and the keys are test keys derived from fixed seeds.

They are **experimental and not part of the protocol.** A recomputed
authorization is proposed in [RFC 0005](https://github.com/dekrops/wvp/pull/36)
and specified nowhere yet. These files were produced by the first
implementation of the proposal, and this tool is the second: agreeing on them
shows that the two agree, and nothing about conformance. See
[ADR 0016](../../docs/decisions/0016-derivation-replay.md).

Each file is `{ "description", "package", "expect" }`. The scenario is a
purchase-order approval: an ERP records the order and the approval, a
directory records who the people are, and a policy store records the Cedar
policy set that was in force.

| Files | What a replay arrives at | Exit code |
| --- | --- | --- |
| `01-allowed`, `02-denied` | Reproduced. Cedar allows, the contract is `SUPPORTED`; Cedar denies, `CONTRADICTED` | 0 |
| `03` to `10`, `13` | Reproduced, and undetermined: a policy set not declared complete or of another time, a missing entity, an unstated absence, conflicting records, a policy template, an evaluation error, another language version | 0 |
| `11`, `12` | Reproduced: a denial that is not concluded because the event listing is incomplete; an authorized approval of an order that was not approved in the end | 0 |
| `14-statements-in-another-order` | Reproduced, with the commitment of `01` | 0 |
| `20-statement-altered` | Not reproduced at `EVIDENCE`, `SIGNATURE_INVALID` | 1 |
| `21`, `22`, `24`, `25` | Not reproduced at `DERIVATION`: a body altered, a statement removed, a correlation altered, an outcome altered with digests to match | 1 |
| `23-profile-altered`, `26-contract-altered` | Not reproduced at `PROFILE`, at `CONTRACT` | 1 |

Exit 0 means the presented result was computed again from the evidence and
is the same. It does not mean the work was authorized: `02` exits 0 on a
denial.

```sh
verified derivation replay examples/derivation-replay/01-allowed.json \
  --trust examples/derivation-replay/trust.json
verified --json derivation replay examples/derivation-replay/25-outcome-altered.json \
  --trust examples/derivation-replay/trust.json
verified derivation inspect examples/derivation-replay/02-denied.json
```
