# JSON output: the contract for tools and SDKs

Every command accepts `--json` and then writes exactly one JSON value to
standard output. This page is what a script, or a Python or TypeScript wrapper,
may rely on. Stability rules are in the
[compatibility policy](../development/compatibility-policy.md): members may be
added, and existing members keep their names and shapes.

## Rules that hold for every command

- **Read `outcome` first**, then the exit code. Never infer success from the
  absence of an error.
- **There is no `valid`, `verified`, `ok` or `trusted` member, anywhere.** A
  consumer that wants one boolean must compute it from the properties it
  actually needs, and own that decision.
- A digest is `{ "algorithm": "sha-256", "hex": "<64 lowercase hex>" }`.
  Identifiers are full, never shortened.
- A property is `{ "status": "established" }`, or
  `{ "status": "not_checked", "reason": … }`. A property that was checked and
  failed never appears: the outcome is then `refused`.
- Text from a package is JSON-escaped and otherwise unchanged. It is
  untrusted input to whatever reads it next.

## Outcomes shared by commands

| `outcome` | Exit | Members |
| --- | --- | --- |
| `refused` | 1 | `refusal.code` (a protocol refusal code, stable), `refusal.detail` (for people, not stable) |
| `error` | 2 | `error.code`, `error.message`. Nothing was concluded about any package. |

`error.code` is one of `IO_ERROR`, `RESOURCE_LIMIT`, `TRUST_REGISTRY`,
`WORK_RECORD`, `WORKSPACE`, `USAGE`, `EXPECTATIONS_UNDEFINED`,
`RECORD_UNDEFINED`, `NOT_COMPARABLE`.

## `verify`

`outcome` is `complete` (exit 0, or 4 if a required decision was not met) or
`incomplete` (exit 3).

A program linking the library gets the same members without the command:
`Report::to_value` in `verified-verifier` returns them, and the command prints
what it returns plus `note` and `requiredDecision`. `Finding`,
`DecisionFinding` and `IssuerSignature` each have a `to_value` for their part,
which `trace` uses too. A binding should call these and not restate the
mapping.

| Member | Meaning |
| --- | --- |
| `protocol`, `protocolStatus` | `wvp-0.1` or `wvp-0.2`; always `draft` |
| `packageId`, `tenant`, `claim`, `statements` | Of the package. `tenant` and `claim` are what it states. |
| `components[]` | `path` and `digest` of each of the six components |
| `contract` | `wvp-0.2` only: `id`, `version`, `digest` |
| `properties.packageIntegrity` | A property |
| `properties.evidenceSignatures`, `properties.signerAuthority` | Properties |
| `properties.decisionReproduced` | A property. When established it also has `decision` (`SUPPORTED`, `CONTRADICTED` or `UNDETERMINED`) and either `conditions[]` (`wvp-0.1`) or `requirements[]`, `ignored[]`, `conflicts[]` (`wvp-0.2`). **When not checked it has no `decision`**: the decision a package carries is never echoed here. |
| `properties.issuerSignature` | `established` with `count`, `absent`, or `not_checked` with `carried` |
| `properties.sourceTruthfulness` | Always `{ "status": "not_established", … }` |
| `expectationsMet` | The expectations that were given, each `null` if not given |
| `workRecord`, `recordMatched` | `wvp-0.2` only: the record computed from the package, and whether a supplied one was compared (it matched, or the outcome would be `refused`) |
| `requiredDecision` | Only with `--require-decision`: `decision` and `met` |
| `note` | Only when `incomplete`: why |

To act on a package: require `outcome == "complete"` **and**
`properties.decisionReproduced.decision` equal to the decision you need, or
pass `--require-decision` and require exit code 0.

## Workspace commands

| Command | `outcome` | Notable members |
| --- | --- | --- |
| `init` | `initialized`, `exists` | `workspace` |
| `import` | `imported` | `package`, `object`, `protocol`, `alreadyPresent`, `properties` (integrity established; signatures and decision `not_checked`) |
| `show` | `shown` | `package`, `object`, `bytes`, `stated` (everything the package says, with `status: "stated_by_the_package_not_verified"`), `importedAtUnix[]` |
| `log` | none | `imports[]` (newest first: `importedAtUnix`, `importedAt`, `package`, `object`, `protocol`), `damagedRecords`, `note` |
| `trace` | `traced` | `links` (`checked` or `stated_not_checked`), `claim`, `contract`, `evidence[]`, `decision` |
| `fsck` | `clean`, `damaged` (exit 1) | `objects`, `records`, `problems[]` (`kind`, `damage`, `detail`) |
| `export --output` | `exported` | `package`, `object`, `bytes`, `output`. Without `--output`, standard output is the package itself and `--json` is refused. |
| `diff` | `identical`, `different` (exit 1) | `samePackageIdentifier`, `components[]` (`path`, `same`), `stated[]` (`what`, `a`, `b`), `statementsOnlyInA`, `statementsOnlyInB` |
| `replay` | `replayed`, `failed` (exit 1), `decision_not_required` (exit 4) | `packages[]` (`package`, `object`, `status`: `reproduced`, `refused` or `damaged`; `detail`), `requiredDecision` |

## Claim registration commands

| Command | `outcome` | Notable members |
| --- | --- | --- |
| `registration verify` | `registered`, `refused` (exit 1) | `claim`, `claimDigest`, `agreement`, `receipt` (digests), `claimant`, `respondent`, `registry`, `sequence`, `receivedAt`, `respondBy`. Refused: `refusal.code` (a claim registration code, stable), `refusal.detail`. |
| `registration log` | `verified`, `not_covered` (exit 3), `equivocation` (exit 1), `refused` (exit 1) | `registry`, `first`, `last`, `head`, `inclusion` (`null` without `--held`, else `INCLUDED`, `NOT_COVERED` or `EQUIVOCATION`); for `equivocation` also `held` and `logged` (digests) |
| `registration audit` | `audited`, `refused` (exit 1) | `claims[]` in log order: `claim` (identifier), `claimDigest`, `position`, `respondBy`, `state` (`OPEN`, `ANSWERED`, `REFUSED`, `EXPIRED`, `WITHDRAWN`, `SUPERSEDED`), `dispute` (`null`, `OPEN`, `UPHELD`, `REJECTED`) |
| `registration unit` | `unit_matches`, `refused` (exit 1) | `signaturesChecked` (always `false`). Refused: `refusal.code` (a unit check code), `refusal.detail`, which never contains the key or an input value. |

A `state` is the log's, not a verification result, and a claim whose
`dispute` is `OPEN` is not ready to be acted on, whatever its state.

`registered` says a claim was made and received. It never says the claim is
true. `verified` says a run of a log is intact, not that it is complete.

`show`, `trace` without `--trust`, `diff`, `import` and `export` establish
nothing beyond package integrity, and their output says so in a member, not
only in prose.

## Evidence commands

| Command | `outcome` | Notable members |
| --- | --- | --- |
| `evidence chain` | `verified`, `refused` (exit 1) | `fromGenesis`, `first`, `last`, `head`: the last step as an anchor, `{ tenant: { value }, issuer: { value }, stream, sequence, digest }`, which `--anchor` reads back. Refused: `refusal.code` (an evidence code: `MALFORMED`, a `CHAIN_…` code, or a statement code packages share), `refusal.detail`, which names the statement's line when one statement is at fault. |

`verified` says the steps from `first` to `last` are one unbroken run. It
never says the run is complete, or that a statement is true.

## Trust registry commands

| Command | `outcome` | Notable members |
| --- | --- | --- |
| `trust init` | `created` | `registry`, `keys` (0) |
| `trust add` | `added` | `registry`, `key` |
| `trust revoke` | `revoked` | `registry`, `key` |
| `trust show` | `usable`, `unusable` (exit 1) | `keys[]`; for `unusable`, `problem` |

A `key` is `keyId`, `issuer`, `tenant`, `sources`, `maySignDecisions`
(whether `sources` holds `wvp-decision`), and `validFrom`, `validUntil` and
`revokedAt`, spelled as the registry spells them (`null` when absent). A
change that would make the registry unusable is an error (exit 2,
`error.code` `TRUST_REGISTRY`) and leaves the file as it was.

## What a wrapper must not do

- Turn `incomplete` into success. Exit code 3 exists so that it cannot happen
  by accident.
- Present `stated` values, or anything from `show`, as verified.
- Cache a result and return it later as current. Verify again; it is cheap and
  the registry may have changed.
- Supply a default trust registry.
