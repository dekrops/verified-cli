# Fuzz targets

Coverage-guided fuzzing of the untrusted input this tool reads, with
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) and libFuzzer. Why it
is set up this way is recorded in
[decision 0014](../docs/decisions/0014-fuzzing.md).

This directory is its own Cargo workspace with its own pinned nightly
toolchain. Building, testing or installing the tool needs none of it.

## Targets

| Target | What it reads | Beyond "does not panic", it asserts |
| --- | --- | --- |
| `canonical` | any bytes, as JSON | a value's canonical text reads back as that value; text is accepted as canonical exactly when it is that encoding |
| `package` | a trust registry and a package | verification is repeatable; inspection refuses what verification refuses, for the same reason, and otherwise carries the same report |
| `contract` | a contract and an environment | evaluation is repeatable |
| `statement` | a registry, a relying party's context, signed statements | nothing further |
| `registration` | a trust configuration, an agreement, a claim, a receipt | verification is repeatable |
| `registry_log` | a trust configuration, an anchor, a held entry, log entries | the check is repeatable; a held entry only adds checks |
| `registry_audit` | a trust configuration, log entries, documents | the audit is repeatable; an audited log is a segment from the start of the log |
| `registered_unit` | a unit key, an agreement, a claim, the claim's inputs | the check is repeatable |
| `issue` | a trust registry and a draft: a contract, a claim, signed evidence | issuing is repeatable; an issued package is canonical and a verifier with the same registry accepts it with the same complete report |
| `countersign` | a trust registry, countersignatures and a package | a verified package has a signing input; a countersigned package keeps its identifier and verifies with an issuer signature that counts |

A target that takes several texts takes them one per line; each target's
source states its format. Trust configuration is part of the input so that a
seed is self-contained. That is safe because a target asserts only what holds
under any configuration.

## Running

```sh
cargo install cargo-fuzz --version 0.13.2 --locked
cd fuzz                                    # selects the pinned nightly
VERIFIED_CONFORMANCE_DIR=/path/to/wvp/test-vectors ./seeds.sh
cargo fuzz run registry_audit -- -max_total_time=600 -max_len=65536
```

`seeds.sh` writes seed inputs to `corpus/` from the examples in this
repository and, if `VERIFIED_CONFORMANCE_DIR` is set, from the
[published conformance corpus](../conformance/README.md). It needs `jq`.
Seeds are generated rather than committed, because the corpus is not copied
into this repository. `corpus/` and `artifacts/` are ignored by git.

Without seeds a run is of little use: see the next section.

## What a run does and does not show

- **The fuzzer cannot sign.** A changed byte in a signed object makes its
  signature invalid, so an input the fuzzer invents is refused at the
  signature check at the latest. The checks after signatures (chains, the
  rules of an audit, a decision's reproduction) are reached through the
  seeds, and through what the fuzzer can do to them without touching signed
  bytes: dropping, repeating, reordering and recombining whole objects, and
  changing the unsigned configuration. The property tests in
  `crates/verified-verifier/tests` cover the other side: they change
  packages and re-sign them consistently.
- **A panic is a defect, always.** So is a failed assertion of a target. A
  refusal is not: refusing malformed input is the tool working.
- **Finding nothing is weak evidence.** CI runs each target for 30 seconds
  from the seeds, which shows that the targets build and the seeds pass. It
  is not a campaign. Nothing in this repository claims the tool has been
  fuzzed for any stated length of time.

## If a run fails

libFuzzer writes the failing input to `artifacts/<target>/`. Reproduce it
with `cargo fuzz run <target> artifacts/<target>/<file>`, reduce it with
`cargo fuzz tmin`, and turn it into an ordinary test beside the code it
breaks, so that the stable test suite keeps it fixed. If the failure could
make the tool accept something it should refuse, report it as
[SECURITY.md](../SECURITY.md) describes instead of opening a public issue.
