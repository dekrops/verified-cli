# Compatibility policy

What a script or a program depending on this project may rely on. The project
is pre-1.0 and unpublished. Its first tagged revision is `v0.1.0`; this is
the policy tags are held to, and an honest account of the present.

## Stable now

These follow the protocol or are the command-line interface. They change only
with a clear note in the pull request, and after a first release only with a
major version.

- **Refusal codes.** They are the protocol's. A code is never renamed or
  reused; which check reports which code changes only if the protocol does.
- **Exit codes** of `verified`: 0, 1, 2, 3 and 4, with the meanings in the
  README.
- **JSON output**: member names and the shape of their values, as described
  in [`docs/sdk/json-output.md`](../sdk/json-output.md). Members may be
  added. Read values you know and ignore members you do not.
- **What a report means.** A property is established only if its check ran and
  passed; a decision is reported only if it was reproduced.
- **Workspace layout** `verified-workspace-1`. A different layout gets a
  different identifier and is refused by this version, not migrated silently.
- **Determinism.** The same bytes and options give the same library result on
  every platform and run.

## Not stable

- **The Rust API of the library crates, between tags.** It changed in every
  pull request before `v0.1.0` and `main` keeps moving. Depend on a tag, read
  the pull requests between two tags, and expect to adapt across a minor
  version. Additions are the common case; removals and renames happen.
- **Human-readable output.** It is for people. Parse `--json`.
- **The `detail` text of a refusal** and every other message.
- **Resource limits.** They are this tool's own and may be tuned.
- **Test support code** (`crates/*/tests/support`). It is not an interface.
  Use the checked-in files under `examples/`.

## Pinning

Pin a tag, by the commit it names:

```toml
verified-verifier = { git = "https://github.com/dekrops/verified-cli", tag = "v0.1.0" }
```

Cargo records the commit in `Cargo.lock`; build with `--locked`. A commit of
`main` between tags passed the quality gate and promises nothing about its
API. A commit on another branch promises nothing at all.

From `v0.1.0` the Rust API of the five library crates (`verified-canonical`,
`verified-protocol`, `verified-contract`, `verified-verifier`,
`verified-work-unit`) follows semantic versioning as Cargo reads it before
1.0: a patch version (`0.1.x`) only adds or fixes, and a minor version
(`0.2.0`) may remove or rename. `verified-workspace` and the `verified-cli`
crate are not libraries for others and are not covered. All crates share one
version and are tagged together.

CI enforces this for the five library crates: `cargo-semver-checks` compares
every pull request with the last tag and fails on a breaking change made
without the version bump it needs. How a version is chosen and a tag cut is
in [releasing](releasing.md).

### One pin for consumers that exchange packages

Applications that hand packages to one another should verify with the same
revision, or a disagreement between them may be a difference between pins
and not a finding. The known consumers (Agent Billing Center, Agent
Compliance Center, the Python SDK) each record their pin where a test reads
it, in `conformance/upstream.json` or in the SDK's build, and move together
from tag to tag:

```json
{ "verifiedCli": "<the tag's commit>", "wvp": "<the corpus commit>" }
```

A tag, like any publication to a package registry, needs the repository
owner's decision.

## The protocol itself

WVP `0.1` and `0.2` are drafts. A change to an encoding, a rule, the order of
checks or a refusal code is a new protocol version, which this project would
implement beside the existing ones rather than in place of them.
