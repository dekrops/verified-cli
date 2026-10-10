# Compatibility policy

What a script or a program depending on this project may rely on. The project
is pre-release (`0.1.0`), unpublished and untagged, so this is the policy a
first release will be held to, and an honest account of the present.

## Stable now

These follow the protocol or are the command-line interface. They change only
with a clear note in the pull request, and after a first release only with a
major version.

- **Refusal codes.** They are the protocol's. A code is never renamed or
  reused; which check reports which code changes only if the protocol does.
- **Exit codes** of `verified`: 0, 1, 2, 3 and 4, with the meanings in the
  README.
- **JSON output**: member names and the shape of their values. Members may be
  added. Read values you know and ignore members you do not.
- **What a report means.** A property is established only if its check ran and
  passed; a decision is reported only if it was reproduced.
- **Workspace layout** `verified-workspace-1`. A different layout gets a
  different identifier and is refused by this version, not migrated silently.
- **Determinism.** The same bytes and options give the same library result on
  every platform and run.

## Not stable

- **The Rust API of the library crates.** It has changed in every pull request
  so far and will keep changing until a first tagged revision. Depend on an
  exact commit, read the pull requests between two pins, and expect to adapt.
  Additions are the common case; removals and renames happen.
- **Human-readable output.** It is for people. Parse `--json`.
- **The `detail` text of a refusal** and every other message.
- **Resource limits.** They are this tool's own and may be tuned.
- **Test support code** (`crates/*/tests/support`). It is not an interface.
  Use the checked-in files under `examples/`.

## Pinning

Until a tag exists, pin a commit of `main`. Each merge to `main` passed the
quality gate; a commit on another branch promises nothing.

A first tagged revision needs the repository owner's decision, as does any
publication to a package registry. When it exists, the Rust API will follow
semantic versioning from that tag, and this page will say which crates are
covered.

## The protocol itself

WVP `0.1` and `0.2` are drafts. A change to an encoding, a rule, the order of
checks or a refusal code is a new protocol version, which this project would
implement beside the existing ones rather than in place of them.
