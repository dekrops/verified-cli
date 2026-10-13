# 0016. A recomputed authorization is replayed here, as a draft outside the protocol

Status: accepted and implemented in `verified-derivation` and
`verified derivation`. It is an exception to ADR 0005, recorded as one.

## Context

A work contract often requires that someone was authorized. A relying party
that trusts neither a directory's flat list nor the enforcing system's word
holds, or can obtain, the policy set and the entity records as signed
evidence, and the decision follows from them by a published rule: the
[Cedar](https://www.cedarpolicy.com/) policy language.

[RFC 0005](https://github.com/dekrops/wvp/pull/36) proposes that a verifier
may derive a record that way and let a contract read it. It is a draft. No
specification defines the step, the method or the package that carries it.

A first implementation exists upstream, in Scala over Cedar's Java binding.
A proposal of this kind needs a second verifier that reproduces the first
from the evidence alone, and this tool is where a relying party runs one.

ADR 0005 says this project implements the protocol and "does not extend,
reinterpret or rename it", and that "a new behavior is a new protocol
version upstream, not a flag here". This is a new behavior that is not yet a
protocol version.

## Decision

- **Replay it here, in a crate of its own: `verified-derivation`.** It
  authenticates statements with `verified-verifier`, evaluates contracts
  with `verified-contract`, and asks the `cedar-policy` crate for the
  authorization decision. It takes no guard result from a package.
- **It is an exception to ADR 0005, bounded on every side.** The formats it
  reads say `experimental` in their names. The command group says "draft,
  experimental" and its output carries `"draft": true`. No output calls a
  result a WVP verification, a decision or a Work Record. `verified verify`
  is unchanged and still does not read a derived record.
- **Outside the compatibility promise**, like `verified-history` (ADR 0015):
  the crate, the command group, their JSON output and their codes may change
  or be removed without notice. If RFC 0005 is rejected, they are removed.
  If it is accepted, they are rewritten against the specification it
  produces, and the example packages are replaced by the protocol's vectors.
- **The engine is pinned exactly.** `cedar-policy = "=4.10.0"`. A result is
  reproducible against one Cedar language version; an upgrade is a change of
  method version upstream, not a dependency bump here.
- **Cedar is asked only when every precondition holds**, and its answer is
  used only when it reports no evaluation error. Everything else is
  undetermined, which is never a denial. The preconditions are the proposal's.
- **Example packages are committed**, in `examples/derivation-replay`, with
  the approval recorded in the publication review. They were produced by the
  first implementation and are the differential test between the two. They
  are not the protocol's corpus: there is none for this yet.
- **Two licences are added to the allowlist** for Cedar's dependency graph:
  `Zlib` (`foldhash`, linked) and `Apache-2.0 WITH LLVM-exception`
  (`ar_archive_writer`, build time only). Both are permissive and compatible
  with Apache-2.0.

## Consequences

- The dependency graph grows from 95 crates to 225. Every
  one is fetched from crates.io and none brings a network, async or TLS
  stack; the bans of `deny.toml` still hold.
- A reader who installs this tool for `verify` now also builds Cedar. If that
  cost matters, the crate can move behind a Cargo feature. It was not done
  now because the repository has no features and a default build that omits
  a documented command is its own surprise.
- Writing this implementation found an error in the first: its binding
  reports a fixed Cedar language version whatever engine it carries. The
  first implementation was corrected. The two now agree on all 21 example
  packages: 14 reproduced with identical commitments, 7 that were altered
  failing at the same stage with the same code.

## Deliberately not here

- **Two implementations of Cedar.** Both implementations call the same Cedar
  engine at the same release, one through its Java binding and one directly.
  This is a second implementation of the method, not of Cedar.
- **A limit on evaluation time.** Input sizes are bounded. Time is not.
- **A fuzz target.** The crate reads untrusted packages and has none yet
  (ADR 0014).
- **Request context, policy templates and entity tags.** Unsupported: a
  package that needs one is undetermined.
- **Producing a package.** This tool replays; it does not derive and write.
