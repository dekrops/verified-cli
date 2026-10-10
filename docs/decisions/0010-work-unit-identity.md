# 0010. Work-unit identity is a library without state, keys or a command

Status: accepted and implemented in `verified-work-unit`.

## Context

A consumer that bills work needs to recognize two claims about the same unit
of work. The protocol family has a draft for that: an identity built from a
declared scope and a claim's inputs, and a keyed nullifier of it. Agent
Billing Center used a local plaintext key instead because nothing implemented
the draft outside the platform.

## Decision

- Implement the computation: scope, identity, nullifier and key commitment,
  exactly as the draft defines them, checked against its vectors.
- **No registry.** Whether a unit was already accepted or billed needs state
  and an atomic first-write-wins rule. The draft itself marks its registry as
  proposed and unimplemented, and such state belongs to whoever settles. The
  workspace here is a cache and must not become one.
- **No key management.** A nullifier key is a tenant secret. This project
  takes key bytes as an argument and never generates, stores, rotates or
  prints one.
- **No command.** A command would need the secret on the command line or in a
  file this tool reads, for a result only a settling system can use. The
  library is the interface.
- HMAC-SHA-256 is computed by the `hmac` crate with `sha2`. Nothing is
  hand-written.
- The verifier does not depend on it and it does not depend on the verifier.
  Deriving an identity only from inputs of a claim whose verification is
  relied on is the caller's responsibility, and the documentation says so.

## Amendment: the unit of a registered claim

Claim registration v1 lets holders of the parties' unit key check that a
registered claim's unit is the nullifier of its inputs. That check is here,
in `verified_work_unit::registered`, because it is this crate's computation
applied to an agreement and a claim. For it the crate depends on
`verified-protocol`, which reads those objects. It still does not depend on
the verifier, verifies no signature, and keeps no state or key.

That check has a command, `verified registration unit`, which the decision
above ruled out for nullifiers in general. The difference is who runs it: a
party to the agreement, which already holds the key and needs the answer to
decide whether to refuse a claim. The key is read from a file the caller
names, never from an argument or the environment, and is never printed,
logged or stored. There is still no command that computes or prints a
nullifier.

## Consequences

- One more small crate and one more dependency (`hmac`, MIT or Apache-2.0).
- A consumer can interoperate with other implementations of the draft instead
  of inventing a key, and still owns everything stateful.
- The draft may change. It is implemented under its own version identifier
  (`work-unit-1`), so a change there is a new version here, not an edit.
- Privacy is only as good as the key's secrecy: whoever holds a tenant's key
  can test guesses against that tenant's nullifiers. That is a property of the
  construction, stated in the crate's documentation.
