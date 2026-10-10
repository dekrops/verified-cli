# 0009. Signatures are verified by `ed25519-dalek`, strictly

Status: accepted and implemented.

## Context

The protocol's only signature algorithm is Ed25519 (RFC 8032): over evidence
statements and, optionally, over decisions. The mission of this tool rules
out implementing cryptography here.

## Decision

- Ed25519 verification is done by `ed25519-dalek` (with `curve25519-dalek`),
  built without default features: no key generation, no randomness, no
  batch verification. Only verification is used outside tests.
- Verification is strict (`verify_strict`): signatures with a non-canonical
  encoding and signatures that only a small-order component makes valid are
  rejected. A registry key that is a small-order point is refused when the
  registry is loaded.
- Registry keys are the base64 DER `SubjectPublicKeyInfo` of an Ed25519 key.
  That encoding is a fixed 12-byte prefix followed by the 32 key bytes, so it
  is matched exactly rather than parsed with an ASN.1 library.
- Base64 is decoded by the `base64` crate's standard, padded, strict engine.
- SHA-256 remains `sha2`.

## Consequences

- Three more crates of third-party cryptography enter the build
  (`ed25519-dalek`, `curve25519-dalek`, `ed25519`) with their small
  dependencies. They are BSD-3-Clause, which `deny.toml` now allows; a binary
  distribution must reproduce their copyright notice.
- Strict verification can reject an edge-case signature that another
  conforming verifier's library accepts. That direction of disagreement is
  the safe one and is recorded in
  [`docs/protocol/compatibility.md`](../protocol/compatibility.md).
- Signature verification is not constant-time and does not need to be: every
  value involved is public.
