# 0007. SDK boundaries

Status: proposed. No SDK exists.

## Rust

The library crates are the Rust SDK. Stable surface, in order of maturity:
`verified-canonical` (parse, encode, digest, signing input), then
`verified-protocol` types, then `verified-verifier::verify` and its report.
Storage internals stay private to the workspace crate. The crates are
Apache-2.0. Nothing is published to crates.io without explicit authorization.

## Python and TypeScript

Not started, deliberately: bindings to an unfinished core would freeze its
mistakes. The contract a first SDK would wrap is the command-line JSON
output, described in [`docs/sdk/json-output.md`](../sdk/json-output.md). When
they start:

- They expose domain operations (construct a claim, attach evidence
  references, assemble a package, verify, read a report), not hashing
  primitives.
- They are tested against the same public conformance corpus as the Rust
  core. No SDK carries its own informal copy of the protocol.
- **Issuing is not verifying.** An SDK that builds and signs a package has
  produced a claim. Its API and documentation must never present that as an
  independently verified outcome.
- Signing-key custody is the caller's responsibility and is documented as
  such; SDKs take a signer, not a private key file, where the platform allows.

## Open

Python: Rust-backed (PyO3; one implementation, wheels to build per platform)
or pure Python (a fourth independent implementation, simplest install).
TypeScript: upstream already has an independent JavaScript verifier, which is
an argument for the pure route there. Decide per language once the Rust
verifier is complete, weighing installation friction against the value of
independence. Package names are subject to availability.
