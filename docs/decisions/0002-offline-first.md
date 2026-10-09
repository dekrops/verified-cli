# 0002. Offline-first verification

Status: accepted.

## Decision

Verification needs no account, server, API key, database or network. The
library entry point takes bytes and options and returns a result; it performs
no I/O and reads no clock (the protocol takes evaluation time from the
package's inputs, never from the machine).

The dependency graph contains no network, TLS or async-runtime crate, and
`deny.toml` fails the build if one appears.

## Consequences

- Nothing is fetched: not keys, not contracts, not revocation data. What a
  relying party trusts must be on disk and named on the command line.
- Revocation is only as fresh as the registry file supplied.
- A future remote operation is a separate decision with its own trust and
  security review, and does not enter the verification crates.
