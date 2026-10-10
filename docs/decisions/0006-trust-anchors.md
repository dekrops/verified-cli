# 0006. Trust anchors come only from the relying party

Status: accepted as a constraint. Registry support is not implemented.

## Decision

- A trust registry is a file the relying party supplies explicitly
  (`--trust`). There is no default registry, no bundled key, no
  trust-on-first-use and no fetching.
- Nothing inside a package is ever a trust input: not a key, not a registry,
  not a claim about who signed.
- Without a registry the verifier establishes integrity only and reports
  signatures, authority and the decision as not checked. That outcome has its
  own exit code; it is never reported as complete verification.
- Expectations (`--expect-tenant`, `--expect-contract`, `--expect-claim`) come
  from the relying party's records in the same way, and are checked only after
  everything else has passed, as the protocol orders.
- Registry files hold public keys only. Diagnostics never print signature or
  key material beyond a key identifier.

## Consequences

The tool cannot tell a relying party whom to trust, and will not try. Key
distribution, rotation and revocation freshness are the relying party's
responsibility and are documented as such.
