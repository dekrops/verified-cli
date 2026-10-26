# 0017. Contract approvals are verified here, with the WebAuthn signature schemes

Status: accepted and implemented in `verified_verifier::approval` and
`verified approval verify`. Contract approval v1 is a draft, and so is this
command's output.

## Context

Contract approval v1 is a draft published beside WVP
(`protocols/contract-approval/v1/SPEC.md`). An approver approves the exact
text of a Work Contract by signing a statement with a passkey: a WebAuthn
credential on a platform authenticator, a security key or a phone. The
statement names the contract's digest and the digest of a snapshot of what
the approver was shown. Anyone who holds the approval file should be able to
check it offline, without trusting the service that recorded it.

Until now the only checker was the Scala reference that generates the
specification's vectors. A relying party had to run that service's code.

Passkeys do not sign with Ed25519 alone. Platform authenticators use ES256
(ECDSA over P-256); some security keys use RS256 (RSASSA-PKCS1-v1_5); few
use EdDSA. The specification requires all three.

## Decision

- **Verify approvals in `verified-verifier`**, in a module of their own
  (`approval`), because it is the only crate that verifies signatures. It
  reads no file and no clock. The command `verified approval verify` reads
  the file and prints, like `registration verify`.
- **The fifteen checks run in the specification's order** and stop at the
  first failure, with its stable code.
- **Two more signature schemes, from RustCrypto:** `p256` (ECDSA P-256 with
  SHA-256, DER signatures, SubjectPublicKeyInfo keys) and `rsa`
  (PKCS#1 v1.5 with SHA-256). Both are Apache-2.0 OR MIT. They share
  `sha2`, `digest`, `signature`, `der` and `spki` with what is already in
  the build. `rsa` is used at `0.10.0-rc.19`: the stable `0.9` line is built
  on the previous generation of those crates and would duplicate them.
- **Ed25519 stays strict**, as decision 0009 requires everywhere: a
  signature that a lenient verifier accepts can be refused here. The key is
  matched against the fixed SubjectPublicKeyInfo prefix, as for registries.
- **Base64url is decoded with padding optional** (the browser omits it),
  and no other alphabet.
- **The file is read with the canonical reader.** A snapshot without a
  canonical form, a fraction anywhere in the file, or a repeated key is
  `MALFORMED`. The client data is read with the same reader, so it must be
  UTF-8 without repeated keys.

## Consequences

- **RUSTSEC-2023-0071** (the Marvin attack) is reported for every version of
  `rsa`. It recovers a private key from the timing of operations with it.
  This tool holds no RSA private key and verifies public signatures over
  public data, so the advisory is ignored in `deny.toml` with that reason.
  An RSA private-key operation added later must revisit it.
- A release-candidate crate is in the build until `rsa 0.10` is released;
  moving to the release is a lockfile change.
- Agreement with the reference on the corpus is evidence, not proof. The
  readings that are stricter than the specification (the file and the
  client data read with the canonical reader; strict Ed25519) are the safe
  direction of disagreement.
- What a valid approval does not establish is printed with it: whose passkey
  it is, and what the authenticator displayed.
