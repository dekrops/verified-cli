# Decision records

| # | Decision | Status |
| --- | --- | --- |
| [0001](0001-rust.md) | Rust as the implementation language | Accepted |
| [0002](0002-offline-first.md) | Offline-first verification | Accepted |
| [0003](0003-workspace-is-not-a-ledger.md) | A local workspace is not an authoritative ledger | Accepted; implemented |
| [0004](0004-content-addressed-object-storage.md) | Content-addressed object storage | Accepted; implemented |
| [0005](0005-wvp-conformance.md) | Conformance is measured against the upstream corpus | Accepted |
| [0006](0006-trust-anchors.md) | Trust anchors come only from the relying party | Accepted; implemented |
| [0007](0007-sdk-boundaries.md) | SDK boundaries | Accepted; Python built in `dekrops/verified-python`, TypeScript open |
| [0008](0008-portability-guarantees.md) | Portability guarantees | Accepted; implemented |
| [0009](0009-signature-verification.md) | Signatures are verified by `ed25519-dalek`, strictly | Accepted; implemented |
| [0010](0010-work-unit-identity.md) | Work-unit identity is a library without state, keys or a command | Accepted; implemented |
| [0011](0011-statement-chains.md) | Statement chains are verified outside packages, by the library | Accepted; implemented; amended (command) |
| [0012](0012-claim-registration.md) | Claim registration is verified here, in stages, and no registry is run | Accepted; implemented |
| [0013](0013-issuing-packages.md) | `wvp-0.2` packages are issued by the library that verifies them | Accepted; implemented; amended (commands) |
| [0014](0014-fuzzing.md) | Fuzz targets live outside the workspace, on a pinned nightly | Accepted; implemented |
| [0015](0015-work-relations.md) | Work relations are read by a crate of their own, which verifies no record | Accepted; implemented (library) |

"Proposed" means the design is a starting point for the pull request that
builds it, not a commitment.
