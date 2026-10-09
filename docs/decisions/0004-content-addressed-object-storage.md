# 0004. Content-addressed object storage

Status: proposed. To be settled in the pull request that implements it.

## Proposal

- An imported package is stored as the exact bytes received. Its object
  identifier is the protocol's own: the package identifier
  (`wvp:sha-256:…`), which is already a commitment to the manifest and through
  it to every component. No second hash of the same thing is invented.
- If the workspace ever needs an object the protocol does not identify (an
  import record, an index entry), it gets a separate, versioned domain and
  encoding, never one that could be mistaken for a WVP commitment.
- Writes are atomic: validate, write to a temporary file in the same
  directory, flush, rename. An interrupted import leaves either nothing or a
  complete object.
- Objects are immutable. Re-importing identical bytes is a no-op.
- Object paths are derived from validated hexadecimal digests only. No name
  from an artifact reaches the file system. Symbolic links inside the store
  are refused.
- Indexes are rebuildable from objects. `fsck` checks objects against their
  identifiers and indexes against objects.
- No embedded database until measurement shows flat files insufficient.

## Open

Whether only packages that pass the container checks are importable (so every
stored object has a valid identifier), or whether refused packages can be kept
for inspection under a different, clearly marked identifier.
