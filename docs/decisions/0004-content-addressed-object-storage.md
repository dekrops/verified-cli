# 0004. Content-addressed object storage

Status: accepted and implemented in `verified-workspace`.

## Decision

- **A stored package is the exact canonical text that was imported.** It is
  never re-encoded.
- **It has two names, and both are checked.** Its directory is named by the
  protocol's own package identifier (`wvp:sha-256:…`); its file by the
  SHA-256 of its bytes, written `object:sha-256:…`.

  The proposal was to use the package identifier alone. That is not enough:
  the identifier commits to the manifest and through it to every component,
  but not to the package's `signatures` member. A package with and without an
  issuer's signature are different texts with one identifier. Storing by
  identifier alone would make importing the second a silent no-op, or a
  silent replacement. So each text is its own object, and a name that matches
  several is an error that lists them.
- **The object name is the workspace's, not the protocol's.** It has its own
  prefix so that it cannot be mistaken for a WVP commitment, and means
  nothing outside a workspace.
- **Only a package with integrity is importable** (protocol steps 1 to 7).
  This settles the question the proposal left open: every stored object has a
  valid package identifier, and a refused package is not kept. Inspecting
  refused input is what `verify` is for.
- **Writes are atomic**: verify, write to a temporary file in the same
  directory, flush, rename. An interrupted import leaves either nothing or a
  complete object, possibly beside a leftover temporary file that is never
  read as an object.
- **Objects are immutable.** Importing bytes already stored writes nothing.
  If the file under an object's name does not hold those bytes, that is
  damage: the import fails and nothing is overwritten.
- **Every read is checked** against both names. A mismatch is reported as
  damage and nothing is returned.
- **Paths are derived from validated hexadecimal digests only.** No name from
  a package, and no name a user types, reaches the file system: a name is
  matched against what is stored, never joined to a path.
- **Symbolic links inside a workspace are refused**, as is anything this tool
  does not write. Nothing is followed and nothing is skipped silently.
- **The import history is a separate, versioned record** (`verified-import-1`,
  one canonical JSON line per import), not derivable from the objects: it
  holds when this machine stored something, by its own clock. A line that
  cannot be read is counted and reported, never guessed at.
- **The layout is versioned** (`verified-workspace-1` in `format`). Another
  format is refused, not migrated.
- No embedded database until measurement shows flat files insufficient.

## Limits

- The symbolic-link checks defend against what a package could cause and
  against accidents. They are not a defense against another process racing
  this one on the same directory; a workspace belongs to one user.
- Two imports at once are safe for objects (each is written whole or not at
  all). The history is appended one short line at a time; `fsck`, when it
  exists, is what will check it against the objects.
- Durability depends on the platform honoring flushes; where a directory
  cannot be synchronized, a crash can lose the newest object, never corrupt
  one.
