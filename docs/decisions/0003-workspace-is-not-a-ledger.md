# 0003. A local workspace is not an authoritative ledger

Status: accepted and implemented (`init`, `import`, `show`, `log`).

## Decision

`verified init` creates a local cache for inspecting imported artifacts. It
is specified, documented and displayed as exactly that:

- Importing never implies accepting. An imported package is not trusted,
  verified or commercially accepted by being imported.
- Import history (what this machine imported, when) and authenticated work
  history (an event order committed to by a ledger) are different things with
  different commands' output, and are never merged into one timeline.
- Relationships are shown only when an imported artifact contains them. A
  standalone package carries no acceptance or finalization; none is drawn.
- Verification results are not cached at all. `show` reports what a package
  states, labelled as the package's own statement; only `verify`, run now
  under a registry supplied now, reports anything as established. If results
  are ever cached they will be labeled as cached, with the registry they were
  computed under, and never shown as freshly checked.

## Why now

The Git analogy is useful for the mechanics and misleading for the meaning:
a Git repository is authoritative for its own history, and a `.verified/`
directory is authoritative for nothing. Fixing the vocabulary before the code
exists keeps the code from drifting into the wrong claim.
