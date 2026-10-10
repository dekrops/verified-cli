# 0003. A local workspace is not an authoritative ledger

Status: accepted as a constraint. The workspace is not implemented.

## Decision

`verified init` will create a local cache for inspecting imported artifacts.
It will be specified, documented and displayed as exactly that:

- Importing never implies accepting. An imported package is not trusted,
  verified or commercially accepted by being imported.
- Import history (what this machine imported, when) and authenticated work
  history (an event order committed to by a ledger) are different things with
  different commands' output, and are never merged into one timeline.
- Relationships are shown only when an imported artifact contains them. A
  standalone package carries no acceptance or finalization; none is drawn.
- Cached verification results are labeled as cached, with the registry they
  were computed under, and are never shown as freshly checked.

## Why now

The Git analogy is useful for the mechanics and misleading for the meaning:
a Git repository is authoritative for its own history, and a `.verified/`
directory is authoritative for nothing. Fixing the vocabulary before the code
exists keeps the code from drifting into the wrong claim.
