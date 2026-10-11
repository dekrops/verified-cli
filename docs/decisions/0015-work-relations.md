# 0015. Work relations are read by a crate of their own, which verifies no record

Status: accepted and implemented in `verified-history`; amended with a
command, `verified history read`, and with a producer (both below).

## Context

Work relation v1 is a draft published beside WVP. One unit of work leaves
several records: a package, a work record in a ledger, a registration at a
claim registry. A work relation is a signed statement by which an authority
says how records it knows are related, carried by an ordinary evidence
statement. Its relying parties want to take several records and establish,
offline, which belong together and who says so.

The architecture has named a `verified-history` crate since the start and
left it unbuilt, "because there is nothing for it to hold yet": a package
names no other package. Relations are the artifacts that link to each other.

Until now the specification had one implementation, the Scala reference that
generates its vectors. Nothing in it had been checked by two implementations
agreeing.

## Decision

- **Read relations here, in a crate of their own: `verified-history`.** It
  stands above the verifier and depends on it for one thing, authenticating
  a statement under the relying party's registry.
- **The reader verifies no record.** It parses each record as the kind it is
  offered as, names it by that kind's own digest, and compares what records
  state with what relations state. Whether a package verifies, or a
  registration, stays with `verified-verifier`. `CHECKED` therefore means
  "consistent with the records in hand", and the API says so. A caller that
  wants both runs both and reports both.
- **No single result.** `read` returns one standing per relation, one result
  per derived same-claim pair and one per stream. Nothing folds them into a
  flag, as nothing folds a package report into `valid`.
- **A record that was not given is never an error.** The relation to it is
  `STATED`. This is the same line `trace` draws inside a package between
  `checked` and `stated_not_checked`.
- **Shapes stay in `verified-protocol`.** The relation body, a standalone
  reader for `claim.json` and a reader for a work record are added there,
  beside the other typed structures. All three are additions.
- **Outside the compatibility promise.** The specification is a draft. The
  five library crates keep their promise; `verified-history`, and the
  `relation` module of `verified-protocol`, make none until the
  specification leaves draft.
- **Import history stays what it was.** The workspace's log of what was
  imported, and when, is not merged with what authorities signed (ADR 0003).
  This crate reads values it is given and touches no workspace.

## Consequences

- The published corpus, `work-relation/v1`, is reproduced in full: every
  record, every relation's standing, every derived relation and every
  stream of every case. The specification now has two implementations that
  agree.
- Writing this one from the published text found a gap in it: the
  completeness of a stream was defined by reference to a computation the
  evidence statement specification does not contain. The specification was
  corrected upstream.
- The conformance pin moves to a commit of `dekrops/wvp` that contains the
  corpus. The rest of the suite was run against that commit and passes.

## Amendment: a command

`verified history read HISTORY --trust REGISTRY` reads one JSON file,
`{ relations: [{ statement, body }], records: [{ kind, text }] }`, and
prints the reading.

- **The file is the reader's input, not a container.** It is what a ledger
  exports for one claim. The specification defines no container, and this
  command does not pretend one exists: it promises nothing about the file's
  shape beyond the draft.
- **The exit code is the least favourable thing found**, in the tool's
  existing meanings: 1 if a relation is refused or contradicted, a record is
  malformed, a registered claim is not the package's claim, or a stream
  contradicts itself; 3 if a relation names a record that was not given, a
  record is of an unknown kind, or there is no relation; otherwise 0. A
  stream's completeness is reported and never changes the exit code:
  one claim's history is usually part of a longer stream.
- **It says, every time, that no record was verified.** JSON output carries
  `recordsVerified: false`. Running the package and registration verifiers
  over the same file is a later change, and would report beside the
  reading, never fold into it.
- **Bounded.** At most 1024 relations and 1024 records are read; the reader
  compares each relation with each record.

## Amendment: a producer

`verified_history::prepare_relation` lays out the statement that carries a
relation, and `Relation::to_value` writes a relation's body.

- **The producer is here because the reader is.** Three consumers need to
  issue relations: both SDKs and the compliance application. A body written
  in each of them is three places for the encoding to drift. Every relation
  laid out here is read back with `Relation::from_value` first, and the
  statement with the statement reader, so nothing is produced that the
  reader refuses. The conformance test also checks that the producer writes
  every accepted body of the corpus byte for byte.
- **The statement's `kind` and `subject` are not the caller's to state.**
  They follow from the relation and the source, as the specification's
  carrier rules say; a draft that states them is refused.
- **No key is held**, as for statements and packages: the caller signs over
  `statement_signing_input` and attaches the signature.
- **Producing is not being believed.** Whether a relying party accepts the
  relation is its registry's decision. `read` shows what one would see.

There is no command for it yet.

## Not decided here

- **A container.** The specification defines none; neither does this crate.
- **Storing anything but packages.** The workspace still holds packages only
  (ADR 0004).
- **Heads of a registry's log**, which this implementation does not check
  yet, and which the relation specification leaves to claim registration.
