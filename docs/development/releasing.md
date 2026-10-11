# Releasing

How a revision becomes a tagged release. Every release is the repository
owner's decision: a tag, a change of `publish`, a publication to a package
registry and a binary distribution each need it, every time. Nothing here
runs on its own.

What a release promises is in the
[compatibility policy](compatibility-policy.md). This page is how to keep
those promises.

## Between releases

- **CI compares the library API with the last tag.** The job *library API is
  compatible with the last tag* runs `cargo-semver-checks` on the five
  library crates against the most recent `v*` tag. It fails when a pull
  request breaks their API without the version bump that change needs.
- **A breaking change bumps the version in the same pull request.** Before
  1.0, Cargo reads `0.1.x` → `0.2.0` as breaking. Set the new version once,
  in `[workspace.package]` and in each `[workspace.dependencies]` entry of
  the root `Cargo.toml`, and run `cargo update --workspace`. Until the next
  tag, further breaking changes need no further bump. Say in the pull request
  what breaks and what a consumer changes.
- **An addition or a fix needs no bump in the pull request.** The release
  that ships it takes the next patch version.

`verified-workspace` and the `verified-cli` crate are not libraries for
others. They are not checked, and their API changes need no bump.

## Cutting a release

1. **Choose the version.** If the workspace version was already bumped since
   the last tag, that is the version. Otherwise it is the next patch
   version: bump it as above, in its own pull request.
2. **Check the revision.** It is a commit of `main` on which every CI job
   passed, required or not: the checks on three platforms, the published
   corpus, the offline build, the supply chain, the fuzz targets, and the
   API comparison. Run the corpus locally as well, if you hold it
   (`conformance/README.md`).
3. **Record what it was checked against.** The tag message names the
   `dekrops/wvp` commit the corpus job pins.
4. **Write the tag message.** Its first line is `verified-cli X.Y.Z`. Then:
   which protocol versions and drafts it implements; the pull requests since
   the last tag, with what each changes for a consumer; for a minor version,
   what breaks and how to adapt; and a line that nothing is published to a
   package registry, while that holds.
5. **Tag.** An annotated tag, `vX.Y.Z`, on that commit:
   `git tag -a vX.Y.Z <commit>`, then `git push origin vX.Y.Z`. Sign it if
   the owner has a signing key; no signing is configured for the project,
   and none is pretended.
6. **Tell the consumers.** Applications that exchange packages move their
   pins together (compatibility policy, "One pin for consumers that exchange
   packages"). Open an issue or a pull request where each records its pin.

A tag is never moved or deleted once pushed. A mistake is fixed by the next
release.

## Before any binary is distributed

No binary is distributed. A binary links third-party crates, and the
licenses of some require their notices to travel with it (`NOTICE`). Before
a first distribution:

- Ship `LICENSE`, `NOTICE` and `THIRD-PARTY-LICENSES.md` with the binary.
- `THIRD-PARTY-LICENSES.md` holds the license text and copyright lines of
  every crate a binary links, among them the BSD-3-Clause notices of the
  dalek crates. It is generated from `Cargo.lock` by `cargo-about`
  (`about.toml`, `about.hbs`), offline. The CI job *third-party notices
  match Cargo.lock* fails when it is out of date, so the file at a tagged
  commit matches that commit's dependencies.
- A dual-licensed crate is listed under the license chosen for it, the
  first of `about.toml`'s accepted list it offers.
- Crates that ship a `NOTICE` file of their own are not covered by the
  generated file. At `v0.1.1` no dependency ships one; check again before a
  first distribution if dependencies changed.

## Before anything is published to crates.io

Nothing is published, and `publish = false` holds for every crate. Before a
first publication the owner decides:

- **Whether the project is ready.** At the time of writing it was not: the
  repository was days old, the library API was still changing in most pull
  requests, and the protocols it implements are drafts. A useful bar: a few
  weeks of tags without breaking changes, a consumer that has used the API
  in earnest, and protocol drafts frozen at a version.
- **Who owns the crate names.** Publication claims the seven `verified-*`
  names permanently, for an account the project controls, not a person's.
  A published version can be yanked but never deleted.
- **What goes out.** Probably the five library crates first; the CLI
  crate only with the binary notices above settled.

Then, per crate: set `publish = true` for it alone; add `readme`,
`keywords`, `categories` and `documentation` metadata; publish in
dependency order (`verified-canonical`, `verified-protocol`,
`verified-contract`, `verified-work-unit`, `verified-verifier`, then the
others); and run `cargo publish --dry-run` before each.
