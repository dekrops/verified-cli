# Security

Verified CLI reads untrusted files and checks signatures. Reports of ways
to make it accept, misreport or mishandle input are welcome.

## Reporting

Please report privately, through GitHub's **Report a vulnerability** on this
repository's Security tab. Do not open a public issue for a suspected
vulnerability. Include the input that triggers the behavior and the version
(`verified --version`) where you can.

No response time is promised yet: the project is pre-release and has no
security team. This file will state one when that changes.

## What counts

- A package that is reported as established, consistent or not refused when a
  protocol check should have refused it.
- Two inputs with different meaning that yield the same digest or identifier,
  short of a SHA-256 collision.
- A crash, hang, unbounded memory use or file-system effect caused by input.
- Output that states more than was checked.

## What the tool does not claim

It is not audited, certified or production-hardened. The protocol it
implements is a draft. A package that verifies says nothing about whether its
sources told the truth. See [the threat model](docs/security/threat-model.md).

## Supported versions

Releases are tags; nothing is on a package registry. Fixes land on `main`
and in the next tag. Only the latest tag is supported: a fix is not
backported to an earlier one.
