# Security policy

nepomuk stores secrets, so security reports are welcome and taken seriously. Note that the
project is still an early implementation that has **not been independently audited** (see the
[README](README.md)).

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report it privately through GitHub:
[Report a vulnerability](https://github.com/aleslanik2/nepomuk/security/advisories/new)
(Security tab → *Report a vulnerability*).

Please include, as far as you can:

- the affected version (`nepomuk version`) and platform,
- a description of the problem and its impact,
- steps or a proof of concept to reproduce it.

You can expect an acknowledgement within 7 days. Once a fix is ready, it is released together
with a GitHub security advisory, and you will be credited unless you prefer otherwise.

## Supported versions

Only the latest release receives security fixes. The file format may still change between
versions; see the README for migration notes.

## Scope

In scope: the `nepomuk` CLI, the GUI, the vault file format and its cryptography, the
installers (`install.sh`, `install.ps1`) and the release signing.

Out of scope: vulnerabilities that require an already compromised machine or user account,
and issues in third-party dependencies that are not exploitable through nepomuk (please report
those upstream).
