# Security policy

Keyorra stores passwords, so security reports get priority.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through GitHub:
[Security → Report a vulnerability](https://github.com/skensell201/keyorra/security/advisories/new).

Include what you found, how to reproduce it and which version you tested
(the release tag). You will get a reply within a few days. Once a fix is
released, the advisory is published and you are credited unless you prefer otherwise.

## Supported versions

Only the latest release receives security fixes.

## Scope

In scope: the macOS app, the Rust core, the browser extensions and "Keyorra for Safari".
The cryptographic design is described in
[docs/superpowers/specs/2026-10-02-lockbox-mvp-design.md](docs/superpowers/specs/2026-10-02-lockbox-mvp-design.md).

Out of scope: attacks that require an already compromised, unlocked Mac or a malicious browser
extension with full page access.
