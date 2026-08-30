# Security Policy

## Supported Scope

This repository publishes a supported v1 verifier product surface together
with experimental security-profile drafts, tests, vectors, and implementation
helpers. Security reports should target the current `main` branch and any
tagged release that remains within the support window documented in
`docs/API_COMPATIBILITY.md`.

## Reporting a Vulnerability

Report suspected vulnerabilities through GitHub private vulnerability reporting
for this repository. Do not open a public issue with exploit details, tokens,
keys, private logs, or working proof-of-concept material.

Please include:

- affected file, package, profile section, or test vector;
- expected security boundary;
- observed bypass, crash, downgrade, replay, or disclosure behavior;
- minimal reproduction steps when they can be shared safely;
- whether the issue affects profile text, implementation code, CI tests, or
  inherited Cocos runtime code.

The maintainer will triage whether the report is a profile issue, an
implementation issue, inherited runtime debt, or out of scope for this
repository.
