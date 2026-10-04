# Local ASB Debian candidates

These packages distribute existing ASB programs. They do not install a generic
ASB daemon or replace the Go SDK. Building packages does not change the supported
API or preview status recorded in `API_COMPATIBILITY.md`.

| Package | Installed commands | Scope |
|---|---|---|
| `asb` | none | Metapackage depending only on the same version of `asb-tools` |
| `asb-tools` | `agents-secure-binding-cli`, `asb-leastprivilege`, `asb-leastprivilege-proof` | Existing runtime client and finite permission tools |
| `asb-human` | `asb-human` | Optional local approval preview for one trusted OS user |
| `asb-s3` | `asb-s3` | Optional restricted S3 reader candidate |

Commands are installed under `/usr/bin`. Documentation, linked-module notices
and `inventory.json` are under `/usr/share/doc/<package>`. No package creates a
user, changes IAM, starts a service, initializes a database, or installs files
under `/etc`, `/var/lib` or `/usr/local`. There are no maintainer scripts.

Packaged documentation links to included examples at their installed locations;
links to unshipped source files use the exact build revision on GitHub. Source
build and repository-relative test commands still require a source checkout.
The S3 examples include the deployment acceptance template.

The CLI includes optional runtime and attestation commands. Their configured
services, hardware, Cocos integrations and `igvmmeasure` remain separate
requirements; installing `asb-tools` does not provision them. The finite tools
run locally and do not modify cloud policies.

## Build from a reviewed source revision

Use Linux amd64, initially Ubuntu 24.04, with Python 3.10+, Git, Go 1.26.6 and
`dpkg`/`dpkg-deb`. The builder does not need root. Go may download its pinned
toolchain and dependencies through the configured proxy. It performs no cloud
or provider operations. Start from a clean checkout and use an output directory
outside the source tree or under its ignored `build` directory.

```sh
python3 scripts/build-asb-deb.py \
  --source-commit "$(git rev-parse HEAD)" \
  --version 0.1.0~preview.1-1 \
  --maintainer 'Your package maintainer <maintainer@example.invalid>' \
  --output build/debian-candidates \
  --with-human --with-s3
```

Replace the example maintainer with the responsible package maintainer. The
version identifies the Debian distribution candidate; it does not change the
Go module version. Omit the optional flags to build only `asb` and `asb-tools`.
The output directory must not exist. An interrupted or rejected build may leave
partial artifacts there; only a complete `debian-candidates.json` plus passing
validation qualifies a candidate for review.

The builder uses `CGO_ENABLED=0`, checks every binary's Linux/amd64 ELF layout
and rejects dynamic-linker segments. It checks embedded source and toolchain
metadata, copies the linked dependency notices, and inspects each final `.deb`
for exact bytes, modes, ownership and control files. `SHA256SUMS` records the
final package hashes. These are local integrity records, not authenticated apt
repository metadata.

Every executable is newly built. In particular, the S3 package **does not inherit
the previous AWS-qualified archive's binary or systemd evidence**. Its unit is
only a documentation example under `/usr/share/doc/asb-s3/examples`; it uses
`/usr/bin/asb-s3`. Provision its dedicated user, PKI, issuer/projector, private
configuration and durable state deliberately before installing or enabling a
unit. The older S3 runbook's `/usr/local/bin` build/install step does not apply
to this Debian executable. Target-specific service and real-AWS qualification
remain separate.

## Inspect and exercise the final packages on Linux

```sh
python3 scripts/test_build_asb_deb.py
python3 scripts/check-asb-deb-lifecycle.py \
  --artifacts build/debian-candidates \
  --output build/debian-lifecycle.json \
  --image ubuntu:24.04
```

The lifecycle helper needs Docker on Linux. It requires the `asb-human` and
`asb-s3` candidates as well as the default packages, and installs them only in
a disposable container. It records the resolved image ID and repository digest.
The tag is mutable, so retain those recorded identities with the result or use a
digest-pinned image. No ASB packages are installed on the host.

The helper checks installation, unpack/configure separation, documented local
commands, missing configuration rejection, removal, purge and reinstallation.
It retains a real local Human database, keys and receipt state across package
replacement and removal. It does not test an upgrade from a different released
schema, systemd activation, an external runtime, real AWS, or indefinite operation.

Use normal user privileges when running `asb-human self-test` or the interactive
approval app after installation. `agents-secure-binding-cli --help` may create
its existing per-user cache directory. Neither that cache nor application state
belongs to the package file list, so package removal must preserve it.

An apt repository, signing-key distribution, release approval and ongoing update
channel are not created by these scripts. Publish only the reviewed bytes after
their Linux checks and the selected component qualification have passed.
