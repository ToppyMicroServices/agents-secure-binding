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

## Prepare an authenticated apt snapshot

`scripts/asb-apt-repository.py` prepares repository metadata and signs a local
snapshot. It does not publish it or install trust on a client. It requires
Python, `dpkg-deb`, GnuPG and `gpgv` on Linux. The signing input must match a
successful lifecycle record for those exact package bytes, source and version.
A successful record is evidence for review, not an independent release approval.

```sh
created=$(date +%s)
expires=$((created + 604800))
python3 scripts/asb-apt-repository.py prepare \
  --artifacts build/debian-candidates --lifecycle build/debian-lifecycle.json \
  --created "$created" --expires "$expires" --output build/apt-snapshot
python3 scripts/asb-apt-repository.py sign \
  --repository build/apt-snapshot \
  --gnupg-home /absolute/private/asb-release-gnupg \
  --signer APPROVED_EXACT_SIGNING_KEY_FINGERPRINT
python3 scripts/asb-apt-repository.py verify \
  --repository build/apt-snapshot --keyring /absolute/approved/asb-archive.gpg \
  --signer APPROVED_EXACT_SIGNING_KEY_FINGERPRINT
```

Replace the key paths and fingerprint with the approved release key. The
fingerprint is the complete uppercase 40-character fingerprint of the exact
signing key or subkey. The signer requires an explicit private GnuPG home; it
never selects a default identity or replaces existing signatures. Production
key custody, offline backup, access approval and revocation remain operator
choices. CI generates unrelated one-day test keys in a temporary home and
destroys that home after the check. It never uses a personal or production key.

The unsigned `Packages`, compressed index, SHA-256 by-hash objects and `Release`
are deterministic for the supplied packages and times. OpenPGP signatures have
their own creation times. Metadata validity is capped at seven days, and signing
and verification reject expired or future-dated metadata. Renewal requires a
fresh reviewed snapshot before expiry; an outage beyond that date deliberately
blocks apt updates. Choose a shorter window if the publishing operation can
reliably renew it. Do not disable expiry checks to mask an outage.

The verifier requires both `InRelease` and `Release.gpg` to match the exact
`Release`, an independently selected signing fingerprint, the complete package
inventory and deterministic metadata. It rejects changed packages, extra files,
symlinks, duplicate JSON fields, unknown signers and invalid signatures. The
manifest's lifecycle hash binds the supplied evidence bytes; it does not attest
to a trusted builder or prove wider product qualification.

## Configure a client and rotate keys

After selecting a real HTTPS destination, generate a deb822 source:

```sh
python3 scripts/asb-apt-repository.py source \
  --uri https://YOUR_APPROVED_APT_HOST/asb >asb.sources
```

An administrator installs the approved, fingerprint-checked public keyring as
`/etc/apt/keyrings/asb-archive.gpg` with mode `0644`, and the reviewed source as
`/etc/apt/sources.list.d/asb.sources`. Export OpenPGP public key bytes with
`gpg --export-options export-minimal --export`; a GnuPG keybox is not an apt
keyring. Directories must also be searchable by `_apt`. The generated source
uses `Signed-By` for this repository and enables date and expiry checks. It does
not add trust globally or set `Trusted: yes`. These choices follow Debian's
[apt-secure documentation](https://manpages.debian.org/trixie/apt/apt-secure.8.en.html)
and [source configuration](https://manpages.debian.org/trixie/apt/sources.list.5.en.html).

For planned rotation, deliver an A+B public keyring through the organization's
authenticated configuration channel while A still signs current metadata. Check
both fingerprints against the approved record. After clients have that keyring,
publish a fresh B-signed snapshot. Verify their update results, then replace the
keyring with B alone. The Linux check proves that A-only clients reject B before
the overlap, that A+B clients can upgrade with B, and that B-only clients reject
A afterwards. Clients that missed the overlap need an authenticated keyring
update; do not recover by disabling signature checks. If A is compromised, an
A-signed delivery alone cannot authenticate B: use the independent recovery
channel and remove A promptly.

Publish immutable package/by-hash objects before the corresponding signed
metadata, and retain objects referenced by any unexpired snapshot. The current
helper deliberately refuses to update an existing snapshot in place. The
selected host must provide atomic metadata replacement, HTTPS, access logging
without credentials, rollback recovery and monitoring before public delivery is
qualified. After publication, retrieve the current snapshot's declared files
and both signatures into a fresh directory, then use the same verifier. Retained
older objects belong to older snapshots and are outside that verification set;
passing the accumulated mirror directory to the strict snapshot verifier will
reject those extra files. An old but still valid signed index can be replayed within its validity window;
this tooling does not provide a client-side monotonic release counter. Normal
apt upgrade does not automatically downgrade installed packages, but that does
not protect a fresh client from such a replay.

## Exercise apt authentication and upgrades on Linux

The Debian workflow builds `0.1.0~preview.1-1` from the previous merged revision
`b8fd28939a7385a1dab66317d085d58755df0209`, using that revision's builder in a
separate clean checkout. It builds `0.1.0~preview.1-2` from the candidate checkout.
The gate requires the initial commit to be an ancestor of the candidate, distinct
source trees, matching package provenance and different Human executable hashes.
Both candidates must pass their Linux package lifecycle checks before the
upgrade runs. A full-history candidate checkout is required for the ancestry
check. The earlier same-source package-revision test is historical evidence;
it does not satisfy this gate.

For a matching local Linux setup, place the clean historical checkout at
`build/upgrade-baseline`, build its candidates with an absolute output path,
and run:

```sh
python3 scripts/test_asb_apt_repository.py
python3 scripts/test_check_asb_apt.py
python3 scripts/check-asb-apt.py \
  --initial build/debian-candidates --initial-lifecycle build/debian-lifecycle.json \
  --upgrade build/debian-upgrade --upgrade-lifecycle build/debian-upgrade-lifecycle.json \
  --initial-source b8fd28939a7385a1dab66317d085d58755df0209 \
  --upgrade-source "$(git rev-parse HEAD)" \
  --source-checkout "$PWD" --initial-checkout "$PWD/build/upgrade-baseline" \
  --output build/apt-lifecycle.json --image ubuntu:24.04
```

A disposable Linux container with network access disabled installs from signed
local repository snapshots. The old executable creates a real Human receipt
and database. The gate checks the installed executable's SHA-256 against its
package inventory both before and after the upgrade, preserves the state and
file modes, and recovers the old receipt with the new executable. The current
Human database remains schema 1; this is not a Human schema-migration test.
Source commits and executable hashes can differ solely because of build
provenance even when the Human implementation is unchanged. The report records
whether `cmd/asb-human` or `internal/humanapp` changed and makes no broader
behavior-change claim from a binary hash alone.

A separate test-only probe exercises changed TaskCoord storage code. The same
`scripts/fixtures/taskcoord-upgrade/main.go` is compiled against each clean
module checkout, with `GOWORK=off` and source-directory checks. The old probe
creates a real schema-1 database through that revision's public APIs, including
an Assignment and its immutable retry history. The new probe opens that database
through the candidate APIs, requires schema 2 and the new reachability/quarantine
tables, and verifies unchanged Participant, Assignment and state-blob hashes.
This demonstrates the selected TaskCoord schema 1→2 migration. It is separate
from the packaged Human application's database and does not certify other
migration paths. Both probes are synthetic authorization fixtures; no external
Human approval or provider is involved.

The gate also requires apt and the independent verifier to reject unsigned metadata,
unknown or retired keys, signature/index/package changes, expired metadata and
future-dated metadata. Each rejected apt update starts with an empty list/cache,
so stale successful results cannot satisfy the negative check. The report
records exact source commits/trees, package and executable hashes, the observed
database versions, image identity, test key fingerprints and phases. Probe source,
implementation-file and binary hashes identify both builds; the probe has
`buildvcs=false` and is explicitly a test helper, not a distribution executable.
Its adjacent `apt-lifecycle.evidence` directory preserves the signed metadata
and public test keyrings with recorded hashes, along with both probe binaries,
their shared source and build record. Combine each metadata tree with
its matching candidate packages at the manifest's pool paths to repeat signature
and byte verification before metadata expiry; the private test keys are not kept.

This does not test a live HTTPS host, every previous release or a running-process
upgrade. Processes are stopped before package replacement and reopened afterwards.
The S3 state check uses an operator marker. No service is activated, and no host
packages or AWS resources are changed. The
production key, authenticated client key distribution, hosting destination and
post-publication verification remain unqualified until selected and exercised.
