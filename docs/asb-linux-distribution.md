# ASB Linux distribution scope

ASB is the Agent interaction and verification framework. The S3 reader is one
application profile. Its passing AWS tests do not qualify the CLI, discovery,
Human coordination, confidential-VM integrations or a complete installation.

This records the scope of the [local Debian candidates](asb-debian-packages.md)
and a future ASB-owned apt repository. No `.deb` or apt repository has been
published by this work. Start with Ubuntu 24.04/amd64;
support for other distributions or architectures needs separate installation
and runtime evidence. Existing Go module and supported API boundaries remain
unchanged.

## Actual delivery units

| Component | Source and current interface | Distribution boundary |
|---|---|---|
| Verification, request/session binding, policy and replay | `pkg/atls`, `pkg/clients`, `pkg/agtp`, `pkg/production` | Go SDK; compiled into the consuming application, not an invented standalone daemon |
| CLI and finite permission tools | `cmd/cli`, `cmd/asb-leastprivilege`, `cmd/asb-leastprivilege-proof` | Candidate `asb-tools`; preserves the existing command names |
| Domain discovery | `pkg/agtp/discovery`, `examples/agtp-agent-interaction` | Library plus diagnostic example; a service package needs a defined configuration and lifecycle contract |
| Human approval application | `cmd/asb-human` | Optional candidate `asb-human`; one trusted host/user, with its own persistent state |
| Generic Human TaskCoord, Action and relay | `pkg/taskcoord`, `pkg/actionlifecycle`, `pkg/humanrelay` | Go interfaces and selected adapters; do not package reference stores as production provider services |
| Restricted S3 execution | `cmd/asb-s3`, `packaging/s3` | Optional `asb-s3`; [candidate archive](s3-distribution.md) and its own qualification record |
| Runtime manager and helpers | `cmd/manager`, `cmd/computation-runner`, `cmd/egress-proxy`, `cmd/log-forwarder`, `cmd/attestation-service` | Optional runtime/image profile; inspect device, libvirt, filesystem and privilege requirements before installation |
| SNP, TDX and Cocos | `modules/attestation/snp`, `modules/attestation/tdx`, `integrations/cocos` | Independently versioned modules/integration; hardware and provider evidence remain separate |

The candidate `asb` metapackage depends only on the matching `asb-tools` version.
Optional services must not become automatically enabled merely because the
metapackage was installed. The Cocos Agent executable lives under
`integrations/cocos/cmd/agent`; the root `agent` directory is a library. The VM
image units under `init/systemd` are not a ready-made general apt installation.

## Package acceptance

Before shipping each executable package, record its source, linked module and
license inventory, binary hash, dependencies and supported platform. Use the
existing runtime tests for that executable and inspect the final `.deb`, not
only the staging directory. Verify on a clean Linux target:

- installation and documented first use, including missing/invalid configuration;
- upgrade, interrupted configuration and recovery, including nonzero CLI failures;
- removal and reinstallation without deleting user-owned keys or execution history;
- service stop, resource bounds and restart with existing state, where applicable.

Keep `/etc` configuration and `/var/lib` execution state distinct from packaged
program files. Do not initialize or reset an existing journal in a maintainer
script. Preserve revoked IDs, retained outcomes and `UNKNOWN` across upgrades.
Downgrading an executable does not authorize rolling back its database.

Debian packages must not install application files under `/usr/local`; the S3
candidate unit currently uses `/usr/local/bin/asb-s3`. A Debian-specific unit
using the packaged executable path therefore needs its own installation and
lifecycle check. Do not silently transfer the original unit's evidence.
See [Debian filesystem policy](https://www.debian.org/doc/debian-policy/ch-opersys.html#site-specific-programs).

The apt repository needs signed release metadata, an explicit `Signed-By`
keyring, a reviewed key-renewal process and a maintained update channel. APT
authenticates the repository hash chain; a detached signature beside a `.deb`
is not automatically checked as a package-level signature by apt-secure.
See [apt-secure](https://manpages.debian.org/trixie/apt/apt-secure.8.en.html).
Publish only after these checks and a concrete repository destination are
recorded. Each component keeps its own supported, preview or experimental
status; packaging does not change that status.
