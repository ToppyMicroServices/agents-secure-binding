# Manager Runtime Notes

The Manager runtime is inherited implementation code. It is not the core
Direct-Agent verifier API for this repository.

Product-facing verifier work should start from:

- `pkg/clients`
- `pkg/atls`
- `pkg/atls/identitypolicy`
- `README.md`
- `PUBLICATION_TODO.md`

The Manager package remains useful for runtime experiments around VM launch,
attestation policy, and local service wiring. Do not use this package as a
source of normative profile behavior.

## Configuration

Current product-facing environment names:

| Variable | Purpose | Default |
| --- | --- | --- |
| `MANAGER_LOG_LEVEL` | Manager log level | `info` |
| `ASB_JAEGER_URL` | OTLP/Jaeger endpoint URL | `http://localhost:4318` |
| `ASB_JAEGER_TRACE_RATIO` | Trace sampling ratio | `1.0` |
| `MANAGER_INSTANCE_ID` | Stable instance identifier | generated when empty |
| `MANAGER_STATE_DIR` | Private VM state directory | `/var/lib/agents-secure-binding-manager` |
| `MANAGER_ATTESTATION_POLICY_BINARY_PATH` | Attestation policy helper path | `../../build` |
| `MANAGER_PCR_VALUES` | Expected PCR values | empty |
| `MANAGER_EOS_VERSION` | Expected runtime image version | empty |
| `MANAGER_MAX_VMS` | Maximum managed VM count | `10` |
| `MANAGER_CORIM_SIGNING_KEY` | CoRIM signing key path | empty |

Manager gRPC requires mTLS on every bind address, including loopback. Configure
`MANAGER_GRPC_SERVER_CERT`, `MANAGER_GRPC_SERVER_KEY`, and
`MANAGER_GRPC_CLIENT_CA_CERTS` before starting it. All RPCs, reflection, and health
checks use this transport. Only issue certificates from the configured client
CA to operators authorized to manage VMs. Generic runtime servers retain their
existing transport policy. The HTTP listener serves metrics and health and
should remain on loopback unless protected separately.

The service creates VM state with mode `0600` in a directory owned by its user
with mode `0700`. Existing state must meet these ownership and permission checks.
Symlinks in the state path, symlink or hard-linked state files, invalid IDs, and
filenames that disagree with the stored ID are rejected. The opened directory
is pinned for the service lifetime. Use a canonical path without symlink
components; on macOS this means `/private/tmp` or `/private/var` rather than the
`/tmp` or `/var` aliases. The systemd unit creates the default Linux state
directory. For an unprivileged manual run, set `MANAGER_STATE_DIR` to a private
directory owned by the service user.

The legacy `/tmp/agents-secure-binding` directory is no longer loaded. Migration
is manual: stop the Manager, establish the provenance of each legacy record and
its live VM process, and copy only verified records into the new private state
directory with the service user's ownership and mode `0600`. Do not adopt or
change permissions on an untrusted directory to make it pass validation. A
positive PID is required, but state validation does not prove process identity
or prevent PID reuse; verify live processes before restoring legacy records.
