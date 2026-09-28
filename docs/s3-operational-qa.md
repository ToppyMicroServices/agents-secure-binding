# Linux S3 operational QA

This records the implementation and bounded Linux validation of the follow-ups
to the 2026-09-27 static review, tracked under Beads `asb-dik`. The successful run
below covers these tasks. Target-deployment qualification remains separate.

| Beads | Change or decision | Required evidence |
|---|---|---|
| asb-dik.2 | Drain maintenance requests; retain authority lease; emergency cgroup fencing | Active SIGTERM and SIGKILL, durable uncertainty, one dispatch, installed unit lifecycle |
| asb-dik.3 | Read-only snapshot status; lightweight health; separate integrity check | Writer-lock coexistence, cancellation/recovery, 100,000 retained records, latency with/without monitoring |
| asb-dik.4 | Limit 64 accepted connections before TLS; retain 8-handler gate | Saturation/close/reconnect, FD/goroutine recovery, sampled RSS |
| asb-dik.5 | Recover marked private backup workspaces under exclusive lock | Process kill at created/snapshot/sealed/published boundaries; legacy snapshot preservation; hard-link accounting |
| asb-dik.6 | Check cancellation between 64 KiB copy/hash chunks; admin deadlines | Large sparse-file restore SIGTERM/SIGINT, incomplete-store rejection, context-canceled backup |
| asb-dik.7 | Bounded stage diagnostics and isolated journal retention | Identity/STS/S3/persistence errors, generic HTTP, secret exclusion, output cap |
| asb-dik.8 | Explicit enablement and projector readiness/ordering | Installed unit enabled; two systemd container boots with authenticated ASB |
| asb-dik.9 | Qualify stop, crash, process group and identities | Unit drain/emergency, child termination, PrivateTmp cleanup, projector renewal, retired certificate/key denial |
| asb-dik.10 | Qualify capacity and fault recovery | Real tmpfs ENOSPC, kernel write-size failure, lock cancellation, WAL release, retained uncertainty and fresh execution |
| asb-dik.11 | Measure configured resource bounds | Maximum-count configuration startup, connection cycles, post-load recovery; backup/copy tests above |
| asb-dik.12 | Retain conservative pre-dispatch UNKNOWN | [Recorded decision and operator procedure](least-privilege-s3-product.md#operator-diagnostics-and-state-classification) |

## Verified Linux run — 2026-09-28

[Run 36360418600](https://github.com/ToppyMicroServices/agents-secure-binding/actions/runs/36360418600)
passed at source commit `9d9c716ffc75ee3b2eedecb7b7906249d2b3422c` on Ubuntu 24.04
with Go 1.26.6. GitHub verified the commit signature. The run passed 317 regression
cases including subtests under the race detector, vet, lint, product binary
backup/restore, and all offline operational gates. All 32 evidence checks passed.
The downloaded artifact's 15 file hashes were independently checked.

Tested binary SHA-256:
`441eb739e903a46ef322c11ab3c6673fc256f6a61f5c832823477f4fff185227`.

| Measurement or check | Observed result |
|---|---|
| 100,000 retained records; baseline execution latency | p95 1.951 ms; p99 3.566 ms; max 4.230 ms |
| Same history with monitoring | p95 2.845 ms; p99 3.983 ms; max 4.181 ms |
| Monitoring and concurrent backup | p95 3.494 ms; p99 4.404 ms; max 6.290 ms; backup 679 ms |
| Storage after workload | 100,300 operations retained; sampled WAL peak 48,574,832 bytes; free space 90,448,023,552 bytes |
| Maximum-count startup | 4,096 mandates, 256 permissions, 20 grants; 15.755 s; RSS 2,153,032 KiB; 13 FDs |
| Three connection cycles, 128 clients each | FDs 13 → 77 → 13; sampled RSS 18,848 → 18,940 KiB; cycles completed in 90 ms |
| Active maintenance stop | Bare process 2,133 ms; installed systemd unit 2,164 ms; one adapter invocation |
| Emergency stop and restart | No automatic service reactivation; no redispatch; cgroup and PrivateTmp checks passed |
| Backup interruption | Created, snapshot, sealed and published boundaries passed; existing snapshots remained readable |
| Restore interruption | SIGTERM and SIGINT stopped a 1 GiB fixture copy before completion; incomplete stores remained unusable |
| Storage failures | Actual tmpfs ENOSPC and kernel file-size write failure recovered; uncertain effects, revocations and replay history remained retained |
| Identity renewal | Projected token replacement, retired client CA/proof-key rejection and new proof acceptance passed with fabricated local identity |
| Boot recovery | Two real systemd container boots accepted authenticated ASB requests; consumed authority was not redispatched |

The maximum configuration used about 2.05 GiB RSS in this run. Plan host memory
from that measurement and workload headroom; the small connection fixture's RSS
is not the maximum-configuration memory requirement. The 90 ms connection run
and sampled RSS demonstrate bounded short-load behavior, not a long soak test.
A bare SIGKILL retained its private temporary identity directory; installed-unit
cleanup passed. Use the documented systemd lifecycle for supported deployment.

Evidence is available in the run artifact `asb-s3-linux-36360418600` (seven-day
GitHub retention). The working copy also retains the downloaded artifact under
`build/qa-implementation-20260928/run-36360418600/` and its independent hash check
in `build/qa-implementation-20260928/artifact-verification.json`. No real AWS
request or AWS resource change was part of this offline run. The existing live
AWS gate and deployment-specific issuer expiry/recovery remain separate.

## Lab thresholds fixed before execution

The workflow uses Ubuntu 24.04, Go 1.26.6, a disposable local journal, and a
separate 32 MiB tmpfs for exhaustion. These are lab acceptance thresholds, not
an organization's service-level agreement.

- With 100,000 retained records, measure 100 fresh executions without monitoring, with
  monitoring, and with monitoring plus a concurrent backup on a separate
  connection. Report p95/p99/max; require p99 <= 1 second and max <= 5 seconds.
  A sealed backup must finish within 60 seconds. Report journal, WAL and free
  bytes; a pinned reader must release WAL for checkpoint without losing IDs.
- Load 4,096 mandates, 256 permissions and 20 grants within the existing input
  byte limits. Require startup within 120 seconds, sampled idle RSS <= 3 GiB
  and idle FDs <= 64. This covers maximum counts with the fixture's string
  lengths, not every combination of maximum-size inputs or traffic.
- Run three cycles of up to 128 local idle TCP clients. Accepted connections
  are capped at 64; require FD growth <= 66 and return to baseline +2 within
  8 seconds. Sampled RSS growth must stay <= 128 MiB during load and <= 64 MiB
  afterward. Go may retain heap arenas; RSS need not return to its exact baseline.
  In-process connection tests separately count goroutines over 100 cycles.
- The two-second local STS stub must finish during maintenance, with one
  invocation and one uncertain record. SIGKILL cannot produce a confirmed
  result. The installed unit must not automatically restart after an explicit
  emergency stop. Ordinary CLI cancellation and copy cancellation have a
  three-second lab response budget. Kernel-uninterruptible I/O is excluded
  from that bound and must retain the authority fence until it actually stops.

For deployment capacity planning, keep permanent execution/revocation history.
Provision database + WAL + a full temporary snapshot + the chosen retained
backups. Start with an alert when free space is below 20% **or** below two current
database sizes plus the measured WAL high-water mark, whichever alerts earlier;
adjust from the target's growth rate and operator response time. This is an
initial planning rule, not a universal capacity guarantee. The tests do not set
or delete production history to satisfy it.

## Evidence boundaries

The offline qualification uses fabricated local PKI, tokens and a controlled
CLI stub. It does not call AWS. `AccessDenied` from that stub represents a known
fixture, not evidence of AWS policy behavior. Live OIDC/S3 is the separately
authorized workflow gate, with the existing private fixture and no IAM changes.

`systemd-analyze verify`, an installed unit on the GitHub host, and two actual
systemd boots inside a disposable `systemd-nspawn` container are separate tests.
The container shares the host kernel. Neither a container boot nor process kill
is physical power-loss qualification, a reboot of the GitHub runner, or a test
of an organization's target host/storage/issuer.

The write-size fault is a real kernel file-write failure (RLIMIT_FSIZE), not a
simulation of all device EIO/fsync failures. tmpfs ENOSPC verifies space-failure
handling but not persistent-media power loss. Short resource measurements do
not establish absence of long-term leaks. Missing/failed tests and all these
target-environment gaps remain explicit; they must not be reported as passed.

The product remains preview until the target deployment's acceptance work is
complete. No result in this lab authorizes retries of UNKNOWN, IAM expansion,
or deletion of the retained AWS role, policies, fixture objects or journals.
