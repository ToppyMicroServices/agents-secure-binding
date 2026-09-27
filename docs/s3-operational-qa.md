# Linux S3 operational QA

This is the test contract for the follow-ups to the 2026-09-27 static review,
tracked under Beads `asb-dik`. A listed test is **coverage prepared**, not evidence
that it has run. Qualification requires a successful Linux workflow, its source
commit, the tested binary hash, complete logs and the evidence manifest.

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

## Lab thresholds fixed before execution

The workflow uses Ubuntu 24.04, Go 1.26.6, a disposable local journal, and a
separate 32 MiB tmpfs for exhaustion. These are lab acceptance thresholds, not
an organization's service-level agreement.

- With 100,000 retained records, measure 100 fresh executions per monitoring
  condition. Report p95/p99/max; require p99 <= 1 second and max <= 5 seconds.
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
