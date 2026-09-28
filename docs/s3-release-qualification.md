# Linux S3 release qualification

This record concerns only the Linux, single-host, receipt-only S3 reader.
It does not promote the other ASB components or general AWS IAM optimization.
The reference runtime is Ubuntu 24.04 with systemd, one dedicated service user,
GitHub OIDC, the existing restricted AWS role and explicit synthetic S3 fixture.
The journal requires local storage that honors SQLite locks and fsync. Network
filesystems, simultaneous copied authorities and raw disk rollback are outside
the supported profile.

## Current evidence

| Gate | Recorded evidence | Limit |
|---|---|---|
| Reviewed implementation on main | [PR #62](https://github.com/ToppyMicroServices/agents-secure-binding/pull/62), signed merge `b12a55f4a34af8dccdbfbccad641b270bbf60def`; same tree as tested `f3c031544594c9616cef57220f7634bd445d0a2e` | A merge is not a release or deployment qualification |
| Regression, concurrency, storage faults, backup/restore, installed systemd lifecycle and two container boots | [Operational QA record](s3-operational-qa.md), 317 regression cases and 32 evidence checks | Controlled failures and shared-kernel boots do not certify physical power loss |
| Real OIDC/STS, allowed S3 read and outside-object denial | [AWS run 36246640700](https://github.com/ToppyMicroServices/agents-secure-binding/actions/runs/36246640700) | Explicit fixture only; no general IAM guarantee |
| Real product mTLS/ASB, retained receipt and sealed restore | [AWS run 36287447802](https://github.com/ToppyMicroServices/agents-secure-binding/actions/runs/36287447802) | Local test PKI and journal |
| Dedicated-user continuous operation and identity replacement | [15-minute run 36288991572](https://github.com/ToppyMicroServices/agents-secure-binding/actions/runs/36288991572), 32 reads, three idle process kills, 14 observed token changes | Bounded lab, not a long-duration leak claim |
| Real systemd + naturally expired OIDC + renewal without process restart | Opt-in gate implemented; execution result pending | Separate evidence is required; the offline projector is not a real issuer |

PR #62's required CI checks, Linux S3 conformance and CodeQL passed before
merge. Its macOS jobs were skipped. An explicit Linux-only workflow checks main
after merge. Results from later runs must identify their source and binary;
an earlier passing test must not be silently attributed to a changed binary.

## Promotion decision

The code is still preview while the reference integration result and target
acceptance remain incomplete. A finite lab cannot prove the absence of every
future leak. Use measured workload duration, history size, memory, descriptors,
disk growth and recovery results as bounded evidence, and set deployment
budgets from those measurements.

For a first deployment, record the actual host, filesystem, binary hash, issuer,
projector and backup destination. Exercise an authorized read after boot,
expired-token recovery, maintenance stop, emergency fencing and sealed restore
with old authority denied. Choose the observation period and resource limits
from the expected workload and operator response time. Preserve the signed
evidence and assign an owner for capacity alerts, certificate/token renewal,
backup checks and uncertain-outcome review. No target host has yet been supplied
for that acceptance work; the GitHub runner is a reference environment.

Physical power-loss certification is needed only for a claim covering the
specified host/storage under physical power loss. The current storage contract
assumes durable fsync and working SQLite locks; neither CI nor a process kill
verifies those properties for an organization's hardware. Do not imply such
certification or require it for unrelated claims.

Passing the reference gates supports a scoped release decision; it does not
by itself publish a version, set an organizational service-level objective,
or authorize a change to IAM, S3 objects or permanent execution history.
