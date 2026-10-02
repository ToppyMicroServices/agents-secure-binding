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
| Diagnostic and recovery candidate | Signed commit `1b971fb9f73e9cc46906dd3db79a0c150aa70ec8`, [PR #63](https://github.com/ToppyMicroServices/agents-secure-binding/pull/63); required CI and CodeQL passed | This candidate's live systemd result is recorded separately below |
| Regression, concurrency, storage faults, backup/restore, installed systemd lifecycle and two container boots | [Operational QA record](s3-operational-qa.md), 317 regression cases and 32 evidence checks | Controlled failures and shared-kernel boots do not certify physical power loss |
| Diagnostic sink recovery, blocked output and CLI failure classification | [Linux run 36591300814](https://github.com/ToppyMicroServices/agents-secure-binding/actions/runs/36591300814), 338 regression cases including subtests, race detector, 32 evidence checks | Bounded fault tests; no long-term leak claim |
| Real OIDC/STS, allowed S3 read and outside-object denial | [AWS run 36246640700](https://github.com/ToppyMicroServices/agents-secure-binding/actions/runs/36246640700) | Explicit fixture only; no general IAM guarantee |
| Real product mTLS/ASB, retained receipt and sealed restore | [AWS run 36287447802](https://github.com/ToppyMicroServices/agents-secure-binding/actions/runs/36287447802) | Local test PKI and journal |
| Dedicated-user continuous operation and identity replacement | [15-minute run 36288991572](https://github.com/ToppyMicroServices/agents-secure-binding/actions/runs/36288991572), 32 reads, three idle process kills, 14 observed token changes | Bounded lab, not a long-duration leak claim |
| Extended dedicated-user operation | [45-minute run 36437065955](https://github.com/ToppyMicroServices/agents-secure-binding/actions/runs/36437065955), 92 reads, three idle process kills, 44 observed token changes | Same limits as the 15-minute lab; it does not run the systemd unit |
| Real systemd + naturally expired OIDC + renewal without process restart | [Run 36711947746](https://github.com/ToppyMicroServices/agents-secure-binding/actions/runs/36711947746) passed at `1b971fb9`; two completed reads, one retained UNKNOWN, same process after renewal, cleanup passed | GitHub OIDC and the explicit fixture; no organization deployment claim |

PR #62's required CI checks, Linux S3 conformance and CodeQL passed before
merge. Its macOS jobs were skipped. The
[Linux-only run 36438643745](https://github.com/ToppyMicroServices/agents-secure-binding/actions/runs/36438643745)
also passed on the merge commit. Results from later runs must identify their source and binary;
an earlier passing test must not be silently attributed to a changed binary.

Run 36591300814 tested GitHub's PR merge commit
`cee4eec1a0e5842ccc9cd75debe6729212bb7bcc`. Its source tree was independently
compared with signed head `1b971fb9f73e9cc46906dd3db79a0c150aa70ec8` and matched.
All 15 recorded file hashes and the additional diagnostic regression results
were checked after downloading the artifact. Its binary SHA-256 was
`89bf3f2030a1a4cedc847003a1b94b23511267809d99bbc09ed8e29e0ba279b4`.
The recovered sink preserved eight lost events in its suppression count, and
the blocked-sink shutdown test completed in 1.01 seconds. This run did not call
AWS. At the maximum-count configuration, startup used 2,340,700 KiB RSS;
connection-load FDs returned from 77 to their baseline of 13. These are separate
fixtures and must not be combined into a single maximum-workload claim.

## Qualified reference candidate — 2026-09-30

Run 36711947746 checked out signed source
`1b971fb9f73e9cc46906dd3db79a0c150aa70ec8` directly. Its Linux gates passed
338 regression cases including subtests under the race detector, vet, lint,
storage fault recovery, installed-unit lifecycle and two container boots.
All 32 offline evidence checks and 15 file hashes were independently verified.
The real AWS gates used that run's Linux binary, SHA-256
`2cbe370f759d7f5cb7da2b19b2057d7f26b540bde05b6e330a478eea55420c19`.
It identifies Go 1.26.6, Linux/amd64 and that source revision. Its build metadata
also records `vcs.modified=true`; the workflow creates an untracked evidence
directory before building. This record identifies the tested bytes and does
not claim a clean-VCS or reproducible release build.

AWS CLI 2.36.49 returned `ExpiredTokenException` as JSON with exit code 254,
360 seconds after the token's `exp`. The adapter retained that provider code and
normalized it to `ExpiredToken`. This confirms the compatibility path in this
run. Earlier failed requests did not preserve their provider code, so their
exact cause cannot be established retrospectively from this result.

The runner then replaced the token atomically. Without restarting the installed
service, a separately authorized read succeeded, the old operation still
conflicted, and its UNKNOWN state and the first receipt remained intact.
The service retained its dedicated nonroot identity and zero effective Linux
capabilities. Service stop and private-file cleanup passed. The preceding
allowed/outside-object checks, product restart with AWS acquisition disabled,
sealed restore, retired-authority denial and new restored read also passed.
The downloaded AWS reports matched the source and binary above; 38 independent
consistency checks passed and hashes of all 11 AWS evidence files were retained.
The local verification record is
`build/qa-product-20260930/run-36711947746/qa-report.json`.

This is the first passing live systemd expiry/renewal result. It completes the
reference integration gate tracked by `asb-dik.13`; diagnostic sink recovery
and blocked-output tests also passed, completing `asb-dik.14`.

## Earlier operations evidence

The 45-minute run executed source `f3c031544594c9616cef57220f7634bd445d0a2e`
for 2,702.65 seconds. Its binary SHA-256 was
`8adaf84d789adfe171a011385dde2c5ead1b68b191d245b53d57388b46857014`.
The downloaded Linux artifact's 15 hashes and 32 evidence checks passed; the
AWS reports identified that same source and binary. Sampled maxima were
26,776 KiB RSS, 12 descriptors and 4,106,928 journal bytes. The oldest receipt,
sealed restore, retired-authority denial and newly authorized restored read
all passed. Runner private-file cleanup also passed. These results do not
establish unbounded retention or absence of long-term leaks.

## Promotion decision

The reference integration gates now pass for the candidate identified above.
The [S3 distribution candidate](s3-distribution.md) packages these exact tested
bytes separately from the ASB module, with a manifest and verification procedure.
The S3 reader remains a current-branch preview: no versioned S3 distribution or
organization deployment acceptance has been published here. These release and rollout
steps are separate from the passing reference tests. A finite lab cannot prove
the absence of every future leak. Use measured workload duration, history size,
memory, descriptors, disk growth and recovery results as bounded evidence, and
set deployment budgets from those measurements.

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
