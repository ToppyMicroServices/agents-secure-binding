# Security Hardening Proposal: Runtime containment across service and process boundaries

## Decision

Choose how ASB owns Linux service identities, the runner socket, and Windows descendant
termination before enabling untrusted computation as an operated service.

## Executive Recommendation

Option 1, **shared service identity with post-start Job assignment**, is a useful low-risk
migration away from root but leaves the agent and runner in one OS account and leaves a small
Windows launch race. Option 2, **split service identities with fail-closed Job launch**, gives the
runner its own authority and assigns a Windows process to a per-run Job before it executes. I
recommend Option 2 for an untrusted-computation profile. Option 1 is acceptable only as an
explicit interim profile that does not claim strong cross-process isolation.

## Evidence

I inspected the two service units, the socket creation path, and both platform process helpers.
The absence of service identities and the direct-child Windows stop behavior drive this design.

| Evidence | Finding or document | What it establishes |
| --- | --- | --- |
| `ASB-HARD-001` | systemd service identity | Agent and runner units have no `User=` or `Group=`. |
| `ASB-HARD-002` | runner socket ownership | The runner forces its socket to `0600`, which binds access to one owner. |
| `ASB-HARD-003` | Windows process teardown | The helper kills only the direct process and names Job Objects as the missing descendant boundary. |

Sources: `init/systemd/agents-secure-binding-agent.service`,
`init/systemd/computation-runner.service`, `cmd/computation-runner/main.go`, and
`agent/algorithm/process_windows.go`.

## Current Design And Failure Mode

On Linux, the units inherit the service manager's default identity. The runner owns a private
socket, but there is no package-level account or ownership contract. Adding two users without
changing the socket would simply break connectivity. On Windows, stopping a computation can
leave grandchildren running with inherited handles or network access. The structural problem is
that execution authority and teardown ownership are not defined at the service and descendant
boundaries.

## Desired Invariants

- Neither long-running service runs as root in the normal software profile.
- Only the agent can invoke the runner socket; other local users cannot.
- Each computation and every ordinary descendant enter the same teardown boundary before
  untrusted code runs.
- Failure to create or join that boundary prevents the computation from starting.
- Service account, socket, and Job behavior are visible in qualification evidence.

## Constraints And Non-Goals

This change does not make an algorithm sandbox equivalent to a VM. The runner may still need
explicit device, network, or attestation access in selected profiles. Those capabilities must be
added to the service policy rather than inherited from root. Windows versions older than the
selected support floor are not assumed.

## Before Architecture

[Before architecture](../diagrams/runtime-containment-before.mmd) shows the missing identity
contract and the direct-PID teardown edge. The important edge is the dotted descendant path:
the current stop action does not own it on Windows.

## Options

### Option 1: Shared service identity with post-start Job assignment

Create one static `asb` account, use systemd `RuntimeDirectory=` and `LogsDirectory=`, and run
both services under that account. The existing `0600` socket continues to work. On Windows,
start the process, immediately create and assign a Job with
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, and fail if assignment is rejected.

The attractive part is migration simplicity. Existing file ownership and the private socket need
few changes. It removes normal root execution and contains descendants after assignment. The
principal weakness is that the agent and runner share all account-level files, and a child may
run between `CreateProcess` and `AssignProcessToJobObject`. This option should therefore be
labeled transitional. Rollback restores the units and direct process helper; any files written by
the service account need an ownership rollback step.

[Option 1 architecture](../diagrams/runtime-containment-shared-user-after.mmd)

| Change | Before | After | Security consequence | Cost |
| --- | --- | --- | --- | --- |
| Service account | manager default | one static `asb` user | removes routine root authority | package creates and owns directories |
| Windows teardown | direct PID | per-run Job after start | most descendants terminate together | small pre-assignment race remains |
| Socket | ad hoc owner, `0600` | same account, managed runtime dir | local users remain excluded | agent and runner are not separated |

### Option 2: Split service identities with fail-closed Job launch

Create `asb-agent` and `asb-runner` users and an `asb-runtime` group. A systemd socket unit owns
the runner endpoint as `0660`; only the agent and runner join the group. The runner accepts the
inherited listener instead of unlinking it. On Windows, a platform launcher creates the target
suspended, creates and configures a per-run Job, assigns the process, and only then resumes it.
The Job handle is retained until `Wait` completes and is terminated on cancellation.

This option makes the boundary explicit: compromising the agent does not automatically grant
runner file ownership, and a computation cannot execute before containment. It adds packaging,
socket-activation, and Windows launcher code. Standard streams, environment construction, exit
codes, cancellation, and nested-Job behavior require real Windows tests. Rollout should first
ship the accounts and socket unit disabled, migrate ownership, enable socket activation, and
then switch the services. Rollback keeps the old unit files available and restores ownership.

[Option 2 architecture](../diagrams/runtime-containment-split-identities-after.mmd)

| Change | Before | After | Security consequence | Cost |
| --- | --- | --- | --- | --- |
| Service identity | implicit/shared authority | separate agent and runner users | narrows compromise scope | packaging and ownership migration |
| Socket owner | runner-created `0600` | systemd-owned `0660` shared group | explicit caller allowlist | listener inheritance support |
| Windows launch | normal start | suspended, assign, resume | closes the descendant escape window | platform-specific launcher and tests |

## Comparison

| Dimension | Option 1 | Option 2 |
| --- | --- | --- |
| Security | improves root and descendant exposure, with shared-account and launch-race residuals | strongest boundary; adds socket manager and launcher to the trusted base |
| Performance | no expected steady-state hop; measure launch latency | socket activation and suspended launch add setup work; measure p95 start latency |
| Memory | one Job handle per active run | one Job handle per run plus service-manager socket state |
| Reliability | simpler ownership, but Job assignment can fail after start | fail-closed launch; more migration and platform failure modes |
| Operability | one account and directory policy | two accounts, group membership, socket unit, and Windows diagnostics |
| Migration | smaller change | staged package and ownership migration required |

## Recommendation

I recommend Option 2 because untrusted computation makes the pre-execution containment edge
material. If the near-term deployment is a single trusted-host preview with only trusted
algorithms, Option 1 can be shipped as a named transitional profile, with the launch race and
shared identity recorded as residual risks.

## Evidence Coverage And Residual Risk

| Evidence | Coverage | Residual risk |
| --- | --- | --- |
| `ASB-HARD-001` — service identity | addressed by both options | selected capabilities may still be broader than needed |
| `ASB-HARD-002` — socket ownership | preserved by Option 1; structurally addressed by Option 2 | group membership becomes security-sensitive |
| `ASB-HARD-003` — Windows descendant teardown | mitigated by Option 1; addressed by Option 2 | hostile code can still consume resources allowed by the Job limits |

Neither option replaces a VM, seccomp policy, Windows AppContainer, or confidential-compute
boundary. Job limits for CPU, memory, and active process count remain a separate policy choice.

## Migration And Rollout

Build account creation and directory ownership into packages rather than runtime shell code.
For Option 2, introduce socket activation while services still run under the old account, then
migrate one boundary at a time. Windows rollout starts in CI with a child/grandchild escape test
and then moves to a disposable supported host. A failed socket or Job setup must stop startup.

## Validation Plan

Test systemd ownership after install, upgrade, restart, and rollback. Verify that unrelated users
cannot connect and that the agent can. On Windows, launch a process tree that retains pipes,
cancel it, and prove all PIDs exit. Repeat under nested Job conditions. Record launch latency and
working-set delta against the current helper; no threshold is claimed until a deployment budget
is chosen.

## Implementation Work Packages

- Add sysusers/tmpfiles or equivalent package ownership and hardened unit settings.
- Add systemd socket activation and inherited-listener support for Option 2.
- Add the Windows Job launcher, handle lifetime, cancellation, and process-tree tests.
- Add install/upgrade/rollback and supported-Windows qualification cases.

## Open Questions

- Which Linux package formats and account names are supported?
- Must the agent and runner share any state beyond the Unix socket?
- Which Windows Server and desktop versions form the support floor?
- Which device and network capabilities does each production profile require?
