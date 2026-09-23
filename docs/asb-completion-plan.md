# ASB implementation completion

Working plan, 20 September 2026. The inspected main revision is
`41e37c018c34744fcca45a6f9581c77e03366224`; the GitHub main reference was checked
on this date. This document does not change a supported API or declare a new
production profile.

Split-Knowledge is one application of ASB. ASB's implementation and integration
evidence should stand on their own. Application disclosure policy, privacy
accounting and recruiting semantics remain in the application. The immediate
implementation target is the software-only path; optional hardware and managed
cloud qualification retain their existing separate status.

## Current evidence and remaining work

| Area | Confirmed implementation | Completion gap |
| --- | --- | --- |
| Identity and exact request binding | Core verification and software-only profiles; TLS-based Human ingress and local approval app | Preserve these gates in every new integration; verification success alone does not authorize application effects |
| Bounded automatic execution | Prior mandate, finite-model verification, authenticated execution and a single-host durable journal | This is a separate application profile, not the generic Human Coordination transaction owner |
| TaskCoord | Redis/Valkey mutation/outbox adapter; shared SQLite Human mutation, replay, outcome and outbox transactions | Managed-backend and delivery-provider qualification remain separate |
| Task–Action binding | Shared SQLite implementation of the complete Store contract, using current TaskCoord Assignments in the same transaction | External execution dispatch still requires an application adapter and qualification |
| Human relay | Scoped contact, dispatch/revocation ordering and unknown-provider-outcome rules | Reference store and local sink; durable provider reconciliation is not implemented |
| Required CI | Main's required `product-security` status and a separate bounded Human red-team job | The required job previously omitted `strictjson`, `operationjournal` and independent Python transcript checks; this work connects them through the shared Make target |
| Research evaluation | Separate component regression pilot and a proposed comparison protocol | No single integrated human-decision/delegation/effect experiment or participant study |

The local approval application already has SQLite-backed approval and recovery.
The least-privilege TaskCoord adapter already has `DelegateAndCommit` and
`ReconcileDelegation`. The new SQLite adapter closes the generic Human ingress
persistence/recovery gap for the bounded single-host deployment. It does not reuse the separate
applications' results as proof of broader integration.

## Implementation order

### 1. Make bounded Human checks part of the required gate

Reuse the declared Human red-team package set in the ordinary Human gate and
have main CI's required `product-security` job run that target. Include the
independent transcript verifier. Keep extended fuzzing optional; a long fuzz
campaign is not a prerequisite for this increment.

Validate the Make expansion, workflow syntax, Python vectors and the actual
race-test gate. Local checks do not establish that a new commit has passed
hosted CI or merged. Do not close the broader `asb-ljs.15` production scope
based on this coverage change alone.

Local verification on 20 September 2026 passed all six independent Python
transcript/context checks and all 13 packages in `make human-coordination-gate`
with `-race -count=1`. The run used cached Go 1.26.6 on macOS arm64,
`GOWORK=off`, a temporary build cache and disabled module downloads. Loopback
permission was needed for real TLS tests. Workflow syntax passed actionlint.

A separate 5-second Human ingress fuzz smoke passed 17,609 executions, including
recovery request seeds. This is bounded parser evidence, not exhaustive fuzzing.
Scoped static checks for TaskCoord, Action binding, the SQLite adapter, Human
ingress and schemas passed with zero issues using the cached golangci-lint
v2.11.1 source. Hosted CI, main integration and release have not been performed
for this patch.

### 2. Complete generic Human ingress outcome recovery

Implemented for Assignment offer, transition, delegation and interaction. The
selected transaction owner is `pkg/taskcoord/sqlitestore`. It retains replay,
mutation, outbox and exact first response together. Operation identity is the
existing EventID; recovery binds the original request digest in a separate,
freshly authorized `OPERATION_RECOVER` request. Current Human and gateway Actor
must match the original scope. Recovery cannot mutate or replace provenance.

The real mTLS integration drops responses after committed mutations, replaces
the process-facing server and database handle, and retrieves the first response
with a fresh proof after the original proof has expired. Separate subprocess
and injected-write-failure tests verify no partial records around commit.

### 3. Implement the shared durable Task–Action boundary

Implemented all methods in `pkg/taskcoord/actionbinding.Store` on SQLite.
Every transaction reconstructs current Assignments from the authoritative
TaskCoord state. Only immutable historical acceptance Views retain older
Assignments. Shared database serialization protects current-assignment checks
against concurrent revoke/start, resume, takeover and renewal commits.

Tests cover restart, independent processes, both revoke/start orderings,
canonical acceptance, dependency waits and resume, expired leases and unknown
outcome reconciliation. The [adapter guide](taskcoord-sqlite-store.md) records
the supported limits, backup behavior and execution boundary.

Dispatch must then have an explicit ownership and reconciliation boundary.
Persisting `RUNNING` cannot prove that an external callback took effect. A
revocation that completes before a later dispatch must prevent that dispatch;
a revocation cannot undo an earlier external effect.

### 4. Qualify the selected deployment and document its supported surface

Local subprocess termination, restart, backup/restore, outbox fencing and
unknown-outcome persistence have been exercised for the selected SQLite
adapter. Deployment qualification still needs the actual filesystem and
operational controls. Multi-host failover and an external executor/provider
are outside this increment. Retain original operation IDs and unresolved
outcomes when integrating an authoritative query adapter.

Only after this evidence exists should the selected profile receive an API
compatibility and deployment declaration. Keep unsupported optional capabilities
explicit. Real delivery-provider qualification applies if delivery is selected;
hardware attestation, KMS/HSM and managed-provider HA retain their separate
deployment-specific decisions.

The production-readiness increment now supplies dedicated-user systemd units,
Windows Job Object descendant teardown, offline credential and bootstrap-token
rotation, verified SQLite snapshot export and an evidence-bundle harness. The
checked-in target profiles fail when mandatory checks are unavailable or the
source tree is dirty. These are implementation prerequisites, not completed
real-environment qualification. Windows now creates computation processes
suspended and resumes them only after Job assignment. Positive qualification
claims require a detached OpenPGP signature from an explicitly trusted full
fingerprint. Archive verification binds the digest and SQLite checks to one
stable snapshot, and export refuses to replace an existing destination.
Snapshot export does not reclaim online capacity; verified tombstone compaction
still needs a selected archive and retention policy.

## Independent application and paper evidence

Use a disposable maintenance-setting workflow as the initial non-Split-Knowledge
application. The existing local approval app is useful for exact-action and
stale-review behavior, but approving there immediately applies the setting. It
does not already implement the generic Assignment/Action/dispatch composition.

For a comparative experiment, both the ASB composition and the strong reference
receive the same current policy and revocation history. Both use exact-action
approval, persistent operation IDs and evidence-based recovery. Report legitimate
completion as well as refused invalid requests. Equal outcomes are valid; an
advantage cannot be manufactured by withholding current state from the reference.

The first bounded scenarios are current approval, stale approval, revocation
racing with dispatch, and a process crash after an externally recorded effect
but before its receipt. The independent scorer may inspect the controlled
effect ledger; the application may learn outcomes only through its configured
query adapter. Human understanding or reduced burden requires separate evidence
from participants.

## Tracking boundary

Existing work remains tracked by `asb-ljs.8` (durable coordination), `asb-ljs.5`
(broader outcome/recovery contract) and `asb-ljs.15` (required protocol gate and
qualification). `asb-vdf.2`, `.3` and `.4` concern hardware, managed-provider HA
and managed signing respectively. Their open states do not establish a defect
in the already supported software-only profile.

Completion of a local increment, hosted CI, main integration, a release and a
qualified deployment are separate checkpoints. This increment completes the three requested software implementation and local
verification items. External dispatch, selected deployment qualification and
release remain separate stages; the production conformance claim stays false.
