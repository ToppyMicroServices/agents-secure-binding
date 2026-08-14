# Action lifecycle v1 repository profile

Status: unreleased, additive repository implementation. This document is not
an Internet-Draft and does not modify the Direct-Agent v1 wire profile.

`pkg/actionlifecycle` implements a transport-independent state machine for
durable, asynchronous Actions. It adopts the useful ROS Action split between
goal acceptance, execution feedback, cancellation, and terminal result, but it
does not add a ROS or DDS dependency. An HTTP, messaging, or local binding can
store and expose the same snapshots and transition records.

The durable JSON shape is fixed by
[`schemas/action-lifecycle-v1.schema.json`](../schemas/action-lifecycle-v1.schema.json).
Go validation is authoritative for cross-field and transition invariants that
JSON Schema cannot fully express.

## Semantic invariants

These distinctions are mandatory in this repository model:

```text
WAITING       != INDETERMINATE
ORPHANED      != FAILED
timeout       != FAILED
lease expiry  != cancellation
```

- `WAITING` means execution is not currently running because a known external
  condition has not yet been satisfied. It stores that condition durably and
  releases the executor lease.
- `PAUSED` means execution was deliberately suspended by an authenticated
  operation or recovery policy. It has no active executor lease.
- `ORPHANED` means a `RUNNING` or `CANCELING` executor lease expired. It says
  nothing about the Action's outcome.
- `INDETERMINATE` means an external effect may have occurred but the outcome is
  unknown. It always carries unresolved reconciliation state and no terminal
  outcome.
- `FAILED` is allowed only for a known execution failure with a structured
  error code, or when authenticated reconciliation proves failure.

A timeout is classified by what is known:

| Observation | State | Required durable data |
| --- | --- | --- |
| Scheduled time has not arrived | `WAITING` | `TIME` plus absolute `not_before` |
| Target is busy | `WAITING` | `TARGET_AVAILABLE`, target, and `probe_after` |
| Server is unavailable before dispatch | `WAITING` | `SERVER_AVAILABLE`, target, and `probe_after` |
| Operator or policy suspends work | `PAUSED` | checkpoint when required by recovery policy |
| Dispatch may have reached the effecting system, but the response timed out | `INDETERMINATE` | reconciliation record |
| Active executor lease expires | `ORPHANED` | last fencing generation and checkpoint, when available |
| Execution returned a known application error | `FAILED` | application error code |

The state machine rejects `FAIL` with `TIMEOUT` or `TRANSPORT_TIMEOUT`. A
deployment must select `WAIT`, `PAUSE`, or `MARK_INDETERMINATE` from the facts
above rather than treating every timer expiry as failure.

## State model

```text
ACCEPTED -- start --> RUNNING
   |                    |  \
   |                    |   +-- wait ----------------> WAITING
   |                    |   +-- pause ---------------> PAUSED
   |                    |   +-- cancel request ------> CANCELING
   |                    |   +-- known result --------> SUCCEEDED / FAILED
   |                    |   +-- unknown effect ------> INDETERMINATE
   |                    |   +-- lease expiry --------> ORPHANED
   |                    |
   +-- cancel ----------+----------------------------> CANCELED

WAITING / PAUSED -- authenticated resume + new lease --> RUNNING
CANCELING -- known completion / cancellation ------------> terminal result
CANCELING -- unknown effect ------------------------------> INDETERMINATE
CANCELING -- lease expiry --------------------------------> ORPHANED
ORPHANED -- authenticated, policy-allowed takeover -------> RUNNING
ORPHANED -- reconcile-before-resume ----------------------> INDETERMINATE
INDETERMINATE -- proven terminal effect ------------------> terminal result
INDETERMINATE -- proven NO_EFFECT ------------------------> PAUSED
```

`SUCCEEDED`, `FAILED`, and `CANCELED` are terminal. `INDETERMINATE` is not a
terminal result: it is an unresolved state from which authenticated
reconciliation must establish a terminal effect or `NO_EFFECT`.

Cancellation preserves ROS Action-style race handling. A cancel request made
while work is running changes the state to `CANCELING`; if a successful result
was durably committed first or is then authoritatively reported, `SUCCEEDED`
can still win. An ambiguous cancel/effect race becomes `INDETERMINATE`.

## Durable resume conditions

Resume conditions are data, not in-process timers:

```json
{
  "type": "TIME",
  "not_before": "2026-08-10T09:00:00+09:00"
}
```

```json
{
  "type": "TARGET_AVAILABLE",
  "target": "service:target-a",
  "probe_after": "2026-08-09T18:10:00Z"
}
```

```json
{
  "type": "SERVER_AVAILABLE",
  "target": "https://worker.internal.example",
  "probe_after": "2026-08-09T18:10:00Z"
}
```

`TIME` can resume once the stored timestamp is reached. Availability,
dependency, manual, and signal conditions require an authenticated resume
event with an evidence reference. Reaching `probe_after` authorizes a probe; it
does not by itself prove availability.

Because `WAITING` and `PAUSED` have no executor lease, an Action waiting until
tomorrow does not become `ORPHANED` overnight. Resumption always acquires a new
finite lease and increments the fencing generation.

## Owner, executor lease, and takeover

`owner_id` is immutable durable responsibility for the Action. It is separate
from the executor currently permitted to perform work.

An executor lease contains:

- a unique lease ID;
- the authenticated executor ID;
- a monotonically increasing generation used as a fencing token;
- an issue time; and
- a finite expiry time.

`RUNNING` and `CANCELING` require an active lease. Executor mutations present
the exact lease ID, executor ID, and generation. Lease renewal extends the same
fenced lease. A fresh start, resume, or takeover increments the generation, so
a delayed mutation from a previous executor is rejected even after takeover.

Only a trusted lease monitor/store observation may apply `LEASE_EXPIRED`, and
only after the stored expiry. The transition removes the active lease and
makes the Action `ORPHANED`; it does not create a failure or terminal outcome.

Takeover is allowed only from `ORPHANED`. The new operation must be freshly
authenticated and bind all of:

```text
actor_id
authorization_id
proof_id
operation = TAKEOVER
action_id
action_digest
verifier_nonce
issued_at
expires_at
```

The actor must be the new executor, and the lease must use the next fencing
generation. The accepted operation is a minimal projection produced after ASB
verification; raw peer claims are not sufficient. Every other externally
requested state mutation uses the same event-specific authenticated binding.
The single exception is the trusted, time-based `LEASE_EXPIRED` observation.

## Checkpoint and recovery policy

A checkpoint contains a strictly increasing sequence, a canonical SHA-256
payload digest, an immutable storage reference, and its creation time. The
state machine never assumes that an opaque reference exists or is valid; the
deployment must verify checkpoint storage and access policy before takeover.

One immutable recovery policy is selected at acceptance:

| Policy | Takeover behavior |
| --- | --- |
| `RESUME_FROM_CHECKPOINT` | Direct takeover requires a stored checkpoint. |
| `RESTART_IDEMPOTENT` | Direct takeover is allowed only with the policy's durable idempotency key. |
| `RECONCILE_BEFORE_RESUME` | Direct takeover is rejected; reconciliation must prove the prior effect first. |
| `MANUAL` | Authenticated takeover also requires an evidence reference for the manual decision. |

All policies have a positive maximum recovery-attempt count. Exhausting it
does not make the Action `FAILED`; further takeover is rejected until an
operator or application-specific policy creates a separately authorized
resolution.

## Reconciliation

`MARK_INDETERMINATE` records `REQUIRED` reconciliation. An authenticated
reconciler advances it to `RUNNING`, performs an authoritative lookup against
the effecting system, and resolves it with an evidence reference as one of:

- `SUCCEEDED`;
- `FAILED`;
- `CANCELED`; or
- `NO_EFFECT`.

The first three produce a known terminal outcome. `NO_EFFECT` produces
`PAUSED`; a separate authenticated `RESUME` then acquires a new lease. This
separation prevents reconciliation from silently becoming a retry.

## Persistence contract

`Store.Commit` is a compare-and-swap durability boundary. Before acknowledging
a mutation, an implementation must atomically:

1. compare the expected snapshot revision;
2. persist the complete next snapshot; and
3. append or deduplicate the transition by `event_id`.

Acceptance uses the same rule with expected revision zero. Each snapshot is a
complete recovery record; an implementation must not rely on process memory,
an open connection, or a local timer to reconstruct lease, wait,
reconciliation, checkpoint, or outcome state.

The package intentionally supplies the contract and pure state machine, not a
database adapter. A deployment chooses a store whose transaction, replication,
backup, and availability properties meet its failure model. An in-memory store
does not satisfy the production durability requirement.

The additive [Task–Action binding profile](task-action-lifecycle-v1.md) defines
the application transaction that joins an accepted TaskCoord Assignment to an
initial Action and projects dependency waits to TaskCoord deadlock detection.
It does not merge the Assignment and Action state machines.

## Validation and compatibility

`Snapshot.Validate` enforces cross-field invariants, canonical
`sha256:<lowercase-hex>` digests, finite leases, monotonic fencing state,
terminal outcome consistency, and state-specific lease/resume/reconciliation
presence. `DecodeSnapshot` rejects unknown members, trailing JSON, invalid
UTF-8/control characters, unsupported enums, and documents larger than 1 MiB.

This package is additive and currently outside the supported Direct-Agent v1
API list. It does not change existing tokens, TLS binding, replay behavior,
`pkg/production`, or the protected-change consumer. A transport binding,
database implementation, event streaming format, and HTTP status resource are
separate application decisions.

Run its focused tests with:

```sh
go test -race -count=1 ./pkg/actionlifecycle
```
