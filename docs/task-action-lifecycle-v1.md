# Task–Action lifecycle binding v1

Status: unreleased, additive repository profile. This document is not an
Internet-Draft and does not change the Direct-Agent v1 wire profile.

Stable product-profile identifiers and their English/Japanese conformance
mapping are maintained in the
[Human Coordination conformance registry](human-coordination-conformance-v1.md).
Identifier units, whitespace, case, and Unicode handling follow
[`human-coordination-field-semantics-v1.md`](human-coordination-field-semantics-v1.md).

This profile connects the persistent responsibility in [`pkg/taskcoord`](../pkg/taskcoord)
to the durable execution state in [`pkg/actionlifecycle`](../pkg/actionlifecycle).
The integration is implemented by
[`pkg/taskcoord/actionbinding`](../pkg/taskcoord/actionbinding). The two state
machines remain separate.

## Minimal model

```text
Participant ── Assignment ── Task
                    │
                    │ immutable Binding
                    ▼
                  Action ── lease / wait / recovery / outcome
```

An Assignment answers **who remains accountable for the Task**. An Action
answers **what execution is currently happening and what is durably known
about its result**. An Actor is the authenticated sender of one operation and
may differ from both the accountable Participant and the current executor.

The immutable Binding contains only:

- `task_id`;
- `assignment_id`;
- `action_id`; and
- `created_at`.

It does not copy `participant_id`, Participant kind or status, Assignment role,
authority, or Action owner. Those values are re-read from their authoritative
snapshots. This avoids stale or contradictory identity data.

## Binding creation

A Binding may be created only when all of the following are true:

1. the Assignment is valid and `ACCEPTED`;
2. a freshly verified `AuthenticatedOperation` authorizes this exact `ACCEPT`;
3. the Action is a valid revision-one `ACCEPT` snapshot whose transition stores
   that authorization's provenance, Assignment context digest, and final
   request digest;
4. `Action.owner_id` equals `Assignment.participant_id`;
5. Action acceptance does not predate Assignment acceptance; and
6. the Assignment snapshot, authenticated acceptance request, initial Action
   snapshot and transition, and Binding are committed in one application
   transaction.

The transaction compares the supplied Assignment revision, treats the initial
Action revision as zero, rechecks authorization freshness with its own clock,
derives `accepted_at`, and deduplicates the Action transition by `event_id`.
After locking the Assignment, it reconstructs the initial Action and Binding.
An in-process composition of two independent stores is not equivalent to this
atomic contract.

`ASB-HC-TA-001` fixes the Developer Preview cardinality at zero or one Action
per Assignment. A Task may have several Actions only through distinct
Assignments. `CommitAcceptance` must reject a second distinct Action for the
same Assignment atomically, without writing a partial Action, Binding, or
event. Supporting several Actions under one Assignment would require a new
profile version with listing and aggregate fulfillment semantics.

`actionbinding.AcceptanceRequestDigest` returns the versioned final digest for
this operation. It first derives `AcceptanceContextDigest` from the Assignment
ID and revision plus the trusted Assignment's `task_id`, `participant_id`,
`role`, `authority_digest`, and `status = ACCEPTED`. The lifecycle digest then
binds that context digest with `operation = ACCEPT`, `event_id`, `action_id`,
`action_digest`, the derived owner, and every recovery-policy field: `mode`,
`max_attempts`, and `idempotency_key`. `NewSnapshot` recomputes this final
digest, while the Store recomputes its Assignment context after locking the
current row. Changing any caller-selected Action field or replacing the
Assignment therefore invalidates the authorization. `accepted_at` is excluded
because `Store.CommitAcceptance` derives it from its transaction clock rather
than from the caller or Service.

Acceptance persistence keeps three values separate: the business identity
from `AcceptanceRequestDigest`, the complete verifier attempt identity from
`AcceptanceAttemptFingerprint`, and the first canonical committed `View`.
An exact retry of the same request and verifier attempt returns that original
result, including after the proof expires. An expired attempt cannot create
state. A different proof for the same business request returns
`ErrAcceptanceReconciliationRequired`; it does not replace the first proof or
result. Recovery after an uncertain result therefore requires retaining the
original authenticated attempt or entering an explicit reconciliation flow.

Both digest layers use the fixed-order, language-independent
[Action request transcript v1](action-transcript-v1.md). That profile defines
the primitive encodings, exact field order, absence rules, timestamp form, and
16 KiB bound. Machine-readable vectors fix the complete transcript bytes and
digests. The former field-ordered Go JSON form was unreleased and is not a
supported legacy encoding.

## Independent lifecycle decisions

No cross-lifecycle mutation is implicit:

| Observation | Allowed conclusion | Not implied |
| --- | --- | --- |
| Action is `SUCCEEDED` and Assignment is `ACCEPTED` | Assignment is eligible for a separately authorized `FULFILL` | Assignment is already fulfilled |
| Assignment is `RELEASED` or `REVOKED` | Application policy must decide what happens next | Action is canceled |
| Action is `WAITING` or `PAUSED` | Execution is not running | Assignment responsibility ended |
| Action is `ORPHANED` | Its executor lease expired | Action failed |
| Action is `INDETERMINATE` | Reconciliation is required | A terminal outcome is known |

`FulfillmentEligible` is a read-only predicate. It never calls TaskCoord
`FULFILL`. Release or revocation also leaves Action history unchanged, so a
deployment can reconcile effects before deciding whether to cancel, take over,
or record a terminal responsibility decision.

## Dependency waits

A Task may have multiple dependency groups. Groups are conjunctive, while the
edges inside a group use TaskCoord `ALL`, `ANY`, or `QUORUM` semantics.

`WaitForDependencies` performs these steps without adding a new Action state:

1. revalidate the current Binding, `ACCEPTED` Assignment, and `RUNNING` Action;
2. validate and canonicalize all active dependencies whose `from_task_id`
   equals the bound Task;
3. reject a wait if every group is already satisfied;
4. compute a domain-separated SHA-256 digest over the dependency topology,
   excluding mutable `satisfied` flags;
5. put the Action into ordinary `WAITING` with a derived `SIGNAL` condition;
6. return an immutable `DependencyWait` containing the Action revision, sorted
   dependency IDs, topology digest, and creation time.

The Action transition and `DependencyWait` must be committed atomically after
comparing the current Assignment, Action, and dependency rows.

`ResumeDependencyWait` re-reads the dependencies. It rejects changed topology
or an unsatisfied group. When the exact topology is satisfied, it creates a
deterministic evidence reference over the stored wait and current satisfaction
values, then applies the normal authenticated Action `RESUME`. The evidence,
Action transition, and immutable wait evidence must be committed through the
same application transaction boundary.

Dependency satisfaction is application state, not cryptographic proof. A
production adapter is responsible for authenticating and serializing updates
to dependency rows and for retaining the evidence addressed by the reference.

## Deadlock projection

`ProjectTaskLiveness` maps current linked Actions into the existing
`taskcoord.TaskLiveness` input:

| Action condition | Projection |
| --- | --- |
| `ACCEPTED`, `RUNNING`, or `CANCELING` | `Runnable` |
| validated Task dependency wait | blocked inside the dependency graph |
| time, availability, signal, or manual wait | `ExternalEscape` |
| `PAUSED`, `ORPHANED`, or `INDETERMINATE` | `ExternalEscape` |
| non-terminal Action with non-`ACCEPTED` Assignment | `ExternalEscape` for application resolution |
| all linked Actions terminal | `Terminal` |

Only a validated dependency wait is allowed to remove `ExternalEscape`. A
missing wait record, incomplete target graph, or progress source outside the
graph therefore cannot create a false-positive deadlock. The resulting view is
passed unchanged to `taskcoord.DetectDeadlockedTasks`.

## Durable documents and validation

The durable JSON shapes are:

- [`schemas/action-lifecycle-v1.schema.json`](../schemas/action-lifecycle-v1.schema.json)
  for complete Action snapshots; and
- [`schemas/task-action-binding-v1.schema.json`](../schemas/task-action-binding-v1.schema.json)
  for Binding and DependencyWait documents.

The `schemas` package exposes startup preparation and JSON shape validators for
both schemas. JSON Schema does not replace semantic validation: services must
also use the strict decoders and cross-snapshot functions in
`actionlifecycle` and `actionbinding`.

## Store boundary

`actionbinding.Store` is the minimum production persistence contract. Its
acceptance, execution-start/extension, dependency-wait, and dependency-resume
commits require one atomic database transaction or an equivalent primitive.
`CommitAcceptance` owns the transaction timestamp and returns the first
canonical committed `View`. It must persist the business digest, exact attempt
fingerprint, and canonical result in the same transaction as the Action,
Binding, event, and Assignment-to-Action index.
`CommitExecutionTransition` compares the complete `ACCEPTED` Assignment,
immutable Binding, and current Action in the same commit for `START`, `RESUME`,
`TAKEOVER`, and lease renewal. This prevents a concurrent Assignment release
or revocation from authorizing new execution through a stale read.
`CommitAuthorizedTransition` handles authenticated cancellation, terminal,
failure, and reconciliation mutations that may still be needed after
responsibility changes to settle already-started effects. It rejects execution
and trusted lease-expiry transitions, which have dedicated commit paths. The
integrated Store does not expose the generic `actionlifecycle.Store.Commit`
method.

Every mutation commit receives the original Event as well as the proposed
Transition. After locking the compared rows, a production adapter must apply
that Event to the stored current Action and require the complete derived
Transition to match before writing. This prevents a structurally valid next
snapshot from bypassing the state machine. For authenticated mutations, the
adapter must then use its transaction clock to reject a future transition
time, an expired authorization, or an expired current executor lease. A new or
renewed lease is also bounded by the authorization expiry.
`CommitTrustedLeaseExpiry` is the only unauthenticated mutation path and
derives expiry from the stored lease plus that same trusted clock. An exact
retry of a committed `event_id` is deduplicated only after the Event and
Transition pair has been revalidated.

`actionbinding.Service` is the intended application entry point. It loads the
current Binding, Assignment, Action, and dependencies through `Store`; callers
provide identifiers and verifier-created authenticated operations, not trusted
snapshots. `Service.Accept` validates the request shape, then delegates time
ownership, freshness, derivation, commit, and retry recovery to
`Store.CommitAcceptance`. The lower-level `actionlifecycle.NewSnapshot` also
rejects a missing or inconsistent acceptance authorization. The Service
rejects dependency WAIT or RESUME through the ordinary transition method, so
the topology checks cannot be bypassed accidentally.

`actionbinding.MemoryStore` is a concurrency-safe reference adapter. It tests
multi-record atomicity, CAS, event deduplication, and dependency TOCTOU
rejection under one process lock. It is not restart-durable and is not a
production database implementation.

This repository supplies the state machines, application service, reference
adapter, and Store contract. It does not claim a production database adapter,
replication, outbox delivery, or disaster recovery implementation.

## Security boundary

The Action state machine accepts only a projection of a freshly verified ASB
operation. Initial `ACCEPT` is included in this rule; the sole unauthenticated
transition is the trusted lease-expiry observation. Signature, token, policy,
TLS binding, nonce replay, and exact request-digest verification remain the
responsibility of the enclosing verifier/application adapter. A raw network
claim must not be converted directly into `AuthenticatedOperation`, even when
its fields appear to match an acceptance request.

The Binding contains no contact coordinates or public Human discovery data.
Human identity resolution and Email/SNS/TEL relay remain outside these
packages, as required by the Task Participant profile.

## Conformance checks

An implementation of this repository profile must demonstrate that:

- Binding creation rejects an unaccepted Assignment, a missing, stale, or
  request-mismatched `ACCEPT` authorization, a non-initial Action, or an
  owner/Participant mismatch;
- Action completion does not mutate Assignment state;
- Assignment release or revocation does not mutate Action state;
- execution start, resume, takeover, and lease renewal atomically reject a
  concurrently changed or non-`ACCEPTED` Assignment;
- each authenticated authorization binds the complete mutation and is still
  current at the Store transaction clock;
- every Store mutation reapplies the original Event to the locked current
  Action and rejects a mismatched or forged Transition;
- a future-dated transition and an executor mutation after lease expiry are
  rejected at commit;
- the initial `ACCEPT` transition retains authenticated provenance, its
  Assignment context digest, and its versioned final request digest;
- an exact acceptance-attempt retry returns the first canonical result even
  after proof expiry, while an expired new attempt creates no state and a
  different proof for the same business request requires reconciliation;
- only the trusted lease monitor can commit the sole unauthenticated
  transition, `LEASE_EXPIRED`;
- dependency wait and resume use current CAS snapshots and unchanged topology;
- `ALL`, `ANY`, and `QUORUM` are evaluated with multiple groups conjunctively;
- non-dependency waits are projected as external progress paths;
- strict JSON and Draft 2020-12 Schema validation both run; and
- the production store implements the documented atomic commits.
