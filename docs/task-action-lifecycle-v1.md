# Task–Action lifecycle binding v1

Status: unreleased, additive repository profile. This document is not an
Internet-Draft and does not change the Direct-Agent v1 wire profile.

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
2. the Action is a valid revision-one `ACCEPT` snapshot;
3. `Action.owner_id` equals `Assignment.participant_id`;
4. Action acceptance does not predate Assignment acceptance; and
5. the Assignment snapshot, initial Action snapshot and transition, and
   Binding are committed in one application transaction.

The transaction compares the supplied Assignment revision, treats the initial
Action revision as zero, and deduplicates the Action transition by `event_id`.
An in-process composition of two independent stores is not equivalent to this
atomic contract.

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
binding, dependency-wait, and dependency-resume commits require one atomic
database transaction or an equivalent primitive whose isolation preserves the
checked revisions and dependency rows. The embedded
`actionlifecycle.Store` retains complete snapshot CAS and event deduplication
for ordinary Action transitions.

`actionbinding.Service` is the intended application entry point. It loads the
current Binding, Assignment, Action, and dependencies through `Store`; callers
provide identifiers and authenticated events, not trusted snapshots. It also
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
operation, except for trusted lease-expiry observations. Signature, token,
policy, TLS binding, nonce replay, and exact request-digest verification remain
the responsibility of the enclosing verifier/application adapter. Raw network
claims must not be converted directly into `AuthenticatedOperation`.

The Binding contains no contact coordinates or public Human discovery data.
Human identity resolution and Email/SNS/TEL relay remain outside these
packages, as required by the Task Participant profile.

## Conformance checks

An implementation of this repository profile must demonstrate that:

- Binding creation rejects an unaccepted Assignment, a non-initial Action, or
  an owner/Participant mismatch;
- Action completion does not mutate Assignment state;
- Assignment release or revocation does not mutate Action state;
- dependency wait and resume use current CAS snapshots and unchanged topology;
- `ALL`, `ANY`, and `QUORUM` are evaluated with multiple groups conjunctively;
- non-dependency waits are projected as external progress paths;
- strict JSON and Draft 2020-12 Schema validation both run; and
- the production store implements the documented atomic commits.
