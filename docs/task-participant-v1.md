# Task Participant v1

Status: experimental, additive repository implementation. This document does
not define an IETF standard or claim interoperability with an external task
protocol.

A consolidated Japanese implementation specification is available in
[`task-participant-v1-spec-ja.md`](task-participant-v1-spec-ja.md).
Stable product-profile identifiers and the bilingual conformance mapping are
maintained in the
[Human Coordination conformance registry](human-coordination-conformance-v1.md).
The complete reference flow can be run locally with the
[Human Coordination debug-simple E2E](../examples/human-coordination-e2e/README.md).
Identifier units, whitespace, case, and Unicode handling follow
[`human-coordination-field-semantics-v1.md`](human-coordination-field-semantics-v1.md).

## Purpose

`pkg/taskcoord` represents a Human, Agent, or qualifying automated service as
a Task Participant that can accept bounded responsibility for progressing a
Task. It closes the application-model gap between a Human that merely starts
or approves work and a Human that actually receives, holds, completes, or
delegates an assignment.

The package deliberately keeps seven concepts separate:

| Concept | Meaning |
| --- | --- |
| Task Participant | Accountable Human or automated system |
| Task Assignment | Durable responsibility relation between Task and Participant |
| Actor | Authenticated caller that submits one protocol operation |
| Action state | Execution lifecycle such as RUNNING or WAITING |
| Executor lease | Short-lived permission for a runtime to effect an Action |
| Task dependency | Typed wait-for condition between Tasks |
| Interaction event | Immutable question, response, correction, or withdrawal |

A Human may be the Participant while a UI or gateway service is the Actor. An
ASB verifier must bind both identities and the concrete assignment; equality is
not assumed.

## Assignment lifecycle

```text
                 +------------ ACCEPT ------------> ACCEPTED
                 |                                    |  |  |
OFFER -> OFFERED +------------ DECLINE -----------> DECLINED
                 |                                    |  |  +-- FULFILL -> FULFILLED
                 +------------ REVOKE ------------> REVOKED
                                                      |  +----- RELEASE -> RELEASED
                                                      +-------- REVOKE  -> REVOKED
```

`DELEGATE` is an authenticated event on an `ACCEPTED` parent Assignment. It
atomically creates an `OFFERED` child Assignment and an immutable provenance
edge. The parent remains `ACCEPTED`; delegation does not silently transfer or
release accountability.

`WAITING`, `PAUSED`, `ORPHANED`, and execution outcomes are intentionally not
Assignment states. They belong to the Task or Action lifecycle.

Under `ASB-HC-CORE-004`, `OWNER`, `ASSIGNEE`, and `REVIEWER` are responsibility
labels, not permission grants. Assignee-owned transitions still require the
assigned Participant, while authority to offer or revoke comes from the
authenticated operation and verifier-local policy. Implementations must not
infer extra permissions from a role name.

### Human waiting example

When Agent A delegates work to Human B for completion tomorrow:

1. Human B's Assignment remains `ACCEPTED`.
2. The associated Task or Action becomes `WAITING` with a time or human-response
   resume condition.
3. No executor lease is retained while waiting.
4. A Human gateway later submits a freshly authenticated resume or completion
   operation with `participant_id = Human B` and its own distinct `actor_id`.

Passing a response deadline is not by itself Assignment failure, Action
failure, or executor orphaning. Escalation, reassignment, or pause is a policy
decision that must be recorded explicitly.

## Interaction and response events

Human latency, multiple answers, and corrections are represented by an
append-only interaction history, not by adding states to the Assignment
lifecycle. Each `InteractionEvent` binds an `interaction_id`, Task, Assignment,
authoring Participant, actual Actor, authorization and proof, timestamp, and
the digest of any referenced content.

Questions may be authored by either a Human or an automated Participant. The
event kinds are:

- `QUESTION`: starts a thread or asks a follow-up question;
- `RESPONSE`: replies to one question; multiple response events may refer to
  the same `in_reply_to` question;
- `CORRECTION`: supplies new content and names the author's earlier response or
  correction in `supersedes`; and
- `WITHDRAWAL`: retracts the author's earlier response or correction without
  deleting it.

`RESPONSE` and `CORRECTION` declare `INTERIM` or `FINAL`. Finality is the
author's assertion about that response version. It neither closes the shared
interaction nor changes, fulfills, or releases the Assignment. A later
correction may supersede a final response, and other Participants may still
append responses.

Under `ASB-HC-CORE-007`, a terminal Assignment does not close its interaction
history. Authorized questions, responses, corrections, and withdrawals may be
appended afterward for audit or reconciliation, but no interaction append may
change the terminal Assignment snapshot or revision.

Content is not stored inline by this package. `content_ref` locates it and
`content_digest` binds its exact bytes. A correction or withdrawal never
overwrites the prior event, so an auditor can reconstruct response provenance.
The in-memory Store requires relation targets to have been appended already,
which prevents cycles and cross-thread references.

As with Assignment operations, a Human may be the authoring Participant while
a Human-facing service is the Actor. `AuthenticatedInteraction` binds the full
event—including its relationships, finality, content reference, and digest—to
a fresh verifier result before it becomes an `InteractionEvent`.

## Agent discovery and Human reachability

`HUMAN` and `AGENT` share the `Participant` abstraction but are not the same
kind. `AgentDiscoveryRecord` accepts only an active `AGENT` Participant.
`MemoryAgentDirectory` resolves the Participant registry when a record is
registered and again when it is searched, so changing a serialized `kind` field
cannot place a Human in Agent search results. Automated services are not
silently coerced into Agents either.

Human matching is a separate, opt-in interface. `HumanMatchConsent` is scoped
to one:

- Human and Agent requester pair;
- opaque pairwise candidate identifier;
- purpose and capability;
- brokered `EMAIL`, `SNS`, or `TEL` channel;
- HTTPS contact-request relay; and
- validity window.

Queries require the exact requester, purpose, capability, and channel. They are
accepted as an `AuthenticatedHumanMatchQuery` carrying a fresh Actor,
authorization, proof, verifier nonce, and validity window. Wildcard queries are
rejected and results are bounded. `HumanMatchCandidate` exposes the pairwise
candidate identifier, capability, channel, relay reference, and expiry only. It
does not expose the Human Participant identifier, consent proof, Email address,
social account, or telephone number.

A broker-verified contact approval attributed to the Human produces a separate
`HumanReachabilityGrant`. The grant is bound to the requester, purpose,
capability, channel, and validity window and contains only an HTTPS relay
session reference. It omits both the Human Participant identifier and the
internal consent identifier. Approval Actor, authorization, and proof
identifiers remain broker-internal rather than requester-facing. This
trusted-internal projection does not by itself declare any of the Human ingress
assurance levels. Either the Human or the requesting Agent can append an
immutable grant revocation; withdrawing the underlying matching consent also
invalidates its grants.

Matching consent and a reachability grant authorize the scoped contact route
and contact metadata. They do not mean that the Human approved the exact
message content. The relay's ASB proof binds the Agent's exact request. A
deployment that requires Human approval of those bytes needs a separate
authenticated, Human-produced binding to the relay `RequestDigest`; that
approval statement is not implemented here.

Participant status is re-resolved when Human matches and active grants are
read. A Human that is no longer active is therefore omitted even when an older
consent or grant has not yet expired. Grant reads likewise require a fresh
`AuthenticatedReachabilityAccess` projection for the exact Agent requester and
scope; possession of a requester identifier alone is insufficient.

The relay must repeat this check under the same grant-scoped serialization
guard immediately before external dispatch. If revocation wins, a queued
intent becomes `CANCELED` and no provider callback occurs. If dispatch wins,
`DISPATCHING` is durable before that callback and revocation waits. An unknown
provider outcome remains `DISPATCHING` and is not retried blindly. A production
adapter needs a distributed lock with fencing or a gateway-consumed one-shot
permit to preserve this ordering across processes.

For Human Participants, `identity_ref` must be an opaque resolver reference;
public HTTP(S) profiles and direct-contact URI schemes such as `mailto:`,
`tel:`, `sms:`, and `sip:` are rejected. Interaction `content_ref` also rejects
the direct-contact schemes. This is a structural guardrail, not a complete
data-loss-prevention system: a production relay must still prevent raw contacts
from being embedded in HTTPS paths, message content, logs, or diagnostics.

Homepage or SNS publication is not represented as consent. A caller must
provide a separately verified `HumanMatchConsent`; the package does not crawl,
import, or infer permission from public contact information.

## Authenticated operation binding

`AuthenticatedOperation` is a projection of a freshly verified ASB result. It
binds:

- the accountable Participant;
- the actual Actor;
- authorization and proof identifiers;
- operation, Task, and Assignment identifiers;
- verifier nonce and validity window; and
- for delegation, the child Task, Assignment, and target Participant.

The package validates these bindings and transition invariants. It does not
verify tokens, signatures, or authorization policy itself.

Opaque authority digests cannot prove scope narrowing. Before `Delegate` is
called, an authorization component must verify the child authority against the
parent and produce a `VerifiedDelegation`. The state machine checks that the
verified parent and child digests match the committed Assignments.

## Automated services

An external API or Tool is not automatically a Task Participant. A deployment
should register an `AUTOMATED_SERVICE` only if it can accept assignments,
maintain or integrate with durable task state, authenticate result reporting,
and follow delegation policy. Those capabilities are deployment conformance
requirements, not facts inferred from the enum value.

## Dependencies and deadlock detection

`Dependency` represents only `Task --waits-for--> Task`. Delegation provenance
uses `DelegationRecord` and is never treated as a wait edge automatically.

Dependency groups support `ALL`, `ANY`, and `QUORUM`. `DetectDeadlockedTasks`
uses runtime liveness projections and treats timers, signals, Human responses,
and manual escalation as external escape paths. Unknown dependency targets are
also treated as possible external progress. The detector therefore reports
only deadlocks provable from the supplied graph; a directed cycle alone is not
sufficient.

## Store boundary

`Store.CommitAssignment` requires revision compare-and-swap, complete snapshot
persistence, and event deduplication in one atomic commit. Exact
deduplication compares the complete durable record; a retry made with a fresh
ASB proof is a different audit record and requires application-level outcome
reconciliation.

`Store.CommitDelegation` requires the parent event, child offer, delegation
record, and notification outbox entry to be committed atomically.

`Store.AppendInteractionEvent` requires exact event-ID deduplication and
append-only persistence. It must not modify the related Assignment snapshot or
revision. `ListInteractionEvents` returns raw append order and does not collapse
corrections or withdrawals into a mutable "latest response" view. Append order
does not establish which branch is authoritative when concurrent corrections
exist; that resolution belongs to application policy.

`AgentDirectory` and `HumanReachabilityDirectory` are separate application
boundaries. Neither is part of the Assignment `Store`. The in-memory directory
stubs exercise kind checks, pairwise binding, exact matching, expiry,
idempotency, and revocation, but do not implement a network directory or a
contact transport.

`NewMemoryReachabilityDirectory` uses the local wall clock.
`NewMemoryReachabilityDirectoryWithClock` is an additive reference-test path
for deterministic expiry checks and rejects a missing clock. Its clock must be
verifier-controlled and must never be selected from a peer request; it does not
add a caller-supplied time field to any profile.

`MemoryStore` is an in-process application stub that exercises these contracts.
It does not survive restart and is not evidence of database durability,
replication, failover, or outbox delivery.

`production.RedisTaskCoordStore` is a Redis/Valkey adapter candidate. It uses
Lua commits for revision CAS, event deduplication, delegation atomicity,
immutable Interaction append, and a transactional outbox. The outbox uses
bounded leases and at-least-once delivery semantics, so consumers must
deduplicate by event ID. It has been tested against a stateful TLS Redis
protocol test double; live Redis/Valkey execution, persistence, replication,
failover, backup, and recovery have not been qualified. When replica
acknowledgement is configured, an idempotent mutation retry writes a same-slot
replication barrier and runs `WAIT` on that connection before returning
success. This narrows an unknown-write recovery gap; it does not make
asynchronous replication linearizable or zero-loss.

## Current boundary

Implemented:

- Participant and Assignment models with cross-field validation;
- authenticated offer, acceptance, decline, release, revoke, fulfill, and
  delegation transitions;
- immutable delegation provenance with verified authority-digest bindings;
- authenticated immutable question, response, correction, and withdrawal
  events with reply and supersession lineage;
- Agent-only discovery records with registry binding checks;
- requester-scoped Human matching consent and privacy-minimized candidates;
- relay-only, purpose-bound Human reachability grants and immutable
  revocations;
- CAS and atomic delegation Store contracts;
- concurrency-safe in-memory Store stub;
- strict bounded JSON decoders;
- TLS 1.3/mTLS ingress for exact gateway-asserted-for-human offers,
  transitions, delegations, and interaction appends; delegation requires a
  configured deployment policy verifier;
- route-specific challenge/execute request validation and a response schema
  for the existing `201` challenge success, `200` execute success, and public
  error bodies;
- a Redis/Valkey TaskCoord adapter candidate with atomic state/outbox commits,
  bounded interaction history, and leased outbox delivery;
- a privacy-minimized Agent-to-Human relay profile that consumes one active
  reachability grant per intent, plus an in-process Mac/CI gateway sink;
- separate Action lifecycle and Task–Action binding packages that preserve
  Assignment responsibility while tracking durable execution state;
- typed dependency groups and conservative deadlock detection; and
- Draft 2020-12 JSON Schema for durable documents, with meta-schema, format,
  positive fixture, and privacy-negative validation in CI.

The Human ingress item above means that the authenticated gateway Actor submits
the exact request for a Human Participant under operation-authority and local
policy. It is not evidence of a Human-held signature, authenticated-Human
evidence, Human liveness, Human-facing UI confirmation, or legal consent. The
assurance vocabulary is defined by the
[Human request binding profile](asb-taskcoord-human-request-binding-v1.md#21-human-assurance-vocabulary).
Accepted Human ingress persists that verifier-derived pair on transition,
delegation, and interaction audit records. Legacy or trusted-internal records
may omit it; absence never implies Human assurance.

Not implemented or not yet qualified:

- live Redis/Valkey acceptance, persistence, replication, failover, backup,
  and recovery for the TaskCoord adapter;
- an outbox publisher and downstream delivery worker;
- general A2A/AGTP bindings or a transport for Participant discovery and Human
  matching;
- a network Participant, Agent discovery, or Human matching protocol;
- an encrypted contact vault, Email/SNS/TEL provider, abuse-monitoring service,
  or live Human delivery implementation;
- a relay-specific TLS challenge/execute endpoint or restart-durable relay
  Store;
- a production Action binding store or network Action ingress;
- Participant status-transition audit (`MemoryStore` registry records are
  immutable);
- cryptographic verification adapters for reachability consent, approvals, or
  authority-revocation inputs.

The implemented HTTP surface is limited to
`POST /v1/human-operations/challenge` and
`POST /v1/human-operations/execute`. Every response carries a server-generated
`X-Request-ID`. Error bodies retain the string `error` field and add `code`,
`retryable`, and `request_id`; raw internal errors are not returned. A `429`
response carries `Retry-After: 1`. An execute response with an unknown outcome
is not safe for automatic retry and requires reconciliation against trusted
state. The exact status/code table is in the
[Human ingress demo](asb-taskcoord-human-ingress-demo.md). Relay and Action HTTP
endpoints remain unimplemented.

The Agent-to-Human relay is documented separately in
[`agent-to-human-relay-v1.md`](agent-to-human-relay-v1.md). A provider
acknowledgement is transport state only; it is not a Human response or an
Assignment transition. The relay also distinguishes `CANCELED`, where
revocation won before any provider call, from `DISPATCHING`, where an external
effect may already have occurred.
