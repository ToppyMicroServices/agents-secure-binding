# Human Coordination production profile v1

Status: unavailable. This document defines the evidence required for a future
production claim; it is not evidence that this repository is production-ready.

The machine-readable source for profile identifiers, requirement identifiers,
implementation status, and test mappings is the
[Human Coordination conformance manifest](../testdata/human-coordination-conformance-v1.json).
The readable bilingual mapping is in the
[Human Coordination conformance registry](human-coordination-conformance-v1.md).

## Capability-based claim

Production conformance is declared per capability. Conformance to
`asb.human-coordination.core/v1` does not imply either Task–Action execution or
Agent-to-Human delivery. A declaration must name only the capabilities that are
deployed and qualified.

The production profile's static manifest dependency is core. Additional
Task–Action, relay, HTTP, or matching profiles are claim selections named in the
declaration, not unconditional profile dependencies.

The following are separate claims:

| Capability | Required profile | Current repository evidence |
| --- | --- | --- |
| Task Participant and TaskCoord state | `asb.human-coordination.core/v1` | In-memory reference behavior; Redis/Valkey candidate tested against a protocol test double |
| Human TLS ingress | `asb.human-coordination.http/v1` | Repository-local TLS 1.3/mTLS implementation and tests |
| Task–Action binding | `asb.human-coordination.task-action/v1` | In-process reference Store only |
| Agent-to-Human relay | `asb.human-coordination.relay/v1` | In-process Store and local gateway sink only |
| Production overlay | `asb.human-coordination.production/v1` | Unavailable; live qualification and production adapters are incomplete |

The separate [local approval application](local-human-approval.md) implements
a browser workflow and a real SQLite transaction for one local setting. Its
replay records, approval, effect and original response share one transaction.
This is application-level recovery evidence; it does not implement the generic
TaskCoord, Task–Action or relay production adapters listed above.

Human matching is an optional capability. A deployment that does not provide
matching can still implement Human assignments through an already established,
consent-scoped gateway. A deployment that does provide matching must declare
and test that capability separately.

## Open stable-release decisions

Before any Human Coordination wire or Go surface receives a compatibility
promise, the following contracts remain to be decided:

1. how Human ingress derives the `OperationID` used by `pkg/operationjournal`
   from `event_id` or a separate identifier, and atomically stores its
   reservation, status-readable result, and TaskCoord mutation;
2. which production component owns the authoritative transaction spanning the
   selected TaskCoord, operation-journal, outbox, Task–Action, and relay records;
3. if a relay HTTP ingress is added, its public error, retry, and reconciliation
   contract; and
4. the exact Go packages and interfaces, profile IDs, JSON Schemas, and HTTP
   envelopes that receive semantic-versioning and migration guarantees.

These decisions do not change the current Developer Preview behavior. Until
they are recorded, the affected surfaces remain outside the supported API.

## Required declaration

A production declaration must be a versioned artifact that contains:

- the exact Human Coordination profile IDs and requirement IDs claimed;
- each selected optional capability and each explicitly unsupported capability;
- implementation and deployment versions, immutable source revision, and build
  provenance;
- deployment realm and policy identifier without accepting a peer-controlled
  realm value on Human Coordination documents;
- the Human assurance level derived from the selected verified profile, never
  a caller-controlled assertion;
- durable Store, replay, outbox, journal, vault, and provider adapter identities;
- qualification environment, dates, test artifacts, and evidence digests;
- recovery objectives, operational limits, monitoring, and responsible runbook;
  and
- every remaining exception, expiry date, and accountable owner.

A generic statement such as “Human Coordination production-ready” is not a
conformance declaration.

## Qualification gates

Before a selected capability is claimed for production, its live deployment
must demonstrate the following properties where they apply.

### Durable TaskCoord state

- atomic Assignment, delegation, Interaction, deduplication, and outbox commits;
- persistence across restart and process replacement;
- replication and failover behavior under acknowledged and unknown writes;
- backup creation, restoration, and integrity verification;
- event conflict handling and exact retry reconciliation; and
- outbox lease expiry, poison-record handling, redelivery, and consumer
  deduplication.

The current Redis/Valkey candidate has stateful protocol-test-double evidence.
That is useful reference evidence, but it is not live Redis/Valkey
qualification.

### Human TLS ingress

- trusted TLS 1.3 termination with client-certificate validation;
- shared replay protection across every ingress instance;
- durable TaskCoord commits and reconciliation of unknown outcomes;
- bounded request handling, rate and abuse controls, retention, and
  privacy-safe telemetry; and
- rolling deployment, failover, restore, and incident exercises.

### Task–Action binding

- the integrated multi-record transaction contract, including one immutable
  Action binding per Assignment for this profile version;
- durable separation of the acceptance business digest, exact verifier-attempt
  fingerprint, and first canonical result, including recovery after an unknown
  response without accepting a new expired proof;
- durable event re-application, restart recovery, and fencing behavior;
- reconciliation of unknown executor outcomes; and
- operational qualification of every selected wait and recovery mode.

No production Task–Action Store is implemented in this repository.

### Agent-to-Human relay

- restart-durable queue and event state;
- cross-process grant-scoped serialization with fencing;
- provider idempotency and reconciliation for unknown dispatch outcomes;
- protected contact vault and access audit;
- provider-specific delivery, abuse, rate, retention, and deletion controls;
  and
- failure, retry, revocation, and provider-outage exercises.

`LocalGatewaySink` is a local test boundary. It is not a qualified Email, SNS,
telephone, or messaging provider adapter.

The `mac-human-coordination-e2e` target composes these reference boundaries in
one deterministic process and emits a self-limiting evidence report. Its
software-only success is useful integration evidence, but it does not satisfy
any live durability, TLS, provider, failover, or recovery gate in this profile.

## Attestation and Cocos boundary

SNP, TDX, and Cocos are not Human Coordination core requirements. If a
deployment requires confidential-computing evidence, it must select and
qualify a separately versioned attestation or Cocos integration profile. Such a
claim supplements Human Coordination; it does not change the Assignment,
Action, relay, or Human ingress semantics defined here.

The absence of an SNP, TDX, or Cocos module does not prevent a software-only
Human Coordination implementation. Conversely, using one of those modules
does not supply missing Store durability, provider delivery, or operational
qualification.

## Current production decision

`asb.human-coordination.production/v1` is unavailable and
`production_claim.available` is `false` in the conformance manifest. The
change trigger is concrete evidence for every selected capability: production
adapters, live backend and provider qualification, recovery exercises, and an
immutable declaration that maps those artifacts to the stable requirement IDs.
