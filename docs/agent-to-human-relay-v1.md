# Agent-to-Human relay v1

Status: experimental, repository-local profile. This document does not define
an Internet standard or claim a production Human-delivery service.

Stable requirement identifiers and the English/Japanese implementation mapping
are maintained in the
[Human Coordination conformance registry](human-coordination-conformance-v1.md).
Identifier units, whitespace, case, and Unicode handling follow
[`human-coordination-field-semantics-v1.md`](human-coordination-field-semantics-v1.md).

`pkg/humanrelay` provides a narrow bridge from an authenticated Agent request
to an already approved Human gateway session. It does not discover Humans,
store direct contact details, or treat a gateway acknowledgement as a Human
decision.

## Separation from Human TaskCoord

Human TaskCoord and the relay answer different questions:

| Surface | Question | Authoritative state |
| --- | --- | --- |
| Human TaskCoord ingress | What did the Human offer, accept, decline, delegate, or answer? | Assignment and Interaction history |
| Agent-to-Human relay | Was one bounded message handed to the configured Human gateway? | Relay intent and transport event |

The relay never creates or changes an Assignment, Interaction, or Action. A
`PROVIDER_ACKNOWLEDGED` relay event does not mean that the Human received,
read, approved, or completed anything.

## Flow

```text
Agent runtime
  │ RelayIntentRequest + ASB grant/session proof
  v
pkg/humanrelay/asbbinding.Profile
  │ exact request digest, policy, session, active AGENT, replay
  v
AuthenticatedRelayIntent
  │ exact active HumanReachabilityGrant lookup
  v
humanrelay.Service.Queue
  │ one grant = one immutable intent
  v
Store: QUEUED
  │ trusted internal worker rechecks grant, consent, Participants, and expiry
  ├─ revocation/recheck wins -> Store: CANCELED (no provider callback)
  v
Store: DISPATCHING (durable before the provider callback)
  │ SessionDispatcher -> opaque Human gateway session
  v
Store: PROVIDER_ACKNOWLEDGED
```

The ASB profile binds the complete request, including the reachability grant,
Agent Participant, purpose, capability, channel, content reference, and
content digest. It verifies the signed identity grant and session-binding
statement against verifier-controlled policy, checks that the requester is an
active `AGENT`, and consumes the session-binding replay key before returning
the projection.

`asbbinding.Profile` is a programmatic verification boundary. A direct TLS
challenge/execute HTTP ingress for relay requests is not implemented. The
caller must supply binding values derived from the accepted TLS session and
must not construct `AuthenticatedRelayIntent` from unverified peer input.

## Privacy boundary

The Agent-facing `Receipt` contains only:

- relay intent and reachability grant identifiers;
- `QUEUED`, `DISPATCHING`, `PROVIDER_ACKNOWLEDGED`, or `CANCELED`
  transport state;
- the content digest; and
- queue and update timestamps.

It omits the Human Participant, candidate, consent, approval evidence, opaque
relay session, provider reference, and direct contact. The broker-controlled
dispatcher receives the opaque relay-session reference from the active grant;
the Agent does not select or recover it.

The request uses an HTTPS `content_ref` plus a lowercase SHA-256 digest rather
than embedding message content. This is a binding and data-minimization rule,
not proof that the referenced content is safe or secret. Both values are in
the durable broker intent and are passed to the gateway, so they are already
broker-visible. An HTTPS path may contain sensitive text, and a digest of
low-entropy content may support guessing. A deployment still needs
authorization, content access control, malware/content policy, retention, and
logging controls.

`HumanMatchConsent` and `HumanReachabilityGrant` authorize bounded contact
metadata and use of an opaque gateway route for the named requester, purpose,
capability, channel, and validity window. They are not Human approval of the
exact message content. The ASB relay proof binds the Agent to the exact
`RelayIntentRequest`; it proves which request the Agent authorized, not that
the Human approved its bytes. A policy that requires exact-content approval
would need a separate authenticated, Human-produced statement bound to the
relay `RequestDigest`. This profile does not implement that statement.

## Idempotency and state

One active reachability grant authorizes one relay intent. A retry with the
same request digest, route, and content may use a fresh ASB proof and returns
the original receipt. It does not replace the original queue time or proof
record. Reusing the intent identifier with a changed business request is
reported as a conflict only after the authoritative grant transaction confirms
the caller's scope. Before that check, an existing mismatched identifier and
an unknown identifier both return `ErrUnavailable`, so the identifier cannot
be used as a state oracle. Racing different intents against one grant allows
only one commit. A production audit that must retain every retry proof needs a
separate append-only verification-attempt log; the in-memory reference Store
retains only the first committed proof.

`Store.CommitAuthorizedIntent` is the queue authorization boundary. After
locking the authoritative reachability state, it must recheck the requester
Participant, Human Participant, consent, grant revocation, scope, and expiry,
then commit the immutable intent, its `QUEUED` event, and a pending dispatch
record before releasing that lock. Checking the grant and committing the
intent in separate transactions is not conformant because a concurrent consent
or grant revocation could otherwise race the queue operation.

Dispatch has a second authorization boundary immediately before any external
provider callback. The Worker must serialize this boundary with grant and
consent revocation, recheck the authoritative grant, consent, requester and
Human status, scope, and expiry, and reserve the intent by committing
`DISPATCHING` before calling `SessionDispatcher`.

The durable commit order resolves a concurrent dispatch and revocation. The
caller-supplied timestamp inside a revocation does not decide the race:

- If revocation or revalidation wins while the intent is `QUEUED`, the Store
  commits `CANCELED` and does not call the provider.
- If dispatch wins, the Store commits `DISPATCHING` first. Revocation waits for
  the same grant-scoped guard while the provider callback and acknowledgement
  commit complete.
- If the provider returns an error, or the outcome cannot be established, the
  intent stays `DISPATCHING`. That state means an external effect may have
  occurred, so the reference Worker does not retry the callback blindly.

`CANCELED` therefore asserts that no provider callback was attempted. It is
valid only as a transition from `QUEUED`; it does not retroactively cancel an
attempt that already reached `DISPATCHING`. Multiple Workers racing the same
intent must share the same durable reservation and invoke the provider at most
once. Later recovery from `DISPATCHING` requires provider reconciliation by
intent identifier or an operator decision.

`SessionDispatcher` must deduplicate by intent identifier. Provider
acknowledgement is append-only and must match the same intent. Dispatch is not
an Agent operation: the separate `Worker` API is a trusted internal outbox
consumer and must not be exposed as a network route. Raw dispatcher,
contact-resolution, and provider errors remain private worker telemetry. These are interface requirements. `MemoryStore` and `LocalGatewaySink`
satisfy them only inside one process. The Linux `FileStore` implements the
restart-durable relay side described below.

A deployment needs equivalent cross-process serialization. It
may use a grant-scoped distributed lock with a fencing token, or issue a
one-shot gateway permit only after the final reachability check. A database
check committed before an unguarded provider call does not provide the
no-provider-call guarantee when revocation wins.

Relay event identifiers are collision-resistant derived identifiers, not
caller-selected concatenations. For all relay statuses, implementations must
compute:

```text
event_id = "relay-event:v1:" || lowerhex(SHA-256(transcript))
transcript = ASCII("ASB-HUMAN-RELAY-EVENT-ID-v1") || 0x00
           || field("status", UTF8(status))
           || field("intent_id", UTF8(intent_id))
field(name, value) = uint16be(len(name)) || ASCII(name)
                   || uint32be(len(value)) || value
```

Lengths are octet lengths. The status is exactly `QUEUED`, `DISPATCHING`,
`PROVIDER_ACKNOWLEDGED`, or `CANCELED`. This construction keeps event
identifiers within the 256-octet semantic limit even when `intent_id` itself is
256 octets. It does not make a guessable intent identifier confidential.
The JSON Schema enforces the `relay-event:v1:` prefix and lowercase 64-hex
shape. It cannot recompute SHA-256; semantic validation must recompute the
transcript and reject an identifier that does not match its status and intent.

The broker-controlled clock supplies every durable event timestamp. The
`DISPATCHING` time is recorded before the provider callback. If that time is
zero or earlier than the queue time, dispatch fails closed and the provider is
not called. The acknowledgement time is when the broker observes a valid
provider acknowledgement. A timestamp supplied by the provider is advisory
telemetry only and must not become `Event.At` or `Receipt.UpdatedAt`. If a
valid acknowledgement cannot be committed after the callback, the state stays
`DISPATCHING` rather than claiming that no attempt occurred.

## Linux durable relay and provider recovery

`OpenFileStore(path, directory)` persists the immutable intent and its ordered
transport events in a private directory on one Linux host. Every operation
acquires the same permanent file lock across processes. Each transition syncs
the replacement state file and its parent directory before returning. In
particular, `DISPATCHING` is durable before the provider callback. A provider
success followed by process termination before its acknowledgement commit
therefore reopens as `DISPATCHING`; it does not become a new dispatch.

The directory argument remains the authorization authority. Use a durable
`taskcoord/sqlitestore.Store` shared by the queue, worker and revocation paths.
The SQLite adapter serializes grant/consent changes with dispatch while reading
its current Participant registry; it does not hold an SQL transaction during
provider I/O. Its Participant registry is immutable; changing an identity or
status is not exposed as an in-place registry update. Callback contexts must
have at most 30 seconds remaining, as enforced by both adapters. Stop all old
writers before opening the schema-2 SQLite database for migration. Older
binaries do not participate in the new grant guard. Passing a
`MemoryReachabilityDirectory` is useful for tests but
provides no restart or cross-process revocation guarantee.

The trusted worker can enumerate `Pending(ctx, afterIntentID, limit)` with a
limit of 1–256 and a lexical cursor. It returns privacy-minimized receipts:
`QUEUED` entries need fresh dispatch authorization; `DISPATCHING` entries need
reconciliation. Concurrent workers use the durable marker to reserve one
provider attempt. The pending list itself grants no authority or lease.

`Worker.Reconcile(ctx, intentID, provider)` uses a trusted `ProviderReconciler`
adapter to query the configured provider by the exact immutable dispatch
request. The adapter must authenticate the provider and compare the opaque
session, channel and content binding. It must perform no send or redelivery.
Only an authoritative acknowledgement of that same request can append
`PROVIDER_ACKNOWLEDGED`. Missing, pending or expired provider history, timeout,
invalid acknowledgements and query errors leave `DISPATCHING` unchanged. A
missing provider record is not proof that delivery did not happen. Terminal
receipts cannot be overwritten, and reconciliation does not grant reuse or
create Human approval. `LocalGatewaySink.Lookup` is a synthetic implementation
for conformance tests, not a qualified external provider.

The file adapter bounds each operation, lock acquisition, dispatch and query
context to 30 seconds, or the caller's earlier deadline. Adapters must honor
cancellation; the worker does not abandon a still-running callback in another
goroutine or release its authorization guard. A provider that ignores context
requires the service supervisor to fence/terminate that worker. Reopen and
reconcile the retained attempt before resuming work. This is a bounded workload
adapter: 10,000 immutable intents and 16 MiB of state. Exhaustion fails closed;
no automatic deletion of grant consumption or unknown outcomes occurs.

Malformed/ambiguous JSON, invalid event order, inconsistent request digests,
symlinks, hard links, non-private files and loss of an initialized state file
fail closed. An error after rename has an unknown durability result and fences
that handle. Inspect storage health before opening a new handle; query the
provider rather than inferring that the callback is safe to repeat. No
checksum or file lock protects against an administrator rolling back both the
state and lock. Stop/fence all workers before a consistent backup or restore,
retain the authoritative grant database with the relay files, and reconcile any
post-backup external effects. Filesystem power-loss behavior, live provider
identity/idempotency and multi-host failover still require deployment evidence.

## CI mode

`LocalGatewaySink` is a deterministic in-memory gateway for local development.
It validates the opaque HTTPS session and content references, records the
dispatch, and returns a provider acknowledgement without contacting a Human or
an external service. Protocol tests use synthetic identifiers and content. The durable adapter and
process cut-point tests run on Linux.

Focused checks:

```sh
GOWORK=off go test -race -count=1 ./pkg/humanrelay/... ./schemas
```

## Remaining deployment work

The repository does not yet provide:

- a relay-specific TLS challenge/execute endpoint;
- an encrypted contact vault;
- Email, SNS, or telephone provider adapters;
- delivery receipts, Human read state, or identity proofing;
- rate limits, abuse handling, retention/deletion policy, or operator UI;
- a Human-produced exact-content approval bound to `RequestDigest`; or
- a selected, authenticated external `ProviderReconciler` adapter and live
  provider/failover qualification.

Those components should remain outside ASB Core. They may consume an ASB-bound
projection and opaque reachability grant, but they must not expose direct Human
contact data to the requesting Agent.
