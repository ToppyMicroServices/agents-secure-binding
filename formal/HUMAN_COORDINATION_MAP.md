# Human Coordination formal model map

This map links the Human Coordination models to protocol requirements and Go
surfaces. It is review traceability, not a machine-checked refinement proof.
The TLA+ models are target contracts for production adapters that do not yet
exist in this repository.

## ProVerif Human ingress

| Model property | Requirement mapping | Go surface and current boundary |
| --- | --- | --- |
| `gateway_asserted_for_human` is distinct from the accountable Human Participant | `ASB-HC-CORE-001`; `ASB-HC-CORE-003` | The internal `acceptance` type in `pkg/taskcoord/asbbinding` retains the resolved Human and gateway Actor separately; its `operation` method projects both into `taskcoord.AuthenticatedOperation`. `HumanAssuranceGatewayAssertedForHuman` names the implemented assurance level. |
| Exact Human profile, verifier-local realm and audience, Participant, operation kind, and canonical request digest | `ASB-HC-CORE-003`; `ASB-HC-CORE-010`; `ASB-HC-HTTP-003`; `ASB-HC-HTTP-008` | `pkg/taskcoord/asbbinding/canonical.go` constructs the domain-separated request digest. `IngressPolicy` supplies verifier-controlled grant and session audiences. `Profile.accept` requires exact authorization detail, request-context hash, and accepted TLS binding. Audience maps directly to verifier configuration. The model's separate `realm` is an additional verifier-local namespace abstraction with no current Go or wire field, so no `ASB-HC-CORE-010` implementation refinement is claimed. |
| Acceptance corresponds to an authority grant and gateway holder proof over the same values | `ASB-HC-CORE-003`; holder-proof aspect of `ASB-HC-HTTP-002`; `ASB-HC-HTTP-003` | `clients.VerifyIdentityGrantJWT`, `clients.VerifySessionBindingJWT`, `identitypolicy.NewAssertionFromSessionBinding`, and `Policy.ValidateAssertion` are the intended implementation sequence. ProVerif does not model their parsers, concrete algorithms, certificates, or TLS handshake. |
| Relay-profile material cannot satisfy Human ingress | profile-separation aspect of `ASB-HC-RLY-001` and `ASB-HC-HTTP-009` | Human ingress uses `asb.taskcoord-human-request/v1`; relay authorization uses `asb.taskcoord-agent-relay/v1`. The symbolic model gives both profiles to the attacker and accepts only the Human profile. It does not verify the full relay authorization tuple or HTTP route exposure. |
| One gateway proof has injective correspondence to one acceptance across fresh verifier sessions | `ASB-HC-CORE-003`; `ASB-HC-HTTP-003` | `BindingFromTLS` and the pending challenge bind the request to one accepted connection, nonce, and digest. `identitypolicy.MarkSessionBindingUsed` supplies concrete replay consumption. The ProVerif proof depends on fresh exporter, nonce, and context values; it does not prove replay-store atomicity or durability. |

The model deliberately emits `gateway_asserted_for_human`, not a
`human_signed` event. Compromise of the gateway key destroys the modeled basis
for Actor attribution. It still does not create evidence that the Human was
present or approved the request.

These requirement links are aspect-level where stated. The model does not
cover certificate validation, expiry, HTTP methods, one-execute-attempt state,
or endpoint reachability.

## TLA+ Human ingress commit and retry

`tla/HumanIngressCommitRetry.tla` starts after proof verification. It keeps the
durable journal state separate from Worker control state, caller knowledge, and
write-only external-effect history. It models an operation identifier,
immutable request digest, proof-use accounting for every exact retry, one
effect attempt, crash and response-loss cutpoints, unknown outcome, conflict
rejection, and evidence-gated reconciliation.

| Model invariant | Requirement mapping | Go surface and current boundary |
| --- | --- | --- |
| `StateShapeInvariant`, `ConflictIsolationInvariant` | `ASB-HC-CORE-009`; `ASB-HC-HTTP-008` | `operationjournal.Reservation` and `Store.Lookup` use the exact operation ID and request digest; `ErrConflict` rejects changed data. Human ingress does not currently compose this journal with TaskCoord mutation. |
| `ProofOneShotInvariant` | `ASB-HC-CORE-003`; `ASB-HC-PROD-003` | `operationjournal.AcceptanceStore.ReserveAcceptance` is the replay-plus-operation target boundary and consumes a fresh replay key even when returning an existing exact record. The model's `ObserveExactRetry` mirrors that behavior for accepted, running, indeterminate, succeeded, and failed records. `pkg/taskcoord/asbbinding.Ingress` instead consumes replay before its separate TaskCoord Store commit, so no atomic refinement is claimed. |
| `NoDoubleEffectInvariant` | `ASB-HC-CORE-009`; `ASB-HC-PROD-008` | The model writes durable `RUNNING` before a separate effect action and explores crashes before, during, and after that action. `effectCalls` and `effectApplied` are ghost histories and never enable an implementation action. A production transaction/outcome adapter remains required. |
| `UnknownOutcomePreservedInvariant`, `NoBlindRetryInvariant` | `ASB-HC-HTTP-007`; `ASB-HC-PROD-008` | `operationjournal.StateIndeterminate` and package documentation require recovery before retry. The model snapshots call history on entry to recovery and checks that it cannot advance. Human ingress has the public unknown-outcome vocabulary, but no integrated durable outcome reconciler. |
| `OutcomeConsistencyInvariant`, `ReconciliationInvariant` | `ASB-HC-HTTP-007`; `ASB-HC-PROD-008` | An environment observation converts external truth into trusted evidence; reconciliation actions read only that evidence. The model does not define a network reconciliation endpoint, evidence authenticator, or result-sealing implementation. |

`pkg/taskcoord/actionbinding.Store.CommitAcceptance` is a separate atomic
TaskCoord-to-Action acceptance contract and implements exact-attempt canonical
recovery in the in-memory reference Store. The ingress outcome model is not a
refinement proof for that package and does not imply restart durability.

## TLA+ relay dispatch

`tla/HumanRelayDispatch.tla` models two distinct one-intent grants, two racing
Workers, grant-scoped revocation, a durable `DISPATCHING` reservation, one
provider call, acknowledgement-to-intent validation, unknown provider outcome,
and evidence-gated reconciliation. The one-intent-per-grant relation is an
explicit model assumption corresponding to relay queue authorization; this
model starts after that queue decision.

| Model invariant | Requirement mapping | Go surface and current boundary |
| --- | --- | --- |
| `ReservationInvariant`, `GrantRevocationInvariant`, `CanceledMeansNoCallbackInvariant` | `ASB-HC-RLY-004` | `humanrelay.Store.CommitAuthorizedDispatch` requires serialization with reachability revocation and a `DISPATCHING` commit before callback. The model keys revocation by grant and blocks it only while the live Worker holds that grant's callback boundary. `MemoryStore` provides only in-process reference behavior. |
| `ProviderHistoryInvariant`, `NoBlindRetryInvariant` | `ASB-HC-RLY-005`; serialization aspect of `ASB-HC-PROD-005` | `humanrelay.Worker.Dispatch` delegates the whole boundary to the Store. Worker phase, not ghost provider history, permits the first callback; every pre-call, in-call, and post-return crash path enters recovery and cannot call again. The model does not verify a real provider's idempotency. Cross-process fencing and durable outbox state are not implemented here. |
| `UnknownOutcomePreservedInvariant`, `NoBlindRetryInvariant` | `ASB-HC-RLY-005`; `ASB-HC-PROD-008` | A dispatcher error or crash after `DISPATCHING` leaves the receipt unresolved, and the reference Worker does not call again. There is no production provider-reconciliation adapter. |
| `AcknowledgementInvariant`, `RejectedAcknowledgementInvariant`, `ReconciliationInvariant` | `ASB-HC-RLY-005`; `ASB-HC-PROD-008` | With two intent identities, the model rejects an acknowledgement naming a different intent. Environment observations must match ghost provider truth before reconciliation may consume them. `ASB-HC-RLY-007` remains a semantic non-inference obligation: the model does not assert Human receipt, approval, Action completion, or TaskCoord lifecycle mutation. |

The model leaves a reconciled `NO_EFFECT` intent in `DISPATCHING`. The current
wire vocabulary has no safe requeue state after a callback was attempted. A
policy that permits a later provider call needs a separate protocol and model
change; this model does not silently authorize it.

## Compromise and environment assumptions

- ProVerif treats signatures and hashes as ideal. The authority and gateway
  signing keys remain secret, and verifier-local policy, Participant registry,
  TLS-derived binding, and freshness inputs are trusted.
- Gateway compromise permits false gateway assertions for a Human. Authority
  compromise permits false grants. The model does not claim recovery from
  either compromise.
- The Human holds no modeled key. Human authentication, presence, cognition,
  UI confirmation, legal consent, coercion, and account recovery are outside
  the model.
- TLA+ actions idealize atomic durable journal and relay reservations. External
  effects and provider callbacks are separate actions with explicit crash
  cutpoints. The environment observations that create reconciliation evidence
  are trusted; their concrete authentication is not modeled. Storage
  corruption, replica lag, split brain, transaction isolation, fencing-token
  implementation, and provider idempotency require separate qualification.
- The checked TLA+ configurations are finite safety checks. Deadlock checking
  is disabled and no fairness, availability, or eventual-reconciliation claim
  is made.

## Other unmodeled boundaries

Concrete TLS 1.3, mTLS certificate validation, exporter derivation, JWT/JWS
parsing, algorithm selection, time arithmetic, key rotation, revocation feeds,
strict JSON decoding, Unicode and size limits, log confidentiality, traffic
analysis, rate limits, denial of service, contact-vault privacy, provider API
semantics, and compiled-Go behavior are not verified by these models. The
repository's tests and deployment qualification remain separate evidence.

## Reproduction

```sh
sh formal/proverif/run_human_ingress.sh

TLA2TOOLS_JAR=/path/to/verified/tla2tools.jar \
  JAVA_BIN=/path/to/java \
  sh formal/tla/run_human.sh
```

See `proverif/HUMAN_INGRESS_RESULTS.md` and `tla/HUMAN_RESULTS.md` for the
recorded toolchains, finite bounds, state counts, and results.
