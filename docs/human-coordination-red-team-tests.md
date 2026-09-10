# Human Coordination Red-Team Tests

This page records the hardware-independent misuse gate for the Human
Coordination developer preview. Passing it is local protocol evidence, not a
production or deployment qualification.

## Bounded gate

Run the same bounded gate used by the dedicated CI job:

```sh
make human-coordination-red-team
```

The gate runs with the race detector and a fresh test process. It covers:

- Human-versus-relay profile substitution, wrong audience, operation-kind
  confusion, request mutation, challenge mix-up, replay, and cross-connection
  challenge reuse;
- strict JSON and canonical transcript differentials for duplicate and escaped
  duplicate members, invalid UTF-8, NFC/NFD byte distinctions, multibyte byte
  limits, excessive nesting, integer overflow, timestamps, trailing documents,
  and the document-size limit. Schema-accepted semantic rejection is allowed
  only for the documented UTF-8 octet ceilings, cross-field equality rules,
  and zero-time exclusion; any other schema/semantic differential fails;
- TLS 1.3 loopback tests for HTTP/2 concurrent challenge use and challenge reuse
  across a resumed connection;
- existing fault tests for replay reservation, operation-journal persistence,
  TaskCoord commit-result uncertainty, relay callback failure, invalid provider
  acknowledgement, revocation races, and at-most-one provider invocation; and
- public ingress error and relay receipt canaries. Verifier, storage, provider,
  Human, consent, relay-session, and contact details must not cross those public
  response surfaces.

The gate executes deterministic fuzz seeds but does not start an unbounded fuzz
campaign.

## Separate fuzz campaign

Run the parser/canonical campaign explicitly and set a duration appropriate for
the environment:

```sh
HUMAN_COORDINATION_FUZZTIME=10m make human-coordination-fuzz
```

This target is intentionally separate from pull-request CI. A campaign result
is evidence only for the exact code revision, duration, toolchain, and corpus
that were run.

## Evidence boundary and remaining qualification

The bounded gate uses in-process reference stores, a loopback TLS server, test
keys, and a synthetic gateway. It does not qualify:

- Redis or Valkey persistence, replication, partitions, failover, or host loss;
- a production TaskCoord or Task–Action database transaction across multiple
  processes;
- provider reconciliation after an externally successful callback whose local
  acknowledgement commit was lost;
- deployment TLS termination, certificate rotation, proxies, or load balancers;
- production logs, metrics, traces, or their access controls; or
- SNP, TDX, TPM, or other hardware-backed attestation.

Those checks require deployment-specific live qualification. The current
packages expose no production log or metric sink, so the local gate cannot claim
telemetry-canary coverage. TaskCoord outbox events are backend-internal and can
contain a Participant identifier by design; no Agent-facing outbox view exists
in this preview. A future public view must receive its own projection and
privacy tests rather than exposing the internal event.
