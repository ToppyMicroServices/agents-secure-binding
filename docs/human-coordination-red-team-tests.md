# Human Coordination Red-Team Tests

This page records the hardware-independent misuse gate for the Human
Coordination developer preview. Passing it is local protocol evidence, not a
production or deployment qualification.

## Bounded gate

Run the same bounded gate used by the dedicated CI job:

```sh
make human-coordination-red-team
```

The required `product-security` CI job runs `make human-coordination-gate`.
That target includes the same red-team package set and the end-to-end example
in one Go test invocation, plus independent Python checks for Action and Human recovery transcripts. Both targets
share the red-team package list in the Makefile.

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
- SQLite-backed mTLS recovery for all four Human mutations, multiprocess retries,
  process termination around commit, shared revoke/start ordering, outbox fencing,
  write-failure rollback and backup/restore;
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

The bounded gate uses reference stores, actual local SQLite databases, independent
processes, loopback TLS, test keys and a synthetic gateway. Its local SQLite
results are described in the [adapter guide](taskcoord-sqlite-store.md). It does not qualify:

- Redis or Valkey persistence, replication, partitions, failover, or host loss;
- a selected production deployment, multi-host database failover or host loss;
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
