# Durable gate TLA+ target model

`DurableGate.tla` is a finite, single-writer target state machine for an
application profile that adds durable replay, revocation, lease, audit,
restart, and logical-time state above the core binding acceptance rule.

It is intentionally neutral about higher-level applications. The current Go
tree does not implement this complete state machine, so the TLC result is not
implementation evidence.

## Target guarantees

The TLC configuration checks these safety claims:

- A response acknowledging lease issue or revocation is sent only after its
  replay or revocation state survives restart and its event is synced to the
  audit log.
- An acknowledged lease remains active until a later durable consumption or
  revocation retires it.
- An acknowledged consumption leaves the lease unavailable, and a revoked
  authorization has no active lease.
- At most one active lease exists for an authorization.
- Every durable mutation event is either in the durable outbox or present at
  least once in the audit log.
- A crash after audit append but before durable outbox clearing may create a
  duplicate. Audit delivery is therefore at-least-once, not exactly-once.
- Persistence or audit failure poisons the process and disables operational
  transitions until validated restart.
- Restart drains a non-empty durable outbox before returning to ready state.
- Responses use `max(observed_time, durable_time_floor)`, so acknowledged
  logical times do not decrease when the observed wall clock moves backward.

The write protocol distinguishes temporary-file write, file sync, rename,
directory sync, and memory publication. After rename but before directory
sync, recovery nondeterministically chooses the old or candidate state. An
unacknowledged request may take effect; an acknowledged request may not
disappear.

## Assumptions and exclusions

- One process owns and serializes writes.
- Lease tokens and event identifiers are fresh within the finite model.
- Audit append is durable when it completes.
- Directory sync is the assumed durability boundary. Platform evidence is
  required before applying this assumption to a deployment filesystem.
- Replay and lease expiry or pruning are omitted from this first finite model.
- Cryptography, certificates, request serialization, file permissions, lock
  acquisition, log rotation, storage exhaustion, and partial audit records are
  outside the model.
- `CHECK_DEADLOCK FALSE` is intentional for this bounded safety model. No
  liveness claim is made under repeated crashes or permanent I/O failure.

## Relationship to this repository

The public Go implementation provides `identitypolicy.ReplayCache`,
`MemoryReplayCache`, and a SETNX-style adapter. It does not currently provide
the model's unified durable snapshot, revocation and lease state, audit outbox,
or persistent logical-time floor.

Accordingly:

- no refinement mapping to current Go functions is claimed;
- `MonotonicLogicalTimeInvariant` is a target property, not a current
  implementation guarantee; and
- the TLA+ result must not be described as proof of current crash consistency
  or revocation behavior.

## Running TLC

Use a verified `tla2tools.jar`:

```sh
TLA2TOOLS_JAR=/path/to/tla2tools.jar \
  JAVA_BIN=/path/to/java \
  sh formal/tla/run.sh
```

See `RESULTS.md` for the exact recorded toolchain, bounds, and state counts.
The recorded run is bounded exhaustive evidence for that configuration, not
an unbounded proof. `TLAPS_PLAN.md` records the separate unbounded-proof plan.
