# Durable least-privilege execution

`leastprivilege.DurableStore` extends the finite-model authorizer with a shared
single-host admission journal. It implements `UseStore` and records operation
progress. Linux and macOS processes using the same private directory coordinate
through an OS file lock. This adapter does not provide distributed consensus or
high availability, and it is not supported on network filesystems or Windows.

Provision once with `CreateDurableStore(directory, capacity)`. The parent must
already exist and be controlled by the operator. Creation requires a new
directory; recovery uses `OpenDurableStore(directory)`. Opening missing,
malformed, oversized, publicly accessible or symlinked state fails closed.
Opening never resets replay history. The operator must protect the directory,
its ancestors, and its fixed `lock` file from replacement while workers run.
Each snapshot also carries a checksum to detect accidental corruption. It is
not an authentication mechanism and cannot detect an older valid snapshot.

A failed creation can leave a directory, including valid state published before
an acknowledgment or synchronization error. Another process may already have
opened it. Retry recovery through `OpenDurableStore`; creation never deletes or
resets that path automatically. If opening fails, keep admission disabled and
investigate. An operator may remove the path only after quiescing its users and
establishing that it has never admitted an operation; otherwise use the recovery
procedure below.

Each transaction reloads current state under the lock, writes a private temporary
file, syncs it, atomically renames it, and syncs the directory before acknowledging
success. Process termination releases the OS lock. This relies on the local
filesystem and storage device honoring file and directory synchronization. The
tests exercise process crashes; they do not qualify storage hardware under power
loss. The maximum is 10,000 entries and 64 MiB of serialized state. Each mutation
rewrites the snapshot, so larger workloads need a separately qualified database
adapter. The store never evicts unexpired consumption records to make room.
Operation records and their linked mandate IDs remain stored indefinitely and
count toward the configured capacity, including after completion or cancellation.

## Admission and execution

`Prepare` checks a capability against the supplied trusted mandate and exact
request. In one transaction it consumes the mandate ID and reserves the operation
ID. The request digest binds the operation ID, mandate digest, actor, task and
exact action digest. Capability reissuance and signing-key rotation do not create
a second admission. Reusing the operation ID with a different binding is a
conflict. Execution records and their linked mandate IDs remain reserved for
the lifetime of this store, including after authorization expiry. Keep globally
unique identifiers when introducing a new store namespace as well.

`Run` is the normal execution entry point. The enclosing service authenticates
the caller and holds its policy guard through final validation and invocation.
The adapter receives a copy of the exact request arguments and the stable
operation ID. It should pass that ID to a downstream idempotency mechanism when
available. Adapters are selected by trusted configuration and must implement a
specific operation. The journal is not an authentication service and its low-level
methods must not be exposed as an unauthenticated network API.

| Durable state | What a caller may do |
| --- | --- |
| `ACCEPTED` | Revalidate current policy and capability, then claim `Start` once. |
| `RUNNING` | Treat an interrupted execution as uncertain; query its exact external operation. |
| `UNKNOWN` | Preserve the record and reconcile; do not invoke the effect again. |
| `SUCCEEDED` / `FAILED` | Return the recorded outcome; never dispatch again. |

Only the process receiving `started=true` may call the effect. A process crash
after this commit can leave `RUNNING` even if the effect never started. That is an
explicitly uncertain outcome. An adapter error or cancellation after invocation
records `UNKNOWN`; it is not evidence that the effect failed. A failed journal
write after an effect also returns `ErrOutcomeUnknown`, even when the terminal
state might already have reached disk. Recover by looking up the exact operation
and request digest.

`Complete` is a trusted storage operation. Terminal completion requires a
canonical evidence digest. The enclosing service must authorize reconciliation
under current policy and obtain evidence from an authoritative adapter query;
an evidence digest submitted by a requester is insufficient. Do not conclude
failure from an absent eventually consistent result. A terminal decision cannot
be overwritten by a different outcome or evidence digest. Request arguments and
external responses are not stored, so recovery also requires the application's
protected record of the exact original request.

Only expired ordinary consumption records, such as ASB proof nonces not linked
to an execution, may be pruned when a subsequent admission commits. A persisted
pruning watermark rejects clock rollback that could revive those deleted
records. Every execution and its linked mandate record remain, in every state.
Capacity exhaustion and storage errors deny new admission. Clocks and input
mandates come from trusted service configuration.

An authorized administrator may call `CancelAccepted` to abandon a reservation
that has never dispatched. It competes atomically with `Start`, records a local
no-effect decision, and rejects `RUNNING` or `UNKNOWN` operations. This lets an
expired pending reservation receive a terminal outcome without guessing whether
an external effect occurred. Its identity and evidence still occupy capacity.

When this bounded store fills, quiesce all workers before retiring its namespace.
Resolve uncertain effects through authoritative readback, retain the old store
as history, and revoke or replace its mandates in current trusted policy before
provisioning a new directory with globally new mandate and operation IDs.
Changing the directory alone does not authorize reuse of old identifiers. There
is no automatic history reset or eviction of completed operations to make room.

## TaskCoord commit recovery

`leastprivilegebinding.DelegateAndCommit` validates the TaskCoord transition,
reserves admission, then calls `Store.CommitDelegation`. It does not return an
uncommitted transition for another caller to execute. If the commit fails or its
acknowledgment is lost, the durable journal retains the operation as `UNKNOWN`.

`ReconcileDelegation` looks up the immutable delegation event in the authoritative
TaskCoord store. It checks the exact event, action and policy binding before
recording success. Missing data and unavailable storage preserve uncertainty;
the function never retries `CommitDelegation`. The deployment must use a durable
TaskCoord store with the documented atomic delegation contract. A `MemoryStore`
is useful for tests but cannot supply restart recovery.

## Backup and restore

A valid but old snapshot cannot reveal that it omitted later consumptions.
File locking, signatures and a local pruning watermark do not solve this rollback
problem. Back up only after quiescing every writer and syncing the complete store;
retain the matching protected application operation records. Never copy or remove
the live lock file as a substitute for stopping writers.

If state is lost, corrupt, or restored from an older snapshot, keep execution
disabled. Reconcile all operations admitted since that snapshot using the
authoritative effects system. Revoke the old mandate namespace in the trusted
policy authority, provision a new store directory, and issue globally new
mandate/operation IDs before enabling workers. A signing-key rotation alone does
not replace this recovery procedure. Restoring backups is an operator-controlled
procedure; this implementation does not perform unattended rollback recovery.
The same procedure applies to an older store that already pruned terminal
execution records: those forgotten identities cannot be reconstructed by an
update to the retention rule.

## Verification scope

The Go tests cover independent processes sharing one admission, reopen after
restart, capability reissuance and signing-key rotation, capacity, clock rollback,
lock cancellation, unavailable or corrupt state, and process exit at temporary
write, rename and directory-sync cutpoints. They also terminate a worker before
and after the external effect and before terminal persistence, then check that
recovery never redispatches an uncertain operation. TaskCoord tests exercise an
actual committed delegation followed by a lost acknowledgment and authoritative
readback, and a failed commit whose missing result stays `UNKNOWN`.

The gated `TestDurableRedisDelegationRestart` was also run against a real local
Redis 8.10.1 server using TLS 1.3, password authentication, `appendfsync always`
and `noeviction`. After a committed delegation lost its acknowledgment, the test
force-stopped Redis, restarted it from the same AOF, reopened the admission
journal, and recovered success through the immutable delegation record. It
verified that no second commit occurred. This is one local restart test, not
replica failover or power-loss qualification.

To run this gate, provision an isolated Redis fixture and set
`ASB_REDIS_TEST_ADDR` to its explicit loopback IP and port,
`ASB_REDIS_TEST_PASSWORD_FILE` to its protected password file, and
`ASB_REDIS_TEST_CA` to its CA certificate. `ASB_REDIS_TEST_SERVER_NAME` defaults to
`localhost`. `ASB_REDIS_TEST_RESTART` must be an absolute trusted executable that
restarts only that fixture using the same data directory and waits for readiness.
The test creates a unique key namespace. Never point this test at a shared service.

```sh
GOFLAGS=-p=2 go test -tags=integration -race -count=1 \
  -run '^TestDurableRedisDelegationRestart$' ./pkg/taskcoord/leastprivilegebinding
```

Without the integration build tag this test is excluded. With the tag but no
fixture address it is skipped; neither case establishes backend restart recovery.
