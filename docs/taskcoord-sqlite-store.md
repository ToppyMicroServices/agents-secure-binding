# Durable Human coordination on one host

`pkg/taskcoord/sqlitestore` implements `taskcoord.Store`,
`taskcoord.OutboxStore`, the complete `actionbinding.Store` interface, and
`asbbinding.HumanTransactionStore`. It uses the existing SQLite dependency.
The supported storage boundary is a private local database shared by processes
on one host. Network filesystems and multi-host failover are outside this
adapter's scope.

```go
store, err := sqlitestore.Open("./state/coordination.db")
if err != nil {
    return err
}
defer store.Close()

// Policies and the participant registry are deployment-owned. Ingress must
// still be served using its required verified TLS configuration.
ingress := &asbbinding.Ingress{Store: store, Policy: policy}
handler, err := ingress.Handler()
if err != nil {
    return err
}
_ = handler

actions, err := actionbinding.NewService(store, nil)
if err != nil {
    return err
}
_ = actions
```

These are in-process APIs. An application must derive Action authorization
projections from its trusted verifier; it must not decode them from peer JSON.
The existing Human ingress remains the external boundary for its four supported
TaskCoord mutations. `SetDependencies` and `SetDependencySatisfied` likewise
require application-owned authorization.

## Transaction and recovery behavior

A write obtains `BEGIN IMMEDIATE` before loading state. TaskCoord and Action
validation reuse the reference state machines. Only TaskCoord persists current
Assignments. Every Action transaction loads these authoritative Assignments;
its stored historical acceptance View is retained solely for exact retries.
START, RESUME, TAKEOVER and lease renewal therefore cannot pass using a stale
Assignment after its revocation has committed. Revocation preserves prior
execution history and does not itself cancel an already running Action.

For Human ingress, one transaction contains the replay record, mutation,
transactional outbox entry and first response. The operation ID is the request's
existing EventID. An execute retry conflicts. The separately authenticated
`OPERATION_RECOVER` request retrieves the exact first response, with its original
proof provenance, only for the same Human, gateway Actor and request digest.
Its grant binds the recovery operation rather than authorizing execution again.
See [the ingress protocol](asb-taskcoord-human-ingress-demo.md).

A callback error rolls back its transaction. Failed mutation, replay and outcome
writes also poison the transaction if a callback ignores their returned errors.
The callback must not retain its transaction, call the outer Store, or perform
network I/O. Ingress policy hooks should use local verifier state and must not
re-enter the store while its transaction is held.

Action acceptance preserves business identity, complete proof-attempt identity
and the first committed View. An identical attempt retrieves that View after
expiry; a different proof for the same business operation requires reconciliation.
New acceptance and execution transitions recheck authorization and lease time
inside the transaction. Dependency wait/resume retains the original topology
binding. An unknown Action outcome remains unknown across restart until a trusted
application supplies reconciliation evidence. The adapter invokes no external
execution or reconciliation callback.

This transaction boundary covers persisted execution admission. It does not
make an external effect atomic with START, establish exactly-once delivery, or
fence a later external callback by itself. An application connecting an executor
must supply that dispatch and authoritative-query boundary.

## Storage and operations

SQLite uses WAL and FULL synchronous writes. The database must be an owner-only
regular file in a deployment-owned directory. Keep the database, WAL and shared
memory files together during operation. Do not copy only a live database file.
`Backup(ctx, newPath)` uses SQLite's consistent snapshot operation, then syncs the
backup file and directory. It refuses to overwrite an existing file.

To restore, stop/fence all existing writers and open the completed backup as the
new database. A backup preserves state at its snapshot point; it cannot preserve
later replay or external-effect knowledge. Fence old clients/workers and
reconcile effects after that point before resuming. Disk tampering, rollback,
power-loss behavior of a particular filesystem, and managed-provider failover
require separate deployment evidence.

The adapter deliberately bounds its workload: each TaskCoord/Action state blob
is limited to 32 MiB; outcomes, retained outbox rows and used lease identifiers
are each limited to 100,000 records; unexpired replay records are limited to
100,000. An outbox poll returns at most 256 entries with a lease of at most one
hour. A poll that returns a delivery reserves its lease ID permanently, and that
ID must be fresh. Empty polls use a read-only fast path, reserve no lease ID and
do not rewrite the TaskCoord state snapshots because they grant no
acknowledgement capability. Acknowledged rows and non-empty lease IDs remain as
deduplication/fencing evidence. Limits fail closed; there is no automatic
destructive compaction. Each transaction validates stored history, so this
adapter targets bounded workloads rather than high throughput.

A storage/commit error may have an unknown outcome. Recover by stable operation
or event identity. Do not infer that an external effect is safe to repeat.
Outbox publication is at-least-once: consumers deduplicate EventID. A replaced or
expired worker cannot acknowledge another worker's lease.

## Local verification

The required Human gate includes `pkg/taskcoord/...`, including this adapter and
the real TLS/ASB plus SQLite recovery tests. Tests exercise:

- all four Human mutations, response loss after commit, database reopen, fresh
  recovery proof, mismatched scope, current-policy denial and expired proof;
- immutable acceptance retry across handles/processes and restart, both
  revocation/START orderings, dependency wait/resume and normal completion;
- subprocess termination before/after commit, injected state/outbox write errors,
  callback rollback, ignored replay failure and corrupt stored state;
- lease expiry and unknown-outcome reconciliation, outbox fencing, consistent
  backup/restore, and exact response-byte retention.

Action authorization in backend tests is a trusted fixture; the separate ingress
integration uses signed grants and actual mutual TLS. These tests establish the
listed local behavior. They do not constitute managed HA qualification, delivery
provider qualification, a Human participant study or a production-profile release.
