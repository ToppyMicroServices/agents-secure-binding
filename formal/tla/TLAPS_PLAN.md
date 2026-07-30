# TLAPS proof plan

The bounded TLC result in `RESULTS.md` is the input to, not a substitute for,
an unbounded inductive proof. The next proof task will establish a theorem of
the following shape:

```tla
Inv ==
    /\ TypeInvariant
    /\ WriteShapeInvariant
    /\ ReadyInvariant
    /\ FailClosedInvariant
    /\ DurableEventCoverageInvariant
    /\ AcknowledgedAuditInvariant
    /\ AcknowledgedReplayInvariant
    /\ AcknowledgedRevocationInvariant
    /\ AcknowledgedLeaseInvariant
    /\ AcknowledgedConsumptionInvariant
    /\ MonotonicLogicalTimeInvariant

THEOREM Spec => []Inv
```

No such theorem is claimed yet.

## Proof decomposition

1. Prove `Init => Inv`.
2. Determine whether the TLC invariants are inductive as written.
3. Add the smallest necessary strengthening predicates. Expected candidates
   relate:
   - lifecycle and write-stage shape;
   - `disk`, `memory`, `visible`, and `candidate`;
   - a pending mutation event to the durable outbox;
   - durable events to outbox or audit membership;
   - issued, retired, acknowledged, and currently active lease tokens; and
   - response times to the durable logical-time floor.
4. Prove one preservation lemma for every action in `Next`:
   - restart and invalid-disk rejection;
   - issue, revoke, and consume begin actions;
   - temporary-file sync, rename, directory sync, and write finish;
   - audit append and outbox clearing;
   - persistence and audit failure;
   - crash recovery choices; and
   - observed-time changes.
5. Compose the action lemmas into
   `Inv /\ [Next]_vars => Inv'`.
6. Check the final theorem with a pinned TLAPS toolchain and record every
   trusted backend, timeout, omitted obligation, and tool checksum.

## Completion boundary

The task is complete only when `tlapm` reports every selected obligation
proved without `BY OMITTED`, an unproved `ASSUME`, or a suppressed failure.
This proof will remain a theorem about the TLA+ transition system. Separate
refinement work is required before applying it to the Go implementation or a
specific filesystem.
