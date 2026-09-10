# Recorded Human Coordination TLA+ results

These are bounded exhaustive model-checking results for
`HumanIngressCommitRetry.cfg` and `HumanRelayDispatch.cfg`. They are not
unbounded proofs and do not establish refinement by a production Store.

## Integration rerun — 2026-09-10

Both unchanged models passed SANY and TLC again during main integration, with
the same state counts and depths reported below: ingress 1,350,793 generated /
165,185 distinct states (depth 21), and relay 950,381 / 168,100 (depth 17).
Their queues were empty at completion. TLC took 18 and 17 seconds respectively.

The official v1.8.0 release asset had been replaced since the earlier run.
The new binary's SHA-256 was checked against the GitHub release API before
execution: `eefe1ed75d091b3b0263af53add21265546895d12e43dfd68abb9517b7811006`.
It reports `TLC2 Version 2026.09.10.133702 (rev: 8ab94b6)`; the API records its
asset creation at `2026-09-10T13:41:20Z`. The historical tool hashes below still
identify the earlier run and are not substituted with this asset.

The rerun used OpenJDK 21.0.12, the unchanged `run_human.sh`, and
`JAVA_TOOL_OPTIONS='-Xmx512m -XX:ActiveProcessorCount=2'`. No negative model
mutation or coverage campaign was repeated in this integration pass.

## Toolchain and command

- TLA+ tools release asset: v1.8.0
- TLC self-reported build: `2026.09.01.002747` (`95b800c`)
- Java: Homebrew OpenJDK 21.0.12
- `tla2tools.jar` SHA-1:
  `c2b67608594c2a182bf790160bd98b7949e05621`
- `tla2tools.jar` SHA-256:
  `dbcc75552f21978a4846688b8e23be1a6b6c0b3fcee35d78fec2df167958ec94`

The final model revisions were checked on 2026-09-03 with:

```sh
TLA2TOOLS_JAR=/tmp/tla2tools-v1.8.0.jar \
  JAVA_BIN=/opt/homebrew/Cellar/openjdk@21/21.0.12/libexec/openjdk.jdk/Contents/Home/bin/java \
  sh formal/tla/run_human.sh
```

The runner invokes SANY before TLC for each model. Both SANY analyses completed
without an error.

## Human ingress commit and retry

Configuration bounds:

- operation identifiers: 2;
- request digests: 2;
- proofs: 2; and
- deadlock checking: disabled for this bounded safety model.

TLC checked every invariant in `HumanIngressCommitRetry.cfg` without finding a
violation:

- states generated: 1,350,793;
- distinct states: 165,185;
- search depth: 21;
- states left on queue: 0;
- workers: 1;
- fingerprint index: 50;
- seed: `4424333534854180641`;
- optimistic missed-state estimate: `1.1E-8`; and
- actual-fingerprint missed-state estimate: `2.0E-9`.

## Human relay dispatch

Configuration bounds:

- relay intents: 2;
- one-intent grants: 2;
- Workers: 2; and
- deadlock checking: disabled for this bounded safety model.

TLC checked every invariant in `HumanRelayDispatch.cfg` without finding a
violation:

- states generated: 950,381;
- distinct states: 168,100;
- search depth: 17;
- states left on queue: 0;
- workers: 1;
- fingerprint index: 45;
- seed: `-8507701805769834623`;
- optimistic missed-state estimate: `7.1E-9`; and
- actual-fingerprint missed-state estimate: `1.5E-9`.

## Temporary negative mutations

Four local mutation checks confirmed that the invariants reject the safety
regressions they are intended to expose. These temporary mutants are not part
of the repository:

- allowing an ingress effect call from `RECOVERY_REQUIRED` produced an
  `UnknownOutcomePreservedInvariant` counterexample at depth 5;
- allowing another relay provider call from `RECOVERY_REQUIRED` produced a
  `ProviderHistoryInvariant` counterexample at depth 4;
- removing the relay grant critical-section guard produced a
  `GrantRevocationInvariant` counterexample at depth 3; and
- removing the relay acknowledgement-to-intent equality guard produced an
  `AcknowledgementInvariant` counterexample at depth 4.

These mutation checks are sensitivity tests for the bounded specifications.
They do not add an implementation-level proof.

Separate TLC runs with `-coverage 1` completed with the same state counts and
reported a nonzero invocation count for every top-level action in both
specifications. This checks reachability within the recorded bounds; it is not
a liveness result.

The checked state machines assume atomic journal and relay reservation writes.
External effects, response delivery, and provider acknowledgement persistence
are separate transitions with explicit crash paths. `effectCalls`,
`effectApplied`, `providerCalls`, and `providerTruth` are ghost histories; no
implementation transition uses them to permit a call. Only trusted environment
observations use external truth to produce reconciliation evidence. The models
do not verify that evidence's authentication, database isolation, crash
durability, provider idempotency, TLS, cryptography, or the Go implementation.
