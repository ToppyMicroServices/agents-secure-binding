# Least-privilege performance measurements

The exact solver and exhaustive verifier remain bounded to 20 grant decisions.
No replacement solver or production latency target follows from this experiment.
The benchmark records their costs separately from certificate generation and
checking. Fixtures describe controlled finite models, not observed cloud IAM
workloads.

## Reproduce

Build before collecting timings so compilation does not enter the measurements:

```sh
GOFLAGS=-p=2 GOWORK=off go build -o /tmp/asb-leastprivilege-bench \
  ./cmd/asb-leastprivilege-bench
GOMAXPROCS=1 /tmp/asb-leastprivilege-bench \
  --sizes 4,8,12,16,20 --repetitions 3 --timeout 10s \
  --probe-timeout 1ns \
  --environment-note 'local development host; record competing load here' \
  > /tmp/leastprivilege-benchmark.json
```

The JSON includes the Go version, architecture, available CPUs, `GOMAXPROCS`,
build-reported VCS revision and modified flag, exact model digests, budgets,
and every raw sample. Fixture construction is deterministic and contains no
random seed or external data. Positive grant counts up to 20 and 1–10 repetitions
bound the runner. An operation exceeding its deadline is recorded as a failure;
dependent measurements are omitted when their prerequisite is unavailable.

The four patterns vary the work performed by the evaluator and proof checker:

| Pattern | Construction |
| --- | --- |
| `independent` | One distinct permission per grant; require the first permission. |
| `chain` | Add an implication chain from first to last permission; reverse input order exercises repeated passes in the certificate evaluator. |
| `forbidden` | Add forbidden pairs between adjacent permissions. |
| `sparse_last` | All early grants are empty; only the last grant supplies the requirement. |

Every permission costs `index % 3 + 1`. All permissions are allowed. The first
permission is required except in `sparse_last`, where the last is required.
`sparse_last` exposes a weakness of the current certificate generator: it splits
on irrelevant early grants, creating the complete binary tree. At 20 grants
that is 2,097,151 nodes. This is deliberate evidence of the worst case, not a
representative estimate of deployment workloads. The existing optimizer is
unchanged and still enumerates all 2^g subsets for a successful result.

## Measurement interpretation

Each operation has its own elapsed time and `runtime.MemStats` allocation-byte
and allocation-count deltas. Garbage collection runs before each sample and
outside its timer. Allocation deltas include deadline-context bookkeeping;
they are cumulative allocated bytes, **not peak live memory or RSS**. JSON
encoding is outside operation timing. Successful `Solve` and `Verify` each
evaluate exactly 2^g subsets under their existing exhaustive algorithms. Their
APIs do not expose partial counters, so failed runs report `null` for exact
subset evaluations. Certificate node and closure counters are observed and
remain available on failure. `proof_json_bytes` is the compact JSON byte count.

Separate 1 ns deadline probes test failure recording for all four operations.
They do not estimate a practical deadline or throughput. A successful probe, if
one occurs on another runtime, is recorded as successful rather than relabeled.

For standard Go benchmark output, including `ns/op`, `B/op`, and `allocs/op`:

```sh
GOFLAGS=-p=2 GOWORK=off GOMAXPROCS=1 go test \
  ./cmd/asb-leastprivilege-bench -run '^$' \
  -bench BenchmarkOperations -benchmem -benchtime=1x -count=3
```

No measurement here establishes production capacity, cloud-policy completeness,
or a practical basis for skipping an approval. For approval semantics, see
[least-privilege-v1.md](least-privilege-v1.md). For the exact proof rules and
trusted checker boundary, see [least-privilege-certificates.md](least-privilege-certificates.md).

## Recorded local run: 2026-09-10

The [raw report](../examples/leastprivilege/benchmarks/2026-09-10-local.json) records
240 successful normal measurements and 80 deadline failures from the separate
1 ns probes. This was Go 1.26.5 on darwin/arm64 with 8 reported logical CPUs,
`GOMAXPROCS=1`, and three repetitions. Collaborating tasks paused Go and Redis
builds during collection; ambient desktop load remained uncontrolled. Hardware
model, RAM, and process inventory could not be read through the sandbox.

These are medians for 20 grants; the raw artifact also contains 4, 8, 12, and 16:

| Pattern | Solve (ms) | Verify (ms) | Generate proof (ms) | Check proof (ms) | Proof nodes |
| --- | ---: | ---: | ---: | ---: | ---: |
| independent | 92.510 | 111.912 | 0.031 | 0.017 | 3 |
| chain | 656.268 | 790.296 | 0.058 | 0.042 | 3 |
| forbidden | 164.947 | 179.077 | 0.052 | 0.034 | 3 |
| sparse_last | 152.475 | 152.911 | 413.104 | 148.092 | 2,097,151 |

At 20 grants each successful solver/verifier run evaluated 1,048,576 subsets.
The sparse-last proof occupied 2,097,392 compact JSON bytes; generation allocated
a median 136,433,400 bytes and checking allocated 37,762,112 bytes. Generation
started 3,670,015 closures; checking started 1,572,865. These are cumulative
allocations and evaluation counts, not peak memory. The three other 20-grant
proofs occupied 244 JSON bytes. The result supports cheap checking for these
particular simple proof trees, while the sparse case shows that proof production
can cost more than exhaustive verification. It supports no general speedup claim.

The [provenance file](../examples/leastprivilege/benchmarks/2026-09-10-local.provenance.json)
contains the report/binary hashes and hashes of the non-test source files used.
It also records a discrepancy: Go's build metadata reported the original
checkout revision `117b3ec`, while `git rev-parse HEAD` in the source worktree
returned `a794704`. Thus the report's `base_revision` is a build-reported value,
not independently verified source provenance. The separate worktree revision
and source hashes identify the measured implementation.
