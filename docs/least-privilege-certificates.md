# Finite optimality certificates

`pkg/leastprivilege/certificate` adds a portable certificate for the explicit
problem in [least-privilege-v1.md](least-privilege-v1.md). An external consumer can
check the certificate without rerunning `Solve` or `Verify`. The producer is
untrusted. The checker separately recomputes feasibility and permission closure
with boolean arrays; the optimizer uses bitsets.

This proves optimality only within the supplied finite model. A certificate
does not establish that the model accurately describes AWS, another cloud, or a
task's needs. It does not authenticate a model, issue a capability, or waive a
human approval. The existing mandate and execution checks still apply.

## Run the producer and checker

```sh
go run ./cmd/asb-leastprivilege solve \
  --problem examples/leastprivilege/problem.json > /tmp/solution.json
go run ./cmd/asb-leastprivilege-proof generate \
  --problem examples/leastprivilege/problem.json \
  --solution /tmp/solution.json > /tmp/proof.json
go run ./cmd/asb-leastprivilege-proof check \
  --problem examples/leastprivilege/problem.json \
  --solution /tmp/solution.json --proof /tmp/proof.json
```

The checker accepts any feasible optimum, including equal-cost grant selections.
Proofs bind a canonical problem digest and a candidate digest. The latter hashes
the existing solution JSON with grant and effective-permission IDs sorted and
empty arrays represented as `[]`, using SHA-256 with a `sha256:` prefix.
These hashes bind content; they provide no identity or trust by themselves.

## Certificate format and checking rules

The JSON schema is `asb.least-privilege.certificate/v1`. The fields are `schema`,
`problem_digest`, `solution_digest`, and `nodes`. `nodes` is a preorder string
over the alphabet `S`, `C`, `F`, `M`.

Sort grants by ID. At tree depth *d*, grants before *d* have fixed absent/present
decisions. All later grants remain free. A split `S` has exactly two children:
absent first, present second, both at depth *d + 1*. A split at depth equal to
the grant count is invalid. Each leaf proves a fact about every completion of
the current decisions:

| Token | Claim recomputed by the checker |
| --- | --- |
| `C` | Closure of the forced grants costs at least the candidate cost. |
| `F` | Closure of the forced grants exceeds `Allowed` or contains a forbidden set. |
| `M` | Even closure of forced grants plus every remaining grant misses a required permission. |

Implications only add permissions. Therefore closure is monotone under grant
addition. Positive permission costs make the forced closure a cost lower bound.
A forced policy violation cannot be repaired by adding grants. Conversely, the
closure containing every remaining grant is an upper bound on what a completion
can supply. These facts justify the three leaf rules. Splits partition a subcube
into disjoint children; recursively checking both children establishes coverage
of every assignment. No leaf can contain a cheaper feasible assignment. Checking
the candidate itself for feasibility and exact cost then establishes global
optimality. At a fully assigned leaf, a feasible cheaper assignment satisfies
none of the rules, so the producer fails with `ErrNotOptimal`.

The checker rejects missing or trailing nodes, unknown tokens, unjustified
claims, mismatched digests, invalid candidates, and invalid models. It does not
trust costs, effective-permission lists, or indices supplied in proof nodes.
There are no such fields. Permission and grant order in the input model does
not change a certificate's interpretation.

## Bounds and trusted code

The model remains limited to 20 grants and 256 permissions. Maximum depth is
20 and maximum node count is 2,097,151. Every node is one ASCII byte. The CLI
limits each input file to 4 MiB, rejects duplicate/unknown JSON keys and trailing
values, and bounds JSON nesting. `--max-nodes` and `--timeout` fail closed; neither
producer failure nor checker failure returns an accepted partial result. The
deadline bounds evaluation after input loading; it is not a filesystem I/O
timeout. Library callers must also bound decoding before calling the API.

The checker calls neither the solver, its evaluator, the exhaustive verifier,
nor the certificate generator. It shares `DigestProblem` for model validation
and canonical hashing. Its own closure evaluator, leaf rules, candidate checks,
tree parser, shared model validation, Go runtime, and SHA-256 implementation are
trusted. Generation and checking share the new boolean-array semantics; only
the producer's tree construction is outside the acceptance path. Tests compare
against the original exact solver/verifier on deterministic generated models.
The checker is ordinary tested Go code, not a machine-verified proof kernel.

This design follows the producer/consumer separation of
[proof-carrying code](https://www.cs.cmu.edu/~fox/pcc.html). Independently
checkable optimization certificates also have prior art, including
[Verifying Integer Programming Results](https://arxiv.org/abs/1611.08832).
This format is a small certificate for this repository's monotone finite model;
it does not implement either paper's proof language or a general IAM logic.

See [the local measurement protocol](least-privilege-performance.md) for proof
generation/checking costs and a case where the tree remains exponential.
