// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package certificate

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"testing"
	"time"

	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
)

func example() lp.Problem {
	return lp.Problem{
		Schema:      lp.ProblemSchemaV1,
		Permissions: []lp.Permission{{ID: "read", Cost: 1}, {ID: "write", Cost: 7}},
		Grants:      []lp.Grant{{ID: "editor", Permissions: []string{"read", "write"}}, {ID: "reader", Permissions: []string{"read"}}, {ID: "reader2", Permissions: []string{"read"}}},
		Required:    []string{"read"}, Allowed: []string{"read", "write"},
	}
}

func optimum(t *testing.T, p lp.Problem) lp.Solution {
	t.Helper()
	s, err := lp.Solve(context.Background(), p, 1<<lp.MaxGrants)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCheckRoundTripAndEqualCost(t *testing.T) {
	p := example()
	for _, grants := range [][]string{{"reader"}, {"reader2"}, {"reader", "reader2"}} {
		s := optimum(t, p)
		s.Grants = grants
		proof, generated, err := Generate(context.Background(), p, s, MaxNodes)
		if err != nil {
			t.Fatal(err)
		}
		checked, err := Check(context.Background(), p, s, proof, MaxNodes)
		if err != nil || checked.Nodes != generated.Nodes || checked.Closures == 0 {
			t.Fatalf("%+v %v", checked, err)
		}
		p.Grants = slices.Clone(p.Grants)
		slices.Reverse(p.Grants)
		if _, err := Check(context.Background(), p, s, proof, MaxNodes); err != nil {
			t.Fatalf("order changed semantics: %v", err)
		}
	}
}

func TestRejectMalformedAndTamperedProofs(t *testing.T) {
	p := example()
	s := optimum(t, p)
	proof, _, err := Generate(context.Background(), p, s, MaxNodes)
	if err != nil {
		t.Fatal(err)
	}
	for name, nodes := range map[string]string{"missing": "", "truncated": proof.Nodes[:len(proof.Nodes)-1], "trailing": proof.Nodes + "C", "unknown": "X", "false_cost": "C", "false_forbidden": "F", "false_missing": "M", "overdeep": strings.Repeat("S", len(p.Grants)+1), "oversize": strings.Repeat("C", MaxNodes+1)} {
		t.Run(name, func(t *testing.T) {
			bad := proof
			bad.Nodes = nodes
			if _, err := Check(context.Background(), p, s, bad, MaxNodes); err == nil {
				t.Fatal("accepted malformed proof")
			}
		})
	}
	for _, field := range []string{"schema", "problem", "solution"} {
		bad := proof
		switch field {
		case "schema":
			bad.Schema = "unsupported-schema"
		case "problem":
			bad.ProblemDigest = "other-problem"
		case "solution":
			bad.SolutionDigest = "other-candidate"
		}
		if _, err := Check(context.Background(), p, s, bad, MaxNodes); err == nil {
			t.Fatalf("accepted changed %s", field)
		}
	}
	for _, change := range []func(*lp.Solution){func(s *lp.Solution) { s.Cost++ }, func(s *lp.Solution) { s.Grants = []string{"unknown"} }, func(s *lp.Solution) { s.Grants = []string{"reader", "reader"} }, func(s *lp.Solution) { s.Effective = []string{"read", "read"} }, func(s *lp.Solution) { s.Effective = []string{"read", "write"} }} {
		bad := s
		change(&bad)
		if _, err := Check(context.Background(), p, bad, proof, MaxNodes); err == nil {
			t.Fatal("accepted tampered candidate")
		}
	}
}

func TestRejectSuboptimalCandidate(t *testing.T) {
	p := example()
	s := optimum(t, p)
	s.Grants = []string{"editor"}
	s.Effective = []string{"read", "write"}
	s.Cost = 8
	proof, stats, err := Generate(context.Background(), p, s, MaxNodes)
	if !errors.Is(err, lp.ErrNotOptimal) || proof.Schema != "" || stats.Nodes == 0 {
		t.Fatalf("%+v %+v %v", proof, stats, err)
	}
	// A lying producer's single C leaf must not establish optimality.
	var st Stats
	m, err := prepare(context.Background(), p, s, &st)
	if err != nil {
		t.Fatal(err)
	}
	bad := Proof{Schema: Schema, ProblemDigest: m.digest, SolutionDigest: m.solutionDigest, Nodes: "C"}
	if _, err := Check(context.Background(), p, s, bad, MaxNodes); !errors.Is(err, ErrInvalidProof) {
		t.Fatal(err)
	}
}

func TestEmptyAndUnconditionalModels(t *testing.T) {
	cases := []lp.Problem{
		{Schema: lp.ProblemSchemaV1},
		{Schema: lp.ProblemSchemaV1, Permissions: []lp.Permission{{ID: "p", Cost: 2}}, Allowed: []string{"p"}, Required: []string{"p"}, Implications: []lp.Implication{{Then: []string{"p"}}}},
		{Schema: lp.ProblemSchemaV1, Permissions: []lp.Permission{{ID: "p", Cost: 2}}, Grants: []lp.Grant{{ID: "nope", Permissions: []string{"p"}}}},
	}
	for _, p := range cases {
		s := optimum(t, p)
		proof, _, err := Generate(context.Background(), p, s, MaxNodes)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Check(context.Background(), p, s, proof, MaxNodes); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLimitsAndCancellation(t *testing.T) {
	p := example()
	s := optimum(t, p)
	proof, _, err := Generate(context.Background(), p, s, MaxNodes)
	if err != nil {
		t.Fatal(err)
	}
	for _, budget := range []uint64{0, 1} {
		partial, _, err := Generate(context.Background(), p, s, budget)
		if !errors.Is(err, lp.ErrLimit) || partial.Schema != "" {
			t.Fatal("usable partial proof", err)
		}
		if _, err := Check(context.Background(), p, s, proof, budget); !errors.Is(err, lp.ErrLimit) {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := Generate(ctx, p, s, MaxNodes); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := Check(ctx, p, s, proof, MaxNodes); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	deadline, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if _, err := Check(deadline, p, s, proof, MaxNodes); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if _, _, err := Generate(nil, p, s, MaxNodes); !errors.Is(err, lp.ErrInvalidProblem) {
		t.Fatal(err)
	}
	if _, err := Check(nil, p, s, proof, MaxNodes); !errors.Is(err, lp.ErrInvalidProblem) {
		t.Fatal(err)
	}
	p.Permissions[0].Cost = 0
	if _, _, err := Generate(context.Background(), p, s, MaxNodes); !errors.Is(err, lp.ErrInvalidProblem) {
		t.Fatal(err)
	}
}

func TestExactOracleDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(73021))
	accepted, infeasible := 0, 0
	for trial := 0; trial < 300; trial++ {
		n := 1 + rng.Intn(7)
		p := lp.Problem{Schema: lp.ProblemSchemaV1}
		for i := 0; i < n; i++ {
			id := fmt.Sprintf("p%d", i)
			p.Permissions = append(p.Permissions, lp.Permission{ID: id, Cost: uint64(1 + rng.Intn(7))})
			if rng.Intn(5) != 0 {
				p.Allowed = append(p.Allowed, id)
			}
			if rng.Intn(4) == 0 {
				p.Required = append(p.Required, id)
			}
		}
		for i := 0; i < 1+rng.Intn(7); i++ {
			g := lp.Grant{ID: fmt.Sprintf("g%d", i)}
			for _, permission := range p.Permissions {
				if rng.Intn(3) == 0 {
					g.Permissions = append(g.Permissions, permission.ID)
				}
			}
			p.Grants = append(p.Grants, g)
		}
		// Unique consequents make rules distinct; cycles and empty premises occur.
		for i := 0; i < n; i++ {
			if rng.Intn(2) == 0 {
				r := lp.Implication{Then: []string{p.Permissions[i].ID}}
				for _, permission := range p.Permissions {
					if rng.Intn(4) == 0 {
						r.AllOf = append(r.AllOf, permission.ID)
					}
				}
				p.Implications = append(p.Implications, r)
			}
		}
		for i := 1; i < n; i++ {
			if rng.Intn(3) == 0 {
				p.ForbiddenTogether = append(p.ForbiddenTogether, []string{p.Permissions[i-1].ID, p.Permissions[i].ID})
			}
		}
		s, err := lp.Solve(context.Background(), p, 1<<lp.MaxGrants)
		if errors.Is(err, lp.ErrInfeasible) {
			digest, digestErr := lp.DigestProblem(p)
			if digestErr != nil {
				t.Fatal(digestErr)
			}
			forged := lp.Solution{Schema: lp.SolutionSchemaV1, ProblemDigest: digest}
			if _, _, err := Generate(context.Background(), p, forged, MaxNodes); !errors.Is(err, lp.ErrInvalidSolution) {
				t.Fatalf("infeasible model accepted a candidate: %v", err)
			}
			infeasible++
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := lp.Verify(context.Background(), p, s, 1<<lp.MaxGrants); err != nil {
			t.Fatal(err)
		}
		proof, _, err := Generate(context.Background(), p, s, MaxNodes)
		if err != nil {
			t.Fatalf("trial %d: %v", trial, err)
		}
		if _, err := Check(context.Background(), p, s, proof, MaxNodes); err != nil {
			t.Fatalf("trial %d: %v", trial, err)
		}
		if trial < 80 {
			checkAlternativeSelections(t, p, s)
		}
		accepted++
	}
	if accepted < 30 || infeasible < 30 {
		t.Fatalf("insufficient variation: %d %d", accepted, infeasible)
	}
}

func checkAlternativeSelections(t *testing.T, p lp.Problem, optimum lp.Solution) {
	t.Helper()
	var stats Stats
	m, err := prepare(context.Background(), p, optimum, &stats)
	if err != nil {
		t.Fatal(err)
	}
	for mask := 0; mask < 1<<len(m.grants); mask++ {
		selected := make([]bool, len(m.grants))
		candidate := lp.Solution{Schema: lp.SolutionSchemaV1, ProblemDigest: m.digest}
		for i, grant := range m.grants {
			selected[i] = mask&(1<<i) != 0
			if selected[i] {
				candidate.Grants = append(candidate.Grants, grant.ID)
			}
		}
		effective, err := m.close(context.Background(), selected, &stats)
		if err != nil {
			t.Fatal(err)
		}
		if m.violates(effective) || !contains(effective, m.required) {
			continue
		}
		candidate.Cost = m.weight(effective)
		for i, yes := range effective {
			if yes {
				candidate.Effective = append(candidate.Effective, m.permissions[i].ID)
			}
		}
		// Verify recomputes this candidate using the original bitset evaluator.
		// An incorrect closure/cost in the new evaluator fails this comparison.
		oracleErr := lp.Verify(context.Background(), p, candidate, 1<<lp.MaxGrants)
		proof, _, proofErr := Generate(context.Background(), p, candidate, MaxNodes)
		if oracleErr == nil {
			if proofErr != nil {
				t.Fatalf("oracle optimum rejected: %v", proofErr)
			}
			if _, err := Check(context.Background(), p, candidate, proof, MaxNodes); err != nil {
				t.Fatal(err)
			}
		} else if !errors.Is(oracleErr, lp.ErrNotOptimal) || !errors.Is(proofErr, lp.ErrNotOptimal) {
			t.Fatalf("candidate semantics or optimum disagreement: oracle=%v producer=%v", oracleErr, proofErr)
		}
	}
}

// errAfter makes cancellation deterministic inside the traversal, without a
// timing-sensitive sleep or a goroutine mutating the problem under validation.
type errAfter struct {
	context.Context
	calls, limit int
}

func (c *errAfter) Err() error {
	c.calls++
	if c.calls > c.limit {
		return context.Canceled
	}
	return nil
}

func TestCancellationDuringProofTraversal(t *testing.T) {
	p := lp.Problem{Schema: lp.ProblemSchemaV1, Permissions: []lp.Permission{{ID: "p", Cost: 1}}, Allowed: []string{"p"}, Required: []string{"p"}}
	for i := 0; i < 10; i++ {
		p.Grants = append(p.Grants, lp.Grant{ID: fmt.Sprintf("g%02d", i)})
	}
	p.Grants[9].Permissions = []string{"p"}
	s := optimum(t, p)
	proof, _, err := Generate(context.Background(), p, s, MaxNodes)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &errAfter{Context: context.Background(), limit: 80}
	partial, stats, err := Generate(ctx, p, s, MaxNodes)
	if !errors.Is(err, context.Canceled) || partial.Schema != "" || stats.Nodes == 0 {
		t.Fatalf("generation did not fail closed mid-tree: %+v %v", stats, err)
	}
	ctx = &errAfter{Context: context.Background(), limit: 80}
	stats, err = Check(ctx, p, s, proof, MaxNodes)
	if !errors.Is(err, context.Canceled) || stats.Nodes == 0 {
		t.Fatalf("checking did not fail closed mid-tree: %+v %v", stats, err)
	}
}

func TestLeafClaimsAndSubcubeCoverage(t *testing.T) {
	// Required z sorts last. Empty earlier grants prevent bound pruning, so every
	// branch must be supplied. An allowed-set violation separately exercises F.
	p := lp.Problem{Schema: lp.ProblemSchemaV1, Permissions: []lp.Permission{{ID: "need", Cost: 2}, {ID: "bad", Cost: 1}}, Required: []string{"need"}, Allowed: []string{"need"}, Grants: []lp.Grant{{ID: "a"}, {ID: "b", Permissions: []string{"bad"}}, {ID: "z", Permissions: []string{"need"}}}}
	s := optimum(t, p)
	proof, _, err := Generate(context.Background(), p, s, MaxNodes)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range []string{"S", "C", "F", "M"} {
		if !strings.Contains(proof.Nodes, node) {
			t.Fatalf("missing %s in %s", node, proof.Nodes)
		}
	}
	if _, err := Check(context.Background(), p, s, proof, MaxNodes); err != nil {
		t.Fatal(err)
	}
	for i := range proof.Nodes {
		bad := proof
		bad.Nodes = proof.Nodes[:i] + proof.Nodes[i+1:]
		if _, err := Check(context.Background(), p, s, bad, MaxNodes); err == nil {
			t.Fatalf("accepted deletion at %d", i)
		}
	}
}

func FuzzRejectSuboptimalCertificate(f *testing.F) {
	p := example()
	digest, err := lp.DigestProblem(p)
	if err != nil {
		f.Fatal(err)
	}
	// The editor is feasible at cost 8, but the reader costs 1. No complete tree
	// can prove this candidate optimal, regardless of how its nodes are supplied.
	s := lp.Solution{Schema: lp.SolutionSchemaV1, ProblemDigest: digest, Grants: []string{"editor"}, Effective: []string{"read", "write"}, Cost: 8}
	var stats Stats
	m, err := prepare(context.Background(), p, s, &stats)
	if err != nil {
		f.Fatal(err)
	}
	for _, nodes := range []string{"C", "F", "M", "SCC", "SSMCSMCC", "SSSS", "", "\xff"} {
		f.Add(nodes)
	}
	f.Fuzz(func(t *testing.T, nodes string) {
		if len(nodes) > 32 {
			t.Skip()
		}
		proof := Proof{Schema: Schema, ProblemDigest: digest, SolutionDigest: m.solutionDigest, Nodes: nodes}
		if _, err := Check(context.Background(), p, s, proof, MaxNodes); err == nil {
			t.Fatalf("accepted a proof of a strictly suboptimal candidate: %q", nodes)
		}
	})
}
