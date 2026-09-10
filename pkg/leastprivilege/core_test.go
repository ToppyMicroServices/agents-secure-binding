// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package leastprivilege

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func basicProblem() Problem {
	return Problem{
		Schema:      ProblemSchemaV1,
		Permissions: []Permission{{ID: "read", Cost: 1}, {ID: "write", Cost: 3}},
		Grants:      []Grant{{ID: "reader", Permissions: []string{"read"}}, {ID: "writer", Permissions: []string{"read", "write"}}},
		Required:    []string{"read"}, Allowed: []string{"read", "write"},
	}
}

func proposed(t *testing.T, p Problem, grants, effective []string, cost uint64) Solution {
	t.Helper()
	digest, err := DigestProblem(p)
	if err != nil {
		t.Fatal(err)
	}
	return Solution{Schema: SolutionSchemaV1, ProblemDigest: digest, Grants: grants, Effective: effective, Cost: cost}
}

func TestSolveAndVerify(t *testing.T) {
	p := basicProblem()
	solution, err := Solve(context.Background(), p, 4)
	if err != nil {
		t.Fatal(err)
	}
	if solution.Cost != 1 || !slices.Equal(solution.Grants, []string{"reader"}) || !slices.Equal(solution.Effective, []string{"read"}) {
		t.Fatalf("unexpected optimum: %+v", solution)
	}
	if err := Verify(context.Background(), p, solution, 4); err != nil {
		t.Fatal(err)
	}
}

func TestImplicationsReachFixedPointAndBlockEscalation(t *testing.T) {
	p := Problem{
		Schema:      ProblemSchemaV1,
		Permissions: []Permission{{"deploy", 1}, {"pass_role", 1}, {"intermediate", 1}, {"admin", 100}, {"helper", 2}},
		Grants:      []Grant{{"dangerous", []string{"deploy", "pass_role"}}, {"limited", []string{"deploy", "helper"}}},
		Required:    []string{"deploy"}, Allowed: []string{"deploy", "pass_role", "intermediate", "helper"},
		Implications: []Implication{
			{AllOf: []string{"intermediate"}, Then: []string{"admin"}},
			{AllOf: []string{"deploy", "pass_role"}, Then: []string{"intermediate"}},
			{AllOf: []string{"admin"}, Then: []string{"intermediate"}}, // A cycle must terminate.
		},
	}
	solution, err := Solve(context.Background(), p, 4)
	if err != nil || solution.Cost != 3 || !slices.Equal(solution.Grants, []string{"limited"}) {
		t.Fatalf("escalation was not excluded: %+v, %v", solution, err)
	}
	bad := proposed(t, p, []string{"dangerous"}, []string{"deploy", "pass_role"}, 2)
	if err := Verify(context.Background(), p, bad, 4); !errors.Is(err, ErrInvalidSolution) {
		t.Fatalf("infeasible escalation accepted: %v", err)
	}
	p.Allowed = append(p.Allowed, "admin")
	p.Required = []string{"admin"}
	solution, err = Solve(context.Background(), p, 4)
	if err != nil || solution.Cost != 103 || !slices.Equal(solution.Effective, []string{"admin", "deploy", "intermediate", "pass_role"}) {
		t.Fatalf("fixed-point permissions/cost incorrect: %+v, %v", solution, err)
	}
}

func TestForbiddenTogetherAndDistinctPermissionCost(t *testing.T) {
	p := Problem{
		Schema:      ProblemSchemaV1,
		Permissions: []Permission{{"read", 1}, {"write", 1}, {"shared", 2}, {"extra", 3}},
		Grants:      []Grant{{"left", []string{"read", "shared"}}, {"right", []string{"write", "shared"}}, {"bundle", []string{"read", "write", "extra"}}},
		Required:    []string{"read", "write"}, Allowed: []string{"read", "write", "shared", "extra"},
	}
	solution, err := Solve(context.Background(), p, 8)
	if err != nil || solution.Cost != 4 || !slices.Equal(solution.Grants, []string{"left", "right"}) {
		t.Fatalf("overlap must be counted once: %+v, %v", solution, err)
	}
	p.ForbiddenTogether = [][]string{{"read", "write", "shared"}}
	solution, err = Solve(context.Background(), p, 8)
	if err != nil || solution.Cost != 5 || !slices.Equal(solution.Grants, []string{"bundle"}) {
		t.Fatalf("conflict must exclude entire group only: %+v, %v", solution, err)
	}
	p.ForbiddenTogether = [][]string{{"read", "write"}}
	if solution, err := Solve(context.Background(), p, 8); !errors.Is(err, ErrInfeasible) || !reflect.DeepEqual(solution, Solution{}) {
		t.Fatalf("expected infeasible with no partial solution: %+v, %v", solution, err)
	}
}

func TestEmptyBoundsAndUnconditionalImplication(t *testing.T) {
	p := Problem{Schema: ProblemSchemaV1}
	solution, err := Solve(context.Background(), p, 1)
	if err != nil || solution.Cost != 0 || len(solution.Effective) != 0 || len(solution.Grants) != 0 {
		t.Fatalf("empty problem should have empty optimum: %+v, %v", solution, err)
	}
	if err := Verify(context.Background(), p, solution, 1); err != nil {
		t.Fatal(err)
	}
	p = basicProblem()
	p.Allowed = nil
	if _, err := Solve(context.Background(), p, 4); !errors.Is(err, ErrInfeasible) {
		t.Fatalf("empty allowed must not mean wildcard: %v", err)
	}
	p.Required = nil
	solution, err = Solve(context.Background(), p, 4)
	if err != nil || solution.Cost != 0 || len(solution.Grants) != 0 {
		t.Fatalf("optional permissions should be omitted: %+v, %v", solution, err)
	}
	p.Implications = []Implication{{AllOf: nil, Then: []string{"read"}}}
	if _, err := Solve(context.Background(), p, 4); !errors.Is(err, ErrInfeasible) {
		t.Fatalf("unconditional implication must respect allowed: %v", err)
	}
	p.Allowed = []string{"read"}
	solution, err = Solve(context.Background(), p, 4)
	if err != nil || solution.Cost != 1 || !slices.Equal(solution.Effective, []string{"read"}) {
		t.Fatalf("unconditional implication omitted: %+v, %v", solution, err)
	}
}

func TestVerifierRejectsForgeryAndCheaperAlternative(t *testing.T) {
	p := basicProblem()
	optimal := proposed(t, p, []string{"reader"}, []string{"read"}, 1)
	tests := map[string]func(*Solution){
		"schema":              func(s *Solution) { s.Schema = "other" },
		"digest":              func(s *Solution) { s.ProblemDigest = "sha256:" + strings.Repeat("0", 64) },
		"cost":                func(s *Solution) { s.Cost = 0 },
		"missing effective":   func(s *Solution) { s.Effective = nil },
		"extra effective":     func(s *Solution) { s.Effective = []string{"read", "write"} },
		"duplicate effective": func(s *Solution) { s.Effective = []string{"read", "read"} },
		"unknown effective":   func(s *Solution) { s.Effective = []string{"unknown"} },
		"duplicate grant":     func(s *Solution) { s.Grants = []string{"reader", "reader"} },
		"unknown grant":       func(s *Solution) { s.Grants = []string{"unknown"} },
		"missing required":    func(s *Solution) { s.Grants = nil; s.Effective = nil; s.Cost = 0 },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := optimal
			change(&candidate)
			if err := Verify(context.Background(), p, candidate, 4); !errors.Is(err, ErrInvalidSolution) {
				t.Fatalf("expected invalid solution: %v", err)
			}
		})
	}
	broader := proposed(t, p, []string{"writer"}, []string{"write", "read"}, 4)
	if err := Verify(context.Background(), p, broader, 4); !errors.Is(err, ErrNotOptimal) {
		t.Fatalf("feasible nonminimum accepted: %v", err)
	}
	// A redundant grant with the same effective permissions is still optimal.
	p.Grants = append(p.Grants, Grant{"reader2", []string{"read"}})
	tied := proposed(t, p, []string{"reader2", "reader"}, []string{"read"}, 1)
	if err := Verify(context.Background(), p, tied, 8); err != nil {
		t.Fatalf("equal-cost selection rejected: %v", err)
	}
}

func TestBudgetsAndCancellationFailClosed(t *testing.T) {
	p := basicProblem()
	solution := proposed(t, p, []string{"reader"}, []string{"read"}, 1)
	for _, budget := range []uint64{0, 1, 3} {
		partial, err := Solve(context.Background(), p, budget)
		if !errors.Is(err, ErrLimit) || !reflect.DeepEqual(partial, Solution{}) {
			t.Fatalf("budget %d exposed partial optimum: %+v, %v", budget, partial, err)
		}
		if err := Verify(context.Background(), p, solution, budget); !errors.Is(err, ErrLimit) {
			t.Fatalf("budget %d accepted unproved optimum: %v", budget, err)
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if partial, err := Solve(canceled, p, 4); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(partial, Solution{}) {
		t.Fatalf("cancellation exposed partial optimum: %+v, %v", partial, err)
	}
	if err := Verify(canceled, p, solution, 4); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled verification accepted: %v", err)
	}
	for _, operation := range []string{"solve", "verify"} {
		t.Run("mid-search "+operation, func(t *testing.T) {
			base, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := &cancelAfterChecks{Context: base, cancel: cancel, remaining: 5}
			if operation == "solve" {
				if partial, err := Solve(ctx, p, 4); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(partial, Solution{}) {
					t.Fatalf("mid-search cancellation: %+v, %v", partial, err)
				}
			} else if err := Verify(ctx, p, solution, 4); !errors.Is(err, context.Canceled) {
				t.Fatalf("mid-search verification cancellation: %v", err)
			}
		})
	}
	if _, err := Solve(nil, p, 4); !errors.Is(err, ErrInvalidProblem) {
		t.Fatalf("nil context: %v", err)
	}
	if err := Verify(nil, p, solution, 4); !errors.Is(err, ErrInvalidProblem) {
		t.Fatalf("nil verifier context: %v", err)
	}
}

type cancelAfterChecks struct {
	context.Context
	cancel    context.CancelFunc
	remaining int
}

func (c *cancelAfterChecks) Err() error {
	c.remaining--
	if c.remaining <= 0 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestDigestCanonicalizationAndNoMutation(t *testing.T) {
	p := basicProblem()
	p.Implications = []Implication{{AllOf: []string{"write", "read"}, Then: []string{"write"}}}
	p.ForbiddenTogether = [][]string{{"write", "read"}}
	before, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := DigestProblem(p)
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("digest calculation mutated input slices")
	}
	slices.Reverse(p.Permissions)
	slices.Reverse(p.Grants)
	slices.Reverse(p.Grants[0].Permissions)
	slices.Reverse(p.Allowed)
	slices.Reverse(p.Implications[0].AllOf)
	slices.Reverse(p.ForbiddenTogether[0])
	reordered, err := DigestProblem(p)
	if err != nil || reordered != digest {
		t.Fatalf("set ordering changed digest: %s versus %s, %v", digest, reordered, err)
	}
	p.Permissions[0].Cost++
	changed, err := DigestProblem(p)
	if err != nil || changed == digest {
		t.Fatalf("cost change did not alter digest: %v", err)
	}
	empty := Problem{Schema: ProblemSchemaV1}
	emptyDigest, err := DigestProblem(empty)
	if err != nil {
		t.Fatal(err)
	}
	canonical := `{"schema":"asb.least-privilege.problem/v1","permissions":[],"grants":[],"required":[],"allowed":[],"implications":[],"forbidden_together":[]}`
	hash := sha256.Sum256([]byte(canonical))
	if emptyDigest != "sha256:"+hex.EncodeToString(hash[:]) {
		t.Fatalf("unexpected canonical empty problem digest: %s", emptyDigest)
	}
	empty.Permissions = []Permission{}
	empty.Grants = []Grant{}
	empty.Required, empty.Allowed = []string{}, []string{}
	empty.Implications, empty.ForbiddenTogether = []Implication{}, [][]string{}
	if digest, err := DigestProblem(empty); err != nil || digest != emptyDigest {
		t.Fatalf("empty/nil representation changes digest: %s, %v", digest, err)
	}
}

func TestProblemValidation(t *testing.T) {
	tests := map[string]func(*Problem){
		"schema":                    func(p *Problem) { p.Schema = "" },
		"zero cost":                 func(p *Problem) { p.Permissions[0].Cost = 0 },
		"overflow":                  func(p *Problem) { p.Permissions[0].Cost = math.MaxUint64 },
		"empty ID":                  func(p *Problem) { p.Permissions[0].ID = "" },
		"long ID":                   func(p *Problem) { p.Permissions[0].ID = strings.Repeat("x", MaxIDBytes+1) },
		"control ID":                func(p *Problem) { p.Permissions[0].ID = "bad\x00" },
		"space ID":                  func(p *Problem) { p.Permissions[0].ID = "bad id" },
		"non-UTF8 ID":               func(p *Problem) { p.Permissions[0].ID = "\xff" },
		"duplicate permission":      func(p *Problem) { p.Permissions = append(p.Permissions, p.Permissions[0]) },
		"duplicate grant":           func(p *Problem) { p.Grants = append(p.Grants, p.Grants[0]) },
		"invalid grant":             func(p *Problem) { p.Grants[0].ID = " " },
		"unknown grant reference":   func(p *Problem) { p.Grants[0].Permissions = []string{"missing"} },
		"duplicate grant reference": func(p *Problem) { p.Grants[0].Permissions = []string{"read", "read"} },
		"unknown required":          func(p *Problem) { p.Required = []string{"missing"} },
		"duplicate allowed":         func(p *Problem) { p.Allowed = []string{"read", "read"} },
		"empty rule consequence":    func(p *Problem) { p.Implications = []Implication{{AllOf: []string{"read"}}} },
		"unknown rule premise":      func(p *Problem) { p.Implications = []Implication{{AllOf: []string{"missing"}, Then: []string{"read"}}} },
		"unknown rule consequence":  func(p *Problem) { p.Implications = []Implication{{AllOf: []string{"read"}, Then: []string{"missing"}}} },
		"duplicate rule": func(p *Problem) {
			p.Implications = []Implication{{AllOf: []string{"read", "write"}, Then: []string{"read"}}, {AllOf: []string{"write", "read"}, Then: []string{"read"}}}
		},
		"short forbidden":      func(p *Problem) { p.ForbiddenTogether = [][]string{{"read"}} },
		"unknown forbidden":    func(p *Problem) { p.ForbiddenTogether = [][]string{{"read", "missing"}} },
		"duplicate forbidden":  func(p *Problem) { p.ForbiddenTogether = [][]string{{"read", "write"}, {"write", "read"}} },
		"too many permissions": func(p *Problem) { p.Permissions = make([]Permission, MaxPermissions+1) },
		"too many grants":      func(p *Problem) { p.Grants = make([]Grant, MaxGrants+1) },
		"too many rules":       func(p *Problem) { p.Implications = make([]Implication, MaxImplications+1) },
		"too many conflicts":   func(p *Problem) { p.ForbiddenTogether = make([][]string, MaxForbiddenSets+1) },
		"too many references":  func(p *Problem) { p.Allowed = make([]string, MaxPermissions+1) },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			p := basicProblem()
			change(&p)
			if _, err := DigestProblem(p); !errors.Is(err, ErrInvalidProblem) {
				t.Fatalf("expected invalid problem: %v", err)
			}
			if solution, err := Solve(context.Background(), p, 4); !errors.Is(err, ErrInvalidProblem) || !reflect.DeepEqual(solution, Solution{}) {
				t.Fatalf("invalid model produced solution: %+v, %v", solution, err)
			}
		})
	}
	p := Problem{Schema: ProblemSchemaV1, Permissions: []Permission{{"only", math.MaxUint64}}, Grants: []Grant{{"only", []string{"only"}}}, Required: []string{"only"}, Allowed: []string{"only"}}
	if solution, err := Solve(context.Background(), p, 2); err != nil || solution.Cost != math.MaxUint64 {
		t.Fatalf("maximum nonoverflowing cost rejected: %+v, %v", solution, err)
	}
}

func TestPermissionUniverseBoundary(t *testing.T) {
	p := Problem{Schema: ProblemSchemaV1}
	for i := 0; i < MaxPermissions; i++ {
		id := fmt.Sprintf("p%03d", i)
		p.Permissions = append(p.Permissions, Permission{ID: id, Cost: 1})
		p.Allowed = append(p.Allowed, id)
	}
	p.Grants = []Grant{{ID: "all", Permissions: slices.Clone(p.Allowed)}}
	p.Required = []string{"p000", "p255"}
	solution, err := Solve(context.Background(), p, 2)
	if err != nil || solution.Cost != MaxPermissions || len(solution.Effective) != MaxPermissions {
		t.Fatalf("full permission universe evaluated incorrectly: %+v, %v", solution, err)
	}
	if err := Verify(context.Background(), p, solution, 2); err != nil {
		t.Fatalf("full universe optimum rejected: %v", err)
	}
	p.Allowed = p.Allowed[:MaxPermissions-1]
	if _, err := Solve(context.Background(), p, 2); !errors.Is(err, ErrInfeasible) {
		t.Fatalf("permission in final bit escaped allowed bound: %v", err)
	}
}

// This oracle intentionally uses maps and the original unsorted input. It
// shares no normalization, bitsets, closure evaluator, or cost code with the
// production implementation.
func oracleMinimum(p Problem) (uint64, bool) {
	var minimum uint64
	found := false
	for mask := 0; mask < 1<<len(p.Grants); mask++ {
		effective := map[string]bool{}
		for i, grant := range p.Grants {
			if mask&(1<<i) != 0 {
				for _, permission := range grant.Permissions {
					effective[permission] = true
				}
			}
		}
		for changed := true; changed; {
			changed = false
			for _, rule := range p.Implications {
				trigger := true
				for _, permission := range rule.AllOf {
					trigger = trigger && effective[permission]
				}
				if trigger {
					for _, permission := range rule.Then {
						if !effective[permission] {
							effective[permission], changed = true, true
						}
					}
				}
			}
		}
		feasible := true
		for _, permission := range p.Required {
			feasible = feasible && effective[permission]
		}
		for permission := range effective {
			feasible = feasible && slices.Contains(p.Allowed, permission)
		}
		for _, conflict := range p.ForbiddenTogether {
			violates := true
			for _, permission := range conflict {
				violates = violates && effective[permission]
			}
			feasible = feasible && !violates
		}
		if !feasible {
			continue
		}
		var cost uint64
		for _, permission := range p.Permissions {
			if effective[permission.ID] {
				cost += permission.Cost
			}
		}
		if !found || cost < minimum {
			minimum, found = cost, true
		}
	}
	return minimum, found
}

func TestRandomProblemsAgainstIndependentOracle(t *testing.T) {
	rng := rand.New(rand.NewSource(20260910))
	for run := 0; run < 200; run++ {
		p := Problem{Schema: ProblemSchemaV1}
		for i := 0; i < 6; i++ {
			id := fmt.Sprintf("p%d", i)
			p.Permissions = append(p.Permissions, Permission{id, uint64(1 + rng.Intn(20))})
			if rng.Intn(4) != 0 {
				p.Allowed = append(p.Allowed, id)
			}
			if rng.Intn(3) == 0 {
				p.Required = append(p.Required, id)
			}
		}
		for i, count := 0, rng.Intn(7); i < count; i++ {
			grant := Grant{ID: fmt.Sprintf("g%d", i)}
			for _, permission := range p.Permissions {
				if rng.Intn(3) == 0 {
					grant.Permissions = append(grant.Permissions, permission.ID)
				}
			}
			p.Grants = append(p.Grants, grant)
		}
		// Distinct consequences guarantee unique rules, even with empty premises.
		for i := 0; i < 4; i++ {
			rule := Implication{Then: []string{fmt.Sprintf("p%d", i)}}
			for _, permission := range p.Permissions {
				if rng.Intn(4) == 0 {
					rule.AllOf = append(rule.AllOf, permission.ID)
				}
			}
			p.Implications = append(p.Implications, rule)
		}
		if rng.Intn(2) == 0 {
			p.ForbiddenTogether = [][]string{{"p4", "p5"}}
		}
		wantCost, feasible := oracleMinimum(p)
		solution, err := Solve(context.Background(), p, uint64(1)<<uint(len(p.Grants)))
		if !feasible {
			if !errors.Is(err, ErrInfeasible) {
				t.Fatalf("run %d: oracle infeasible, got %+v, %v", run, solution, err)
			}
			continue
		}
		if err != nil || solution.Cost != wantCost {
			t.Fatalf("run %d: want cost %d, got %+v, %v", run, wantCost, solution, err)
		}
		if err := Verify(context.Background(), p, solution, uint64(1)<<uint(len(p.Grants))); err != nil {
			t.Fatalf("run %d: verifier rejected oracle optimum: %v", run, err)
		}
	}
}
