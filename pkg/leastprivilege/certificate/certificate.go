// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Package certificate produces and checks finite least-privilege proof trees.
// Its boolean-array evaluator is separate from the optimizer's bitset evaluator.
// The shared trusted boundary is DigestProblem's validation and canonical hash.
package certificate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
)

const (
	Schema   = "asb.least-privilege.certificate/v1"
	MaxNodes = (1 << (lp.MaxGrants + 1)) - 1
)

var ErrInvalidProof = errors.New("invalid least-privilege certificate")

// Proof.Nodes is a preorder tree. S splits on the next grant in sorted ID order,
// visiting absent before present. C proves the forced cost lower bound; F proves
// a forced policy violation; M proves no completion can supply every requirement.
// Leaf claims are recomputed. No node carries a trusted cost or permission set.
type Proof struct {
	Schema         string `json:"schema"`
	ProblemDigest  string `json:"problem_digest"`
	SolutionDigest string `json:"solution_digest"`
	Nodes          string `json:"nodes"`
}

// Stats counts visited proof nodes and started fixed-point closure evaluations,
// including the candidate evaluation. It is returned even on failure.
type Stats struct {
	Nodes    uint64 `json:"nodes"`
	Closures uint64 `json:"closures"`
}

type (
	rule  struct{ all, then []int }
	model struct {
		permissions            []lp.Permission
		grants                 []lp.Grant
		grantSets              [][]int
		required, allowed      []int
		rules                  []rule
		forbidden              [][]int
		digest, solutionDigest string
		cost                   uint64
	}
)

// prepare shares only input validation and canonical hashing with the optimizer.
// It never reads the optimizer's compiled representation or evaluation results.
func prepare(ctx context.Context, p lp.Problem, s lp.Solution, stats *Stats) (*model, error) {
	if ctx == nil {
		return nil, lp.ErrInvalidProblem
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	digest, err := lp.DigestProblem(p)
	if err != nil {
		return nil, err
	}
	if s.Schema != lp.SolutionSchemaV1 || s.ProblemDigest != digest || len(s.Grants) > len(p.Grants) || len(s.Effective) > len(p.Permissions) {
		return nil, lp.ErrInvalidSolution
	}
	m := &model{permissions: slices.Clone(p.Permissions), grants: slices.Clone(p.Grants), digest: digest, cost: s.Cost}
	slices.SortFunc(m.permissions, func(a, b lp.Permission) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(m.grants, func(a, b lp.Grant) int { return strings.Compare(a.ID, b.ID) })
	index := make(map[string]int, len(m.permissions))
	for i, permission := range m.permissions {
		index[permission.ID] = i
	}
	refs := func(ids []string) []int {
		out := make([]int, len(ids))
		for i, id := range ids {
			out[i] = index[id]
		}
		return out
	}
	m.required, m.allowed = refs(p.Required), refs(p.Allowed)
	for _, grant := range m.grants {
		m.grantSets = append(m.grantSets, refs(grant.Permissions))
	}
	for _, r := range p.Implications {
		m.rules = append(m.rules, rule{refs(r.AllOf), refs(r.Then)})
	}
	for _, f := range p.ForbiddenTogether {
		m.forbidden = append(m.forbidden, refs(f))
	}
	selected := make([]bool, len(m.grants))
	for _, id := range s.Grants {
		i := slices.IndexFunc(m.grants, func(g lp.Grant) bool { return g.ID == id })
		if i < 0 || selected[i] {
			return nil, lp.ErrInvalidSolution
		}
		selected[i] = true
	}
	effective, err := m.close(ctx, selected, stats)
	if err != nil {
		return nil, err
	}
	if m.violates(effective) || !contains(effective, m.required) || m.weight(effective) != s.Cost {
		return nil, lp.ErrInvalidSolution
	}
	actual := make([]string, 0, len(m.permissions))
	for i, yes := range effective {
		if yes {
			actual = append(actual, m.permissions[i].ID)
		}
	}
	claimed := slices.Clone(s.Effective)
	slices.Sort(claimed)
	if !slices.Equal(actual, claimed) {
		return nil, lp.ErrInvalidSolution
	}
	normalized := s
	normalized.Grants, normalized.Effective = make([]string, len(s.Grants)), actual
	copy(normalized.Grants, s.Grants)
	slices.Sort(normalized.Grants)
	raw, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(raw)
	m.solutionDigest = "sha256:" + hex.EncodeToString(hash[:])
	return m, ctx.Err()
}

func contains(effective []bool, ids []int) bool {
	for _, id := range ids {
		if !effective[id] {
			return false
		}
	}
	return true
}

func (m *model) close(ctx context.Context, selected []bool, stats *Stats) ([]bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stats.Closures++
	effective := make([]bool, len(m.permissions))
	for i, yes := range selected {
		if yes {
			for _, id := range m.grantSets[i] {
				effective[id] = true
			}
		}
	}
	for {
		changed := false
		for _, r := range m.rules {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if contains(effective, r.all) {
				for _, id := range r.then {
					if !effective[id] {
						effective[id], changed = true, true
					}
				}
			}
		}
		if !changed {
			return effective, ctx.Err()
		}
	}
}

func (m *model) weight(effective []bool) uint64 {
	var cost uint64
	for i, yes := range effective {
		if yes {
			cost += m.permissions[i].Cost
		}
	}
	return cost // DigestProblem checked the sum of the entire universe for overflow.
}

func (m *model) violates(effective []bool) bool {
	allowed := make([]bool, len(effective))
	for _, id := range m.allowed {
		allowed[id] = true
	}
	for i, yes := range effective {
		if yes && !allowed[i] {
			return true
		}
	}
	for _, group := range m.forbidden {
		if contains(effective, group) {
			return true
		}
	}
	return false
}

// reason proves a monotone lower/upper-bound fact for the subcube at depth.
func (m *model) reason(ctx context.Context, selected []bool, depth int, stats *Stats) (byte, error) {
	forced, err := m.close(ctx, selected, stats)
	if err != nil {
		return 0, err
	}
	if m.weight(forced) >= m.cost {
		return 'C', nil
	}
	if m.violates(forced) {
		return 'F', nil
	}
	maximum := slices.Clone(selected)
	for i := depth; i < len(maximum); i++ {
		maximum[i] = true
	}
	possible, err := m.close(ctx, maximum, stats)
	if err != nil {
		return 0, err
	}
	if !contains(possible, m.required) {
		return 'M', nil
	}
	return 0, nil
}

// Generate constructs evidence for a feasible optimum supplied by any producer.
// A cheaper feasible leaf returns ErrNotOptimal. Failure returns no usable proof.
// maxNodes is a positive work budget, additionally bounded by the model size.
func Generate(ctx context.Context, p lp.Problem, s lp.Solution, maxNodes uint64) (Proof, Stats, error) {
	var stats Stats
	if maxNodes == 0 {
		return Proof{}, stats, lp.ErrLimit
	}
	m, err := prepare(ctx, p, s, &stats)
	if err != nil {
		return Proof{}, stats, err
	}
	var nodes strings.Builder
	selected := make([]bool, len(m.grants))
	var visit func(int) error
	visit = func(depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if stats.Nodes >= maxNodes {
			return lp.ErrLimit
		}
		stats.Nodes++
		reason, err := m.reason(ctx, selected, depth, &stats)
		if err != nil {
			return err
		}
		if reason != 0 {
			nodes.WriteByte(reason)
			return nil
		}
		if depth == len(selected) {
			return lp.ErrNotOptimal
		}
		nodes.WriteByte('S')
		if err := visit(depth + 1); err != nil {
			return err
		}
		selected[depth] = true
		err = visit(depth + 1)
		selected[depth] = false
		return err
	}
	if err := visit(0); err != nil {
		return Proof{}, stats, err
	}
	if err := ctx.Err(); err != nil {
		return Proof{}, stats, err
	}
	return Proof{Schema: Schema, ProblemDigest: m.digest, SolutionDigest: m.solutionDigest, Nodes: nodes.String()}, stats, nil
}

// Check independently replays a bounded proof. It calls neither Solve nor Verify.
// It accepts only complete trees whose leaves cover every grant assignment and
// prove it infeasible or no cheaper than the independently validated candidate.
// A certificate never authorizes an action or changes the mandate/human gate.
func Check(ctx context.Context, p lp.Problem, s lp.Solution, proof Proof, maxNodes uint64) (Stats, error) {
	var stats Stats
	if maxNodes == 0 {
		return stats, lp.ErrLimit
	}
	if proof.Schema != Schema || len(proof.Nodes) == 0 || len(proof.Nodes) > MaxNodes {
		return stats, ErrInvalidProof
	}
	if uint64(len(proof.Nodes)) > maxNodes {
		return stats, lp.ErrLimit
	}
	m, err := prepare(ctx, p, s, &stats)
	if err != nil {
		return stats, err
	}
	if proof.ProblemDigest != m.digest || proof.SolutionDigest != m.solutionDigest || len(proof.Nodes) > (1<<(len(m.grants)+1))-1 {
		return stats, ErrInvalidProof
	}
	selected := make([]bool, len(m.grants))
	var visit func(int) error
	visit = func(depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if stats.Nodes >= uint64(len(proof.Nodes)) {
			return ErrInvalidProof
		}
		node := proof.Nodes[stats.Nodes]
		stats.Nodes++
		if node == 'S' {
			if depth == len(selected) {
				return ErrInvalidProof
			}
			if err := visit(depth + 1); err != nil {
				return err
			}
			selected[depth] = true
			err := visit(depth + 1)
			selected[depth] = false
			return err
		}
		if node != 'C' && node != 'F' && node != 'M' {
			return ErrInvalidProof
		}
		// Each opcode checks its own claim; a producer need not use our order.
		forced, err := m.close(ctx, selected, &stats)
		if err != nil {
			return err
		}
		valid := false
		switch node {
		case 'C':
			valid = m.weight(forced) >= m.cost
		case 'F':
			valid = m.violates(forced)
		case 'M':
			for i := depth; i < len(selected); i++ {
				selected[i] = true
			}
			possible, closeErr := m.close(ctx, selected, &stats)
			for i := depth; i < len(selected); i++ {
				selected[i] = false
			}
			if closeErr != nil {
				return closeErr
			}
			valid = !contains(possible, m.required)
		}
		if !valid {
			return fmt.Errorf("%w: unjustified %c leaf at depth %d", ErrInvalidProof, node, depth)
		}
		return nil
	}
	if err := visit(0); err != nil {
		return stats, err
	}
	if stats.Nodes != uint64(len(proof.Nodes)) {
		return stats, ErrInvalidProof
	}
	return stats, ctx.Err()
}
