// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package leastprivilege

import (
	"context"
	"fmt"
	"slices"
)

// Verify recomputes the proposed selection, then independently enumerates grant
// bitmasks to reject any cheaper feasible selection. It does not call Solve and
// accepts any optimum, including different equal-cost grant selections. Both
// searches trust the same evaluator; this is not an external formal proof.
// maxEvaluations includes the initial evaluation of the proposed selection.
// Budget exhaustion, cancellation, or invalid input always prevents acceptance.
func Verify(ctx context.Context, p Problem, solution Solution, maxEvaluations uint64) error {
	if ctx == nil {
		return ErrInvalidProblem
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if maxEvaluations == 0 {
		return ErrLimit
	}
	cp, err := compileProblem(p)
	if err != nil {
		return err
	}
	invalid := func(reason string) error {
		return fmt.Errorf("%w: %s", ErrInvalidSolution, reason)
	}
	if solution.Schema != SolutionSchemaV1 || solution.ProblemDigest != cp.digest {
		return invalid("schema or problem digest mismatch")
	}
	if len(solution.Grants) > len(cp.grants) || len(solution.Effective) > len(cp.problem.Permissions) {
		return invalid("selection exceeds model bounds")
	}
	grantIndex := make(map[string]int, len(cp.grants))
	for i, grant := range cp.problem.Grants {
		grantIndex[grant.ID] = i
	}
	var candidateMask uint64
	for _, id := range solution.Grants {
		if !validID(id) {
			return invalid("invalid grant ID")
		}
		i, exists := grantIndex[id]
		if !exists || candidateMask&(uint64(1)<<uint(i)) != 0 {
			return invalid("unknown or duplicate grant")
		}
		candidateMask |= uint64(1) << uint(i)
	}
	effective, cost, feasible, err := cp.evaluate(ctx, candidateMask)
	if err != nil {
		return err
	}
	if !feasible || cost != solution.Cost {
		return invalid("selection is infeasible or claimed cost is incorrect")
	}
	claimed := make([]string, len(solution.Effective))
	for _, id := range solution.Effective {
		if !validID(id) {
			return invalid("invalid effective permission ID")
		}
	}
	copy(claimed, solution.Effective)
	slices.Sort(claimed)
	if !slices.Equal(claimed, cp.effectiveIDs(effective)) {
		return invalid("claimed effective permissions do not match the selection")
	}
	evaluations := uint64(1)
	for mask, count := uint64(0), uint64(1)<<uint(len(cp.grants)); mask < count; mask++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if mask == candidateMask {
			continue // The claimed selection was evaluated above.
		}
		if evaluations >= maxEvaluations {
			return ErrLimit
		}
		evaluations++
		_, alternativeCost, alternativeFeasible, err := cp.evaluate(ctx, mask)
		if err != nil {
			return err
		}
		if alternativeFeasible && alternativeCost < cost {
			return ErrNotOptimal
		}
	}
	return ctx.Err()
}
