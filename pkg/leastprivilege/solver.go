// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package leastprivilege

import "context"

// Solve searches every grant subset with a depth-first traversal. The returned
// solution is a global minimum within the supplied finite model. Ties are
// deterministic after normalization; grant count is not a secondary objective.
// maxEvaluations counts evaluated subsets and must be positive. A limit or
// cancellation returns a zero Solution, never a usable partial candidate.
func Solve(ctx context.Context, p Problem, maxEvaluations uint64) (Solution, error) {
	if ctx == nil {
		return Solution{}, ErrInvalidProblem
	}
	if err := ctx.Err(); err != nil {
		return Solution{}, err
	}
	if maxEvaluations == 0 {
		return Solution{}, ErrLimit
	}
	cp, err := compileProblem(p)
	if err != nil {
		return Solution{}, err
	}
	var evaluations, bestMask, bestCost uint64
	var bestEffective permissionSet
	found := false
	var visit func(int, uint64) error
	visit = func(index int, mask uint64) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if index < len(cp.grants) {
			if err := visit(index+1, mask); err != nil {
				return err
			}
			return visit(index+1, mask|(uint64(1)<<uint(index)))
		}
		if evaluations >= maxEvaluations {
			return ErrLimit
		}
		evaluations++
		effective, cost, feasible, err := cp.evaluate(ctx, mask)
		if err != nil {
			return err
		}
		if feasible && (!found || cost < bestCost) {
			found, bestMask, bestCost, bestEffective = true, mask, cost, effective
		}
		return nil
	}
	if err := visit(0, 0); err != nil {
		return Solution{}, err
	}
	if err := ctx.Err(); err != nil {
		return Solution{}, err
	}
	if !found {
		return Solution{}, ErrInfeasible
	}
	solution := Solution{
		Schema: SolutionSchemaV1, ProblemDigest: cp.digest,
		Grants: cp.grantIDs(bestMask), Effective: cp.effectiveIDs(bestEffective), Cost: bestCost,
	}
	if err := ctx.Err(); err != nil {
		return Solution{}, err
	}
	return solution, nil
}
