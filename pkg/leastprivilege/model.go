// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Package leastprivilege solves bounded, explicit permission-selection problems.
// It does not parse cloud IAM policies or infer the permissions a task needs.
package leastprivilege

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	ProblemSchemaV1  = "asb.least-privilege.problem/v1"
	SolutionSchemaV1 = "asb.least-privilege.solution/v1"
	MaxGrants        = 20
	MaxPermissions   = 256
	MaxImplications  = 256
	MaxForbiddenSets = 256
	MaxIDBytes       = 128
)

var (
	ErrInvalidProblem  = errors.New("invalid least-privilege problem")
	ErrInvalidSolution = errors.New("invalid least-privilege solution")
	ErrInfeasible      = errors.New("no feasible grant selection")
	ErrNotOptimal      = errors.New("grant selection is not globally optimal")
	ErrLimit           = errors.New("least-privilege evaluation limit reached")
)

// Permission has a strictly positive cost. The objective counts each effective
// permission once, including permissions derived through implications.
type Permission struct {
	ID   string `json:"id"`
	Cost uint64 `json:"cost"`
}

// Grant is one selectable bundle of permissions.
type Grant struct {
	ID          string   `json:"id"`
	Permissions []string `json:"permissions"`
}

// Implication adds Then when every permission in AllOf is effective. An empty
// AllOf is unconditional. Implications are applied to a fixed point.
type Implication struct {
	AllOf []string `json:"all_of"`
	Then  []string `json:"then"`
}

// Problem is the complete finite model trusted by the optimizer and verifier.
// Allowed is an explicit upper bound; an empty Allowed permits no permissions.
// Each ForbiddenTogether set must contain at least two permission IDs.
// All IDs must be valid UTF-8, 1..MaxIDBytes bytes, without spaces or controls.
// Sets reject duplicates and unknown IDs. A set has at most MaxPermissions IDs.
type Problem struct {
	Schema            string        `json:"schema"`
	Permissions       []Permission  `json:"permissions"`
	Grants            []Grant       `json:"grants"`
	Required          []string      `json:"required"`
	Allowed           []string      `json:"allowed"`
	Implications      []Implication `json:"implications"`
	ForbiddenTogether [][]string    `json:"forbidden_together"`
}

// Solution is a proposed optimum, not a portable formal proof. Verify checks
// its contents and independently searches for a cheaper feasible selection.
type Solution struct {
	Schema        string   `json:"schema"`
	ProblemDigest string   `json:"problem_digest"`
	Grants        []string `json:"grants"`
	Effective     []string `json:"effective"`
	Cost          uint64   `json:"cost"`
}

type permissionSet [MaxPermissions / 64]uint64

func (s *permissionSet) add(i int) { s[i/64] |= uint64(1) << uint(i%64) }

func (s permissionSet) contains(other permissionSet) bool {
	for i := range s {
		if s[i]&other[i] != other[i] {
			return false
		}
	}
	return true
}

func (s *permissionSet) union(other permissionSet) bool {
	changed := false
	for i := range s {
		next := s[i] | other[i]
		changed = changed || next != s[i]
		s[i] = next
	}
	return changed
}

type compiledRule struct{ allOf, then permissionSet }

type compiledProblem struct {
	problem   Problem
	digest    string
	index     map[string]int
	grants    []permissionSet
	required  permissionSet
	allowed   permissionSet
	rules     []compiledRule
	forbidden []permissionSet
}

// DigestProblem validates and hashes a normalized copy of the entire problem.
// All sets and collections are sorted; nil and empty slices are equivalent.
// Input slices are never modified. The digest binds the explicit model, not
// the accuracy or authority of its description of an external IAM system.
func DigestProblem(p Problem) (string, error) {
	cp, err := compileProblem(p)
	if err != nil {
		return "", err
	}
	return cp.digest, nil
}

func validID(id string) bool {
	if len(id) == 0 || len(id) > MaxIDBytes || !utf8.ValidString(id) {
		return false
	}
	for _, r := range id {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func compileProblem(p Problem) (*compiledProblem, error) {
	invalid := func(reason string) (*compiledProblem, error) {
		return nil, fmt.Errorf("%w: %s", ErrInvalidProblem, reason)
	}
	if p.Schema != ProblemSchemaV1 {
		return invalid("unsupported schema")
	}
	if len(p.Permissions) > MaxPermissions || len(p.Grants) > MaxGrants ||
		len(p.Implications) > MaxImplications || len(p.ForbiddenTogether) > MaxForbiddenSets {
		return invalid("collection exceeds model bounds")
	}
	// Allocate non-nil empty collections for one canonical JSON representation.
	n := Problem{
		Schema: p.Schema, Permissions: make([]Permission, len(p.Permissions)),
		Grants: make([]Grant, len(p.Grants)), Implications: make([]Implication, len(p.Implications)),
		ForbiddenTogether: make([][]string, len(p.ForbiddenTogether)),
	}
	copy(n.Permissions, p.Permissions)
	slices.SortFunc(n.Permissions, func(a, b Permission) int { return strings.Compare(a.ID, b.ID) })
	index := make(map[string]int, len(n.Permissions))
	var total uint64
	for i, permission := range n.Permissions {
		if !validID(permission.ID) || permission.Cost == 0 {
			return invalid("permission ID or cost is invalid")
		}
		if _, duplicate := index[permission.ID]; duplicate {
			return invalid("duplicate permission ID")
		}
		if total > math.MaxUint64-permission.Cost {
			return invalid("sum of permission costs overflows uint64")
		}
		total += permission.Cost
		index[permission.ID] = i
	}
	refs := func(ids []string) ([]string, error) {
		if len(ids) > MaxPermissions {
			return nil, fmt.Errorf("%w: permission set exceeds model bounds", ErrInvalidProblem)
		}
		for _, id := range ids {
			if !validID(id) {
				return nil, fmt.Errorf("%w: invalid permission reference ID", ErrInvalidProblem)
			}
		}
		out := make([]string, len(ids))
		copy(out, ids)
		slices.Sort(out)
		for i, id := range out {
			if _, exists := index[id]; !exists || (i > 0 && id == out[i-1]) {
				return nil, fmt.Errorf("%w: unknown or duplicate permission reference", ErrInvalidProblem)
			}
		}
		return out, nil
	}
	var err error
	if n.Required, err = refs(p.Required); err != nil {
		return nil, err
	}
	if n.Allowed, err = refs(p.Allowed); err != nil {
		return nil, err
	}
	grantIDs := make(map[string]bool, len(p.Grants))
	for i, grant := range p.Grants {
		if !validID(grant.ID) || grantIDs[grant.ID] {
			return invalid("invalid or duplicate grant ID")
		}
		grantIDs[grant.ID] = true
		n.Grants[i].ID = grant.ID
		if n.Grants[i].Permissions, err = refs(grant.Permissions); err != nil {
			return nil, err
		}
	}
	slices.SortFunc(n.Grants, func(a, b Grant) int { return strings.Compare(a.ID, b.ID) })
	for i, rule := range p.Implications {
		if len(rule.Then) == 0 {
			return invalid("implication has no consequence")
		}
		if n.Implications[i].AllOf, err = refs(rule.AllOf); err != nil {
			return nil, err
		}
		if n.Implications[i].Then, err = refs(rule.Then); err != nil {
			return nil, err
		}
	}
	compareRules := func(a, b Implication) int {
		if c := slices.Compare(a.AllOf, b.AllOf); c != 0 {
			return c
		}
		return slices.Compare(a.Then, b.Then)
	}
	slices.SortFunc(n.Implications, compareRules)
	for i := 1; i < len(n.Implications); i++ {
		if compareRules(n.Implications[i-1], n.Implications[i]) == 0 {
			return invalid("duplicate implication")
		}
	}
	for i, group := range p.ForbiddenTogether {
		if len(group) < 2 {
			return invalid("forbidden set must contain at least two permissions")
		}
		if n.ForbiddenTogether[i], err = refs(group); err != nil {
			return nil, err
		}
	}
	slices.SortFunc(n.ForbiddenTogether, slices.Compare[[]string])
	for i := 1; i < len(n.ForbiddenTogether); i++ {
		if slices.Equal(n.ForbiddenTogether[i-1], n.ForbiddenTogether[i]) {
			return invalid("duplicate forbidden set")
		}
	}
	data, err := json.Marshal(n)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot encode canonical model: %v", ErrInvalidProblem, err)
	}
	hash := sha256.Sum256(data)
	cp := &compiledProblem{problem: n, digest: "sha256:" + hex.EncodeToString(hash[:]), index: index}
	toSet := func(ids []string) (out permissionSet) {
		for _, id := range ids {
			out.add(index[id])
		}
		return out
	}
	cp.required, cp.allowed = toSet(n.Required), toSet(n.Allowed)
	for _, grant := range n.Grants {
		cp.grants = append(cp.grants, toSet(grant.Permissions))
	}
	for _, rule := range n.Implications {
		cp.rules = append(cp.rules, compiledRule{toSet(rule.AllOf), toSet(rule.Then)})
	}
	for _, group := range n.ForbiddenTogether {
		cp.forbidden = append(cp.forbidden, toSet(group))
	}
	return cp, nil
}

// evaluate is trusted shared semantics used by the two separate searches. The
// verifier is independent of the solver's search, not of this model evaluator.
func (cp *compiledProblem) evaluate(ctx context.Context, mask uint64) (permissionSet, uint64, bool, error) {
	var effective permissionSet
	if err := ctx.Err(); err != nil {
		return effective, 0, false, err
	}
	for i, grant := range cp.grants {
		if mask&(uint64(1)<<uint(i)) != 0 {
			effective.union(grant)
		}
	}
	for {
		changed := false
		for _, rule := range cp.rules {
			if err := ctx.Err(); err != nil {
				return permissionSet{}, 0, false, err
			}
			if effective.contains(rule.allOf) {
				// Do not short-circuit union when another rule already changed it.
				changed = effective.union(rule.then) || changed
			}
		}
		if !changed {
			break
		}
	}
	if !effective.contains(cp.required) || !cp.allowed.contains(effective) {
		return effective, 0, false, nil
	}
	for _, forbidden := range cp.forbidden {
		if err := ctx.Err(); err != nil {
			return permissionSet{}, 0, false, err
		}
		if effective.contains(forbidden) {
			return effective, 0, false, nil
		}
	}
	var cost uint64
	for i, permission := range cp.problem.Permissions {
		if effective[i/64]&(uint64(1)<<uint(i%64)) != 0 {
			cost += permission.Cost // The entire universe's sum was checked above.
		}
	}
	return effective, cost, true, ctx.Err()
}

func (cp *compiledProblem) effectiveIDs(effective permissionSet) []string {
	ids := make([]string, 0)
	for i, permission := range cp.problem.Permissions {
		if effective[i/64]&(uint64(1)<<uint(i%64)) != 0 {
			ids = append(ids, permission.ID)
		}
	}
	return ids
}

func (cp *compiledProblem) grantIDs(mask uint64) []string {
	ids := make([]string, 0)
	for i, grant := range cp.problem.Grants {
		if mask&(uint64(1)<<uint(i)) != 0 {
			ids = append(ids, grant.ID)
		}
	}
	return ids
}
