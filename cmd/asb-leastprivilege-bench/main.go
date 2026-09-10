// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// asb-leastprivilege-bench records bounded, reproducible local measurements.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege/certificate"
)

const (
	operationSolve    = "solve"
	operationVerify   = "verify"
	operationGenerate = "proof_generate"
	operationCheck    = "proof_check"
)

type measurement struct {
	Operation              string  `json:"operation"`
	Repetition             int     `json:"repetition"`
	DeadlineProbe          bool    `json:"deadline_probe"`
	DeadlineNS             int64   `json:"deadline_ns"`
	ElapsedNS              int64   `json:"elapsed_ns"`
	AllocatedBytes         uint64  `json:"allocated_bytes"`
	Allocations            uint64  `json:"allocations"`
	Status                 string  `json:"status"`
	Error                  string  `json:"error,omitempty"`
	ExactSubsetEvaluations *uint64 `json:"exact_subset_evaluations"`
	ProofNodes             uint64  `json:"proof_nodes"`
	ClosureEvaluations     uint64  `json:"closure_evaluations"`
}

type result struct {
	Pattern        string        `json:"pattern"`
	Grants         int           `json:"grants"`
	Permissions    int           `json:"permissions"`
	Implications   int           `json:"implications"`
	ForbiddenSets  int           `json:"forbidden_sets"`
	ProblemDigest  string        `json:"problem_digest"`
	SubsetLimit    uint64        `json:"subset_limit"`
	ProofNodeLimit uint64        `json:"proof_node_limit"`
	ProofJSONBytes int           `json:"proof_json_bytes"`
	Measurements   []measurement `json:"measurements"`
}

type report struct {
	Schema          string    `json:"schema"`
	RecordedAt      time.Time `json:"recorded_at"`
	GoVersion       string    `json:"go_version"`
	GOOS            string    `json:"goos"`
	GOARCH          string    `json:"goarch"`
	NumCPU          int       `json:"num_cpu"`
	GOMAXPROCS      int       `json:"gomaxprocs"`
	Revision        string    `json:"base_revision"`
	Modified        bool      `json:"working_tree_modified"`
	EnvironmentNote string    `json:"environment_note"`
	Method          string    `json:"method"`
	Results         []result  `json:"results"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, out, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("asb-leastprivilege-bench", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	sizesText := flags.String("sizes", "4,8,12,16,20", "comma-separated grant counts, 1..20")
	repetitions := flags.Int("repetitions", 3, "measurements per fixture, 1..10")
	timeout := flags.Duration("timeout", 10*time.Second, "positive per-operation deadline")
	probe := flags.Duration("probe-timeout", time.Nanosecond, "positive deadline-failure probe duration")
	proofBudget := flags.Uint64("max-proof-nodes", certificate.MaxNodes, "positive proof-node budget")
	note := flags.String("environment-note", "uncontrolled local development host", "measurement conditions; avoid credentials or personal hostnames")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *repetitions < 1 || *repetitions > 10 || *timeout <= 0 || *probe <= 0 || *proofBudget == 0 {
		return errors.New("invalid benchmark bounds")
	}
	var sizes []int
	seen := map[int]bool{}
	for _, text := range strings.Split(*sizesText, ",") {
		n, err := strconv.Atoi(text)
		if err != nil || n < 1 || n > lp.MaxGrants || seen[n] {
			return errors.New("sizes must be distinct integers in 1..20")
		}
		seen[n] = true
		sizes = append(sizes, n)
	}
	r := report{
		Schema: "asb.least-privilege.benchmark/v1", RecordedAt: time.Now().UTC(), GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, NumCPU: runtime.NumCPU(), GOMAXPROCS: runtime.GOMAXPROCS(0), EnvironmentNote: *note,
		Method: "Sequential measured operations, runtime.GC before each sample (outside timing), runtime.MemStats TotalAlloc/Mallocs deltas. Not peak memory or RSS. Successful Solve/Verify enumerate exactly 2^grants subsets; failed subset counts are unavailable (null). Proof counters are observed. JSON encoding is outside operation timing. No cloud workload or production latency claim.",
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				r.Revision = setting.Value
			case "vcs.modified":
				r.Modified = setting.Value == "true"
			}
		}
	}
	for _, pattern := range []string{"independent", "chain", "forbidden", "sparse_last"} {
		for _, size := range sizes {
			sample, err := runCase(pattern, size, *repetitions, *timeout, *probe, *proofBudget)
			if err != nil {
				return err
			}
			r.Results = append(r.Results, sample)
		}
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r)
}

func fixture(pattern string, n int) lp.Problem {
	p := lp.Problem{Schema: lp.ProblemSchemaV1}
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("p%02d", i)
		p.Permissions = append(p.Permissions, lp.Permission{ID: id, Cost: uint64(i%3 + 1)})
		p.Allowed = append(p.Allowed, id)
		p.Grants = append(p.Grants, lp.Grant{ID: fmt.Sprintf("g%02d", i), Permissions: []string{id}})
	}
	p.Required = []string{"p00"}
	switch pattern {
	case "chain":
		// Reverse order requires repeated closure passes for a long prefix.
		for i := n - 2; i >= 0; i-- {
			p.Implications = append(p.Implications, lp.Implication{AllOf: []string{p.Permissions[i].ID}, Then: []string{p.Permissions[i+1].ID}})
		}
	case "forbidden":
		for i := 1; i < n; i++ {
			p.ForbiddenTogether = append(p.ForbiddenTogether, []string{p.Permissions[i-1].ID, p.Permissions[i].ID})
		}
	case "sparse_last":
		// Irrelevant early decisions expose the proof tree's exponential case.
		for i := 0; i < n-1; i++ {
			p.Grants[i].Permissions = nil
		}
		p.Required = []string{p.Permissions[n-1].ID}
	}
	return p
}

func measure(operation string, repetition int, probe bool, timeout time.Duration, subsets uint64, fn func(context.Context) (certificate.Stats, error)) measurement {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	start := time.Now()
	stats, err := fn(ctx)
	elapsed := time.Since(start)
	cancel()
	runtime.ReadMemStats(&after)
	m := measurement{Operation: operation, Repetition: repetition, DeadlineProbe: probe, DeadlineNS: int64(timeout), ElapsedNS: elapsed.Nanoseconds(), AllocatedBytes: after.TotalAlloc - before.TotalAlloc, Allocations: after.Mallocs - before.Mallocs, Status: "ok", ProofNodes: stats.Nodes, ClosureEvaluations: stats.Closures}
	if err != nil {
		m.Error = err.Error()
		m.Status = "error"
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			m.Status = "deadline_exceeded"
		case errors.Is(err, lp.ErrLimit):
			m.Status = "limit_reached"
		}
	}
	if err == nil && (operation == operationSolve || operation == operationVerify) {
		count := subsets
		m.ExactSubsetEvaluations = &count
	}
	return m
}

func runCase(pattern string, n, repetitions int, timeout, probe time.Duration, proofBudget uint64) (result, error) {
	p := fixture(pattern, n)
	digest, err := lp.DigestProblem(p)
	if err != nil {
		return result{}, err
	}
	r := result{Pattern: pattern, Grants: n, Permissions: len(p.Permissions), Implications: len(p.Implications), ForbiddenSets: len(p.ForbiddenTogether), ProblemDigest: digest, SubsetLimit: 1 << uint(n), ProofNodeLimit: proofBudget}
	var candidate lp.Solution
	var proof certificate.Proof
	for repetition := 1; repetition <= repetitions; repetition++ {
		m := measure(operationSolve, repetition, false, timeout, r.SubsetLimit, func(ctx context.Context) (certificate.Stats, error) {
			var err error
			candidate, err = lp.Solve(ctx, p, r.SubsetLimit)
			return certificate.Stats{}, err
		})
		r.Measurements = append(r.Measurements, m)
		if m.Status != "ok" {
			continue
		}
		r.Measurements = append(r.Measurements, measure(operationVerify, repetition, false, timeout, r.SubsetLimit, func(ctx context.Context) (certificate.Stats, error) {
			return certificate.Stats{}, lp.Verify(ctx, p, candidate, r.SubsetLimit)
		}))
		m = measure(operationGenerate, repetition, false, timeout, 0, func(ctx context.Context) (certificate.Stats, error) {
			var stats certificate.Stats
			var err error
			proof, stats, err = certificate.Generate(ctx, p, candidate, proofBudget)
			return stats, err
		})
		r.Measurements = append(r.Measurements, m)
		if m.Status != "ok" {
			continue
		}
		raw, err := json.Marshal(proof)
		if err != nil {
			return result{}, err
		}
		r.ProofJSONBytes = len(raw)
		r.Measurements = append(r.Measurements, measure(operationCheck, repetition, false, timeout, 0, func(ctx context.Context) (certificate.Stats, error) {
			return certificate.Check(ctx, p, candidate, proof, proofBudget)
		}))
	}
	// Probes are separate from successful samples. Dependent stages are omitted
	// when a prerequisite failed; the report never substitutes a partial result.
	r.Measurements = append(r.Measurements, measure(operationSolve, 0, true, probe, r.SubsetLimit, func(ctx context.Context) (certificate.Stats, error) {
		_, err := lp.Solve(ctx, p, r.SubsetLimit)
		return certificate.Stats{}, err
	}))
	if candidate.Schema != "" {
		r.Measurements = append(r.Measurements, measure(operationVerify, 0, true, probe, r.SubsetLimit, func(ctx context.Context) (certificate.Stats, error) {
			return certificate.Stats{}, lp.Verify(ctx, p, candidate, r.SubsetLimit)
		}))
		r.Measurements = append(r.Measurements, measure(operationGenerate, 0, true, probe, 0, func(ctx context.Context) (certificate.Stats, error) {
			_, stats, err := certificate.Generate(ctx, p, candidate, proofBudget)
			return stats, err
		}))
		if proof.Schema != "" {
			r.Measurements = append(r.Measurements, measure(operationCheck, 0, true, probe, 0, func(ctx context.Context) (certificate.Stats, error) {
				return certificate.Check(ctx, p, candidate, proof, proofBudget)
			}))
		}
	}
	return r, nil
}
