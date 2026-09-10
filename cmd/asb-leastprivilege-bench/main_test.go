// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege/certificate"
)

func TestReportCountersAndDeadlineFailures(t *testing.T) {
	var out, diagnostics bytes.Buffer
	if err := run([]string{"--sizes", "3", "--repetitions", "1", "--timeout", "5s", "--probe-timeout", "1ns"}, &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	var r report
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Results) != 4 {
		t.Fatal("missing fixture")
	}
	for _, result := range r.Results {
		if len(result.Measurements) != 8 || result.ProofJSONBytes == 0 {
			t.Fatal("missing operation or proof size")
		}
		for _, m := range result.Measurements {
			if m.DeadlineProbe {
				if m.Status != "deadline_exceeded" || m.ExactSubsetEvaluations != nil {
					t.Fatalf("unexpected deadline probe: %+v", m)
				}
				continue
			}
			if m.Status != "ok" {
				t.Fatalf("operation failed: %+v", m)
			}
			if m.Operation == operationSolve || m.Operation == operationVerify {
				if m.ExactSubsetEvaluations == nil || *m.ExactSubsetEvaluations != 8 {
					t.Fatal("wrong completed evaluation count")
				}
			} else if m.ProofNodes == 0 || m.ClosureEvaluations == 0 {
				t.Fatal("missing observed proof counters")
			}
		}
	}
}

func TestBenchmarkInputBounds(t *testing.T) {
	for _, args := range [][]string{{"--sizes", "21"}, {"--sizes", "1,1"}, {"--repetitions", "0"}, {"--timeout", "0s"}, {"--max-proof-nodes", "0"}} {
		if err := run(args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted invalid benchmark bounds: %v", args)
		}
	}
}

func TestReportProofBudgetExhaustion(t *testing.T) {
	r, err := runCase("sparse_last", 3, 1, time.Second, time.Nanosecond, 1)
	if err != nil {
		t.Fatal(err)
	}
	if r.ProofJSONBytes != 0 {
		t.Fatal("partial proof was reported as usable")
	}
	found := false
	for _, m := range r.Measurements {
		if m.Operation == operationCheck {
			t.Fatal("checker ran without a complete proof")
		}
		if m.Operation == operationGenerate && !m.DeadlineProbe {
			found = true
			if m.Status != "limit_reached" || m.ProofNodes != 1 || m.ExactSubsetEvaluations != nil {
				t.Fatalf("incorrect failure counters: %+v", m)
			}
		}
	}
	if !found {
		t.Fatal("budget failure was omitted")
	}
}

// BenchmarkOperations complements the JSON runner with standard Go benchmem
// output. Each operation is timed separately; candidate/proof setup is excluded.
func BenchmarkOperations(b *testing.B) {
	for _, pattern := range []string{"independent", "chain", "forbidden", "sparse_last"} {
		for _, n := range []int{4, 8, 12, 16, 20} {
			b.Run(fmt.Sprintf("%s/grants_%d", pattern, n), func(b *testing.B) {
				p := fixture(pattern, n)
				budget := uint64(1) << uint(n)
				ctx := context.Background()
				s, err := lp.Solve(ctx, p, budget)
				if err != nil {
					b.Fatal(err)
				}
				proof, _, err := certificate.Generate(ctx, p, s, certificate.MaxNodes)
				if err != nil {
					b.Fatal(err)
				}
				for _, operation := range []string{operationSolve, operationVerify, operationGenerate, operationCheck} {
					b.Run(operation, func(b *testing.B) {
						b.ReportAllocs()
						b.ResetTimer()
						for b.Loop() {
							var err error
							switch operation {
							case operationSolve:
								_, err = lp.Solve(ctx, p, budget)
							case operationVerify:
								err = lp.Verify(ctx, p, s, budget)
							case operationGenerate:
								_, _, err = certificate.Generate(ctx, p, s, certificate.MaxNodes)
							case operationCheck:
								_, err = certificate.Check(ctx, p, s, proof, certificate.MaxNodes)
							}
							if err != nil {
								b.Fatal(err)
							}
						}
					})
				}
			})
		}
	}
}
