// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
)

const testProblem = `{"schema":"asb.least-privilege.problem/v1","permissions":[{"id":"read","cost":1},{"id":"write","cost":10}],"grants":[{"id":"reader","permissions":["read"]},{"id":"editor","permissions":["read","write"]}],"required":["read"],"allowed":["read","write"]}`

func inputFile(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSolveVerifyAndRejectCounterfeit(t *testing.T) {
	path := inputFile(t, testProblem)
	var out bytes.Buffer
	if err := run([]string{commandSolve, "--problem", path}, &out, &out); err != nil {
		t.Fatal(err)
	}
	var solution lp.Solution
	if err := json.Unmarshal(out.Bytes(), &solution); err != nil {
		t.Fatal(err)
	}
	if solution.Cost != 1 || len(solution.Grants) != 1 || solution.Grants[0] != "reader" {
		t.Fatalf("unexpected optimum: %+v", solution)
	}
	solutionPath := inputFile(t, out.String())
	out.Reset()
	if err := run([]string{"verify", "--problem", path, "--solution", solutionPath}, &out, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"verified": true`) {
		t.Fatal(out.String())
	}
	solution.Grants, solution.Effective, solution.Cost = []string{"editor"}, []string{"read", "write"}, 11
	raw, err := json.Marshal(solution)
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"verify", "--problem", path, "--solution", inputFile(t, string(raw))}, &out, &out); err == nil {
		t.Fatal("nonoptimal candidate accepted")
	}
	if out.Len() != 0 {
		t.Fatal("failed verification emitted a success result")
	}
}

func TestStrictInputAndSearchLimits(t *testing.T) {
	for name, text := range map[string]string{
		"duplicate": strings.Replace(testProblem, `"required":["read"]`, `"required":["write"],"required":["read"]`, 1),
		"unknown":   strings.Replace(testProblem, `"required":["read"]`, `"required":["read"],"trust_me":true`, 1),
		"trailing":  testProblem + ` {}`,
		"oversized": strings.Repeat(" ", 1<<20) + testProblem,
		"null":      "null",
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			if err := run([]string{commandSolve, "--problem", inputFile(t, text)}, &out, &out); err == nil {
				t.Fatal("invalid input accepted")
			}
			if out.Len() != 0 {
				t.Fatal("invalid input emitted a solution")
			}
		})
	}
	for _, args := range [][]string{
		{commandSolve, "--problem", inputFile(t, testProblem), "--max-evaluations", "1"},
		{commandSolve, "--problem", inputFile(t, testProblem), "--max-evaluations", "0"},
		{commandSolve, "--problem", inputFile(t, testProblem), "--timeout", "1ns"},
		{commandSolve, "--problem", inputFile(t, testProblem), "--timeout", "0s"},
	} {
		var out bytes.Buffer
		if err := run(args, &out, &out); err == nil {
			t.Fatal("incomplete search accepted")
		}
		if out.Len() != 0 {
			t.Fatal("incomplete search emitted a solution")
		}
	}
}

func TestDemoExecutesOnceAndPreservesHumanGate(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"demo"}, &out, &out); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Result       string `json:"executed_result"`
		Replay       bool   `json:"replay_rejected"`
		Human        bool   `json:"human_gate_preserved"`
		Substitution bool   `json:"action_substitution_rejected"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Result != "demo report: 42" || !result.Replay || !result.Human || !result.Substitution {
		t.Fatalf("demo failed: %+v", result)
	}
}
