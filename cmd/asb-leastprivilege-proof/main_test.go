// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege/certificate"
)

func TestGenerateAndCheckCLI(t *testing.T) {
	dir := t.TempDir()
	problem := filepath.Join(dir, "problem.json")
	solution := filepath.Join(dir, "solution.json")
	proof := filepath.Join(dir, "proof.json")
	p := lp.Problem{Schema: lp.ProblemSchemaV1, Permissions: []lp.Permission{{ID: "p", Cost: 1}}, Grants: []lp.Grant{{ID: "g", Permissions: []string{"p"}}}, Required: []string{"p"}, Allowed: []string{"p"}}
	s, err := lp.Solve(context.Background(), p, 2)
	if err != nil {
		t.Fatal(err)
	}
	for path, value := range map[string]any{problem: p, solution: s} {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var output, diagnostics bytes.Buffer
	if err := run([]string{"generate", "--problem", problem, "--solution", solution}, &output, &diagnostics); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proof, output.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	args := []string{"check", "--problem", problem, "--solution", solution, "--proof", proof}
	if err := run(args, &output, &diagnostics); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Verified bool `json:"verified"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || !result.Verified {
		t.Fatalf("%s %v", output.String(), err)
	}
	output.Reset()
	if err := run(append(args, "--max-nodes", "1"), &output, &diagnostics); err == nil || output.Len() != 0 {
		t.Fatal("budget failure produced acceptance")
	}
	if err := run(append(args, "--timeout", "1ns"), &output, &diagnostics); err == nil || output.Len() != 0 {
		t.Fatal("deadline failure produced acceptance")
	}
}

func TestStrictProofInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.json")
	for _, raw := range []string{`{"schema":"a","schema":"b"}`, `{"unexpected":true}`, `{} {}`, strings.Repeat("[", 34) + strings.Repeat("]", 34), strings.Repeat(" ", 4<<20) + "{}"} {
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		var proof certificate.Proof
		if err := readJSON(path, &proof); err == nil {
			t.Fatal("accepted ambiguous/oversize JSON")
		}
	}
}

func TestInvalidArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown"}, {"check"}, {"generate", "--problem", "p", "--solution", "s", "--proof", "x"}, {"generate", "--problem", "p", "--solution", "s", "--timeout", "0s"}, {"generate", "--problem", "p", "--solution", "s", "--max-nodes", "0"}, {"generate", "--problem", "p", "--solution", "s", "extra"}} {
		var output, diagnostics bytes.Buffer
		if err := run(args, &output, &diagnostics); err == nil || output.Len() != 0 {
			t.Fatalf("accepted invalid args: %v", args)
		}
	}
}
