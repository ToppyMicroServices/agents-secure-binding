// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package sbaipv2

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAppendixBContextVectorWithIndependentPython(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not available")
	}
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
	script := filepath.Join(repositoryRoot, "interop", "draft06-v2", "verify_context_vector.py")
	fixture := filepath.Join(repositoryRoot, "interop", "draft06-v2", "appendix-b-context.json")

	runPythonContextVerifier(t, python, script, fixture, true)

	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	want := []byte("5e667cbd7d74e96d89a0cb346a68e4879da4d0335ae9a751fbb5ce9f8df1e1df")
	tampered := bytes.Replace(raw, want, bytes.Repeat([]byte{'0'}, len(want)), 1)
	if bytes.Equal(tampered, raw) {
		t.Fatal("fixture did not contain the expected context digest")
	}
	tamperedPath := filepath.Join(t.TempDir(), "tampered-context.json")
	if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
		t.Fatalf("write tampered fixture: %v", err)
	}
	runPythonContextVerifier(t, python, script, tamperedPath, false)
}

func runPythonContextVerifier(t *testing.T, python, script, fixture string, wantSuccess bool) {
	t.Helper()
	command := exec.Command(python, script, fixture)
	output, err := command.CombinedOutput()
	if wantSuccess && err != nil {
		t.Fatalf("independent Python verifier failed: %v\n%s", err, output)
	}
	if !wantSuccess && err == nil {
		t.Fatalf("independent Python verifier accepted a tampered digest:\n%s", output)
	}
}
