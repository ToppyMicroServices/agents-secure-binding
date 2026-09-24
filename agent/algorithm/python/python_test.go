// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package python

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent/algorithm"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent/algorithm/logging"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent/events/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

const runtime = "python3"

func TestStopDuringPreparationPreventsAlgorithmStart(t *testing.T) {
	dir := t.TempDir()
	entered := filepath.Join(dir, "entered")
	started := filepath.Join(dir, "started")
	runtimePath := filepath.Join(dir, "runtime")
	runtimeScript := "#!/bin/sh\nsleep 30 &\nchild=$!\n: > " + entered + "\nwait \"$child\"\n"
	if err := os.WriteFile(runtimePath, []byte(runtimeScript), 0o700); err != nil {
		t.Fatal(err)
	}
	algoPath := filepath.Join(dir, "algo.py")
	if err := os.WriteFile(algoPath, []byte("from pathlib import Path\nPath("+fmt.Sprintf("%q", started)+").write_text('started')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := NewAlgorithm(logger, nil, runtimePath, "", algoPath, nil, "stop-during-preparation")
	t.Cleanup(func() { _ = p.Stop() })
	done := make(chan error, 1)
	go func() { done <- p.Run() }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(entered); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("preparation command did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled preparation returned success")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled preparation left a descendant holding the run open")
	}
	if _, err := os.Stat(started); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("algorithm started after Stop: %v", err)
	}
	if err := p.Run(); !errors.Is(err, algorithm.ErrStopped) {
		t.Fatalf("second Run after Stop = %v, want ErrStopped", err)
	}
}

func TestPythonRunTimeToContext(t *testing.T) {
	ctx := context.Background()
	newCtx := PythonRunTimeToContext(ctx, runtime)

	md, ok := metadata.FromOutgoingContext(newCtx)
	if !ok {
		t.Fatal("Expected metadata in context")
	}

	values := md.Get(PyRuntimeKey)
	if len(values) != 1 || values[0] != runtime {
		t.Errorf("Expected runtime %s, got %v", runtime, values)
	}
}

func TestPythonRunTimeFromContext(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(PyRuntimeKey, runtime))

	got := PythonRunTimeFromContext(ctx)
	if got != runtime {
		t.Errorf("Expected runtime %s, got %s", runtime, got)
	}
}

func TestNewAlgorithm(t *testing.T) {
	logger := &slog.Logger{}
	eventsSvc := new(mocks.Service)
	requirementsFile := "requirements.txt"
	algoFile := "algorithm.py"
	args := []string{"--arg1", "value1"}

	algo := NewAlgorithm(logger, eventsSvc, runtime, requirementsFile, algoFile, args, "")

	p, ok := algo.(*python)
	if !ok {
		t.Fatal("Expected *python type")
	}

	if p.runtime != runtime {
		t.Errorf("Expected runtime %s, got %s", runtime, p.runtime)
	}
	if p.requirementsFile != requirementsFile {
		t.Errorf("Expected requirementsFile %s, got %s", requirementsFile, p.requirementsFile)
	}
	if p.algoFile != algoFile {
		t.Errorf("Expected algoFile %s, got %s", algoFile, p.algoFile)
	}
	if len(p.args) != len(args) {
		t.Errorf("Expected %d args, got %d", len(args), len(p.args))
	}
}

func TestRun(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "python-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	scriptContent := []byte("print('Hello, World!')")
	scriptPath := filepath.Join(tmpDir, "test_script.py")
	if err := os.WriteFile(scriptPath, scriptContent, 0o644); err != nil {
		t.Fatal(err)
	}

	eventsSvc := new(mocks.Service)
	eventsSvc.On("SendEvent", mock.Anything, "AlgorithmRun", "Warning", mock.Anything).Maybe().Return()

	var stdout, stderr bytes.Buffer

	algo := &python{
		algoFile: scriptPath,
		stderr:   io.MultiWriter(&stderr, &logging.Stderr{Logger: slog.Default(), EventSvc: eventsSvc}),
		stdout:   io.MultiWriter(&stdout, &logging.Stdout{Logger: slog.Default()}),
		runtime:  "python3",
	}

	err = algo.Run()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	expectedOutput := "Hello, World!\n"
	if !strings.Contains(stdout.String(), expectedOutput) {
		t.Errorf("Expected output to contain %q, got %q", expectedOutput, stdout.String())
	}
}

func TestRunWithRequirements(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "python-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	wheelPath := writeTestWheel(t, tmpDir)
	scriptContent := []byte("import asb_test_dependency\nprint(asb_test_dependency.VERSION)")
	scriptPath := filepath.Join(tmpDir, "test_script.py")
	if err := os.WriteFile(scriptPath, scriptContent, 0o644); err != nil {
		t.Fatal(err)
	}

	requirementsContent := []byte(wheelPath + "\n")
	requirementsPath := filepath.Join(tmpDir, "requirements.txt")
	if err := os.WriteFile(requirementsPath, requirementsContent, 0o644); err != nil {
		t.Fatal(err)
	}

	eventsSvc := new(mocks.Service)
	eventsSvc.On("SendEvent", mock.Anything, "AlgorithmRun", "Warning", mock.Anything).Maybe().Return()

	var stdout, stderr bytes.Buffer

	algo := &python{
		algoFile:         scriptPath,
		requirementsFile: requirementsPath,
		stderr:           io.MultiWriter(&stderr, &logging.Stderr{Logger: slog.Default(), EventSvc: eventsSvc}),
		stdout:           io.MultiWriter(&stdout, &logging.Stdout{Logger: slog.Default()}),
		runtime:          "python3",
	}

	err = algo.Run()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !strings.Contains(stdout.String(), "1.0.0") {
		t.Errorf("Expected output to contain local dependency version 1.0.0, got %q", stdout.String())
	}
}

func writeTestWheel(t *testing.T, dir string) string {
	t.Helper()
	wheelPath := filepath.Join(dir, "asb_test_dependency-1.0.0-py3-none-any.whl")
	file, err := os.Create(wheelPath)
	require.NoError(t, err)
	archive := zip.NewWriter(file)
	files := map[string]string{
		"asb_test_dependency.py":                       "VERSION = '1.0.0'\n",
		"asb_test_dependency-1.0.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: asb-test-dependency\nVersion: 1.0.0\n",
		"asb_test_dependency-1.0.0.dist-info/WHEEL":    "Wheel-Version: 1.0\nGenerator: ASB test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
		"asb_test_dependency-1.0.0.dist-info/RECORD":   "asb_test_dependency.py,,\nasb_test_dependency-1.0.0.dist-info/METADATA,,\nasb_test_dependency-1.0.0.dist-info/WHEEL,,\nasb_test_dependency-1.0.0.dist-info/RECORD,,\n",
	}
	for name, contents := range files {
		entry, createErr := archive.Create(name)
		require.NoError(t, createErr)
		_, writeErr := entry.Write([]byte(contents))
		require.NoError(t, writeErr)
	}
	require.NoError(t, archive.Close())
	require.NoError(t, file.Close())
	return wheelPath
}

func TestStop(t *testing.T) {
	t.Run("stop nil cmd", func(t *testing.T) {
		p := &python{}
		err := p.Stop()
		if err != nil {
			t.Errorf("Expected nil error, got %v", err)
		}
	})

	t.Run("stop with running process", func(t *testing.T) {
		p := &python{
			stderr: io.Discard,
			stdout: io.Discard,
		}

		p.cmd = exec.Command("python3", "-c", "import time; time.sleep(10)")
		if err := p.cmd.Start(); err != nil {
			t.Fatalf("Failed to start command: %v", err)
		}

		err := p.Stop()
		if err != nil {
			t.Errorf("Expected nil error, got %v", err)
		}

		// Verify it actually stopped
		_ = p.cmd.Wait()
	})

	t.Run("stop already exited", func(t *testing.T) {
		p := &python{}
		p.cmd = exec.Command("python3", "-c", "print(1)")
		if err := p.cmd.Run(); err != nil {
			t.Fatal(err)
		}
		err := p.Stop()
		if err != nil {
			t.Errorf("Expected nil error, got %v", err)
		}
	})
}

func TestRun_Errors(t *testing.T) {
	t.Run("invalid runtime error", func(t *testing.T) {
		algo := &python{
			algoFile: "algo.py",
			runtime:  "non-existent-python",
			stderr:   io.Discard,
			stdout:   io.Discard,
		}
		err := algo.Run()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error creating virtual environment")
	})

	t.Run("pip install failure", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "python-err-test")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		scriptPath := filepath.Join(tmpDir, "test.py")
		require.NoError(t, os.WriteFile(scriptPath, []byte("print(1)"), 0o644))

		reqPath := filepath.Join(tmpDir, "requirements.txt")
		require.NoError(t, os.WriteFile(reqPath, []byte("/definitely/missing-package.whl\n"), 0o644))

		algo := &python{
			algoFile:         scriptPath,
			requirementsFile: reqPath,
			runtime:          "python3",
			stderr:           io.Discard,
			stdout:           io.Discard,
		}
		err = algo.Run()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error installing requirements")
	})
}

func TestNewAlgorithmEmptyRuntime(t *testing.T) {
	eventsSvc := new(mocks.Service)
	algo := NewAlgorithm(slog.Default(), eventsSvc, "", "req.txt", "algo.py", nil, "")
	p := algo.(*python)
	if p.runtime != PyRuntime {
		t.Errorf("Expected default runtime %s, got %s", PyRuntime, p.runtime)
	}
}
