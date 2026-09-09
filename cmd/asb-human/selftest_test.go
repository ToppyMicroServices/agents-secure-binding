// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSelfTestRunsAuthenticatedWorkflowAndRemovesTemporaryState(t *testing.T) {
	parent := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var output bytes.Buffer
	if err := runSelfTest(ctx, &output, parent); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"authenticated loopback", "Simulated approval: APPLIED", "Simulated denial: DENIED", "original outcomes recovered; no repeated effect"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("missing %q in %s", want, output.String())
		}
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("self-test left private state: %v, %v", entries, err)
	}
}

func TestSelfTestCommandReportsScopeAndSuccess(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"self-test", "--timeout", "30s"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Simulated Human gateway", "software-only TLS 1.3/mTLS", "PASS: local approval self-test completed.", "Temporary credentials and database removed.", "not real-Human or hardware qualification"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("missing scope or outcome %q in %s", want, stdout.String())
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected diagnostic output: %s", stderr.String())
	}
}

func TestSelfTestRejectsExistingStateAndUnboundedTimeout(t *testing.T) {
	for _, args := range [][]string{
		{"--data-dir", t.TempDir()}, {"--core-address", "127.0.0.1:8091"}, {"--timeout", "0"},
		{"--timeout", "-1s"}, {"--timeout", "6m"}, {"unexpected"},
	} {
		var stdout bytes.Buffer
		if err := run(context.Background(), append([]string{"self-test"}, args...), &stdout, io.Discard); err == nil {
			t.Errorf("accepted flags %v", args)
		}
		if strings.Contains(stdout.String(), "PASS") {
			t.Errorf("reported success for invalid flags %v", args)
		}
	}
}

func TestSelfTestCanceledOrExpiredNeverReportsSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var output bytes.Buffer
	if err := run(ctx, []string{"self-test"}, &output, io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation = %v", err)
	}
	if strings.Contains(output.String(), "PASS") {
		t.Fatal("cancellation was reported as success")
	}
	output.Reset()
	if err := run(context.Background(), []string{"self-test", "--timeout", "1ns"}, &output, io.Discard); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired timeout = %v", err)
	}
	if strings.Contains(output.String(), "PASS") {
		t.Fatal("expired timeout was reported as success")
	}
}

type failOnStepWriter struct{ err error }

func (w failOnStepWriter) Write([]byte) (int, error) { return 0, w.err }

func TestSelfTestFailureRemovesTemporaryState(t *testing.T) {
	parent := t.TempDir()
	failure := errors.New("synthetic output failure")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := runSelfTest(ctx, failOnStepWriter{failure}, parent); !errors.Is(err, failure) {
		t.Fatalf("output failure = %v", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed self-test left private state: %v, %v", entries, err)
	}
}

func TestSelfTestHelpHasNoApplicationDirectoryFlag(t *testing.T) {
	var help bytes.Buffer
	if err := run(context.Background(), []string{"self-test", "--help"}, io.Discard, &help); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(help.String(), "data-dir") || !strings.Contains(help.String(), "simulated Human") {
		t.Fatalf("unsafe or unclear help: %s", help.String())
	}
}
