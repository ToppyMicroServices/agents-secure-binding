// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package awsiam

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCLICancellationStopsChildGroupAndRemovesIdentity(t *testing.T) {
	e, _, _, cli := fakeExecutor(t)
	script := "#!/bin/sh\npwd > \"$0.session\"\n/bin/sleep 60 &\necho $! > \"$0.child\"\nwait\n"
	if err := os.WriteFile(cli, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := e.assume(ctx, "operation:cancel", nil); done <- err }()
	until := time.Now().Add(5 * time.Second)
	var pid int
	for time.Now().Before(until) {
		if raw, err := os.ReadFile(cli + ".child"); err == nil {
			pid, _ = strconv.Atoi(strings.TrimSpace(string(raw)))
			if pid > 0 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pid == 0 {
		t.Fatal("CLI child did not start")
	}
	start := time.Now()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if detail := CLIDiagnostic(err); detail == nil || detail.Failure != "cancelled" || detail.ProviderCode != "" {
			t.Fatal("cancellation lost its process diagnostic or became an AWS rejection")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("CLI did not cancel")
	}
	for time.Now().Before(until) {
		raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
		if os.IsNotExist(err) || (err == nil && strings.Contains(string(raw), ") Z ")) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat")); err == nil && !strings.Contains(string(raw), ") Z ") {
		t.Fatal("descendant still running after cancellation")
	}
	raw, err := os.ReadFile(cli + ".session")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(strings.TrimSpace(string(raw))); !os.IsNotExist(err) {
		t.Fatal("temporary credential copy retained")
	}
	t.Logf("cancel_ms=%d descendant_running=false temporary_retained=false", time.Since(start).Milliseconds())
}

func TestCLILaunchAndDeadlineDiagnostics(t *testing.T) {
	for _, name := range []string{"launch", "deadline"} {
		t.Run(name, func(t *testing.T) {
			e, _, _, cli := fakeExecutor(t)
			wantFailure, wantErr := "launch_or_io", ErrProvider
			if name == "launch" {
				e.config.Path = cli + ".missing"
			} else {
				if err := os.WriteFile(cli, []byte("#!/bin/sh\nexec /bin/sleep 60\n"), 0o700); err != nil {
					t.Fatal(err)
				}
				wantFailure, wantErr = "deadline", context.DeadlineExceeded
			}
			ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
			defer cancel()
			_, err := e.assume(ctx, "operation:process-diagnostic", nil)
			if !errors.Is(err, wantErr) {
				t.Fatalf("process failure changed its error contract: %v", err)
			}
			detail := CLIDiagnostic(err)
			if detail == nil || detail.Failure != wantFailure || detail.ExitCode != -1 || detail.Format != "empty" || detail.ProviderCode != "" {
				t.Fatal("process failure lost its diagnostic or became an AWS rejection")
			}
		})
	}
}
