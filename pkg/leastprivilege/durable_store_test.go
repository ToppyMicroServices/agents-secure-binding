// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package leastprivilege

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const durableEffectLine = "operation:one\n"

func durablePlatform(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("durable filesystem adapter supports Linux and macOS")
	}
}

type durableFixture struct {
	now      time.Time
	request  Request
	mandate  Mandate
	cap      Capability
	key      ed25519.PublicKey
	config   AuthorizerConfig
	solution Solution
}

func newDurableFixture(t *testing.T) durableFixture {
	t.Helper()
	f := durableFixture{now: time.Date(2026, 9, 10, 10, 0, 0, 0, time.UTC), request: Request{ActorID: "agent:one", TaskID: "task:one", Action: Action{Operation: "storage.read", Resource: "object:one", Arguments: []byte("version:one")}}}
	p := Problem{Schema: ProblemSchemaV1, Permissions: []Permission{{ID: "read", Cost: 1}}, Grants: []Grant{{ID: "reader", Permissions: []string{"read"}}}, Required: []string{"read"}, Allowed: []string{"read"}}
	var err error
	f.solution, err = Solve(context.Background(), p, 2)
	if err != nil {
		t.Fatal(err)
	}
	ad, err := DigestAction(f.request.Action)
	if err != nil {
		t.Fatal(err)
	}
	f.mandate = Mandate{ID: "mandate:one", PolicyRef: "policy:one", ActorID: f.request.ActorID, TaskID: f.request.TaskID, ActionDigest: ad, ProblemDigest: f.solution.ProblemDigest, NotBefore: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(time.Hour), MaxTTLSeconds: 3600, AllowAutomatic: true}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	f.key = private.Public().(ed25519.PublicKey)
	f.config = AuthorizerConfig{Problem: p, Mandate: f.mandate, SigningKey: private, MaxEvaluations: 2, Clock: func() time.Time { return f.now }}
	a, err := NewAuthorizer(f.config)
	if err != nil {
		t.Fatal(err)
	}
	f.cap, err = a.Authorize(context.Background(), f.request, f.solution)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func createDurableFixtureStore(t *testing.T, capacity int) (*DurableStore, durableFixture) {
	t.Helper()
	durablePlatform(t)
	s, err := CreateDurableStore(filepath.Join(t.TempDir(), "store"), capacity)
	if err != nil {
		t.Fatal(err)
	}
	return s, newDurableFixture(t)
}

func TestDurableConsumptionSurvivesRestartCapacityAndClockPruning(t *testing.T) {
	s, f := createDurableFixtureStore(t, 1)
	ctx := context.Background()
	expiry := f.now.Add(time.Minute)
	if err := s.Use(ctx, "mandate:old", expiry, f.now); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenDurableStore(s.directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Use(ctx, "mandate:old", expiry, f.now); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay after restart: %v", err)
	}
	if err := reopened.Use(ctx, "mandate:new", expiry, f.now); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity evicted live record: %v", err)
	}
	if err := reopened.Use(ctx, "mandate:new", expiry.Add(time.Hour), expiry); err != nil {
		t.Fatal(err)
	}
	reopened, err = OpenDurableStore(s.directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Use(ctx, "mandate:old", expiry, f.now); !errors.Is(err, ErrExpired) {
		t.Fatalf("clock rollback revived pruned record: %v", err)
	}
}

func TestDurablePrepareBindsOperationAndSurvivesKeyRotation(t *testing.T) {
	s, f := createDurableFixtureStore(t, 3)
	ctx := context.Background()
	r, created, err := s.Prepare(ctx, "operation:one", f.cap, f.key, f.mandate, f.request, f.now)
	if err != nil || !created {
		t.Fatalf("prepare: %+v %v %v", r, created, err)
	}
	rotated := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	f.config.SigningKey = rotated
	a, err := NewAuthorizer(f.config)
	if err != nil {
		t.Fatal(err)
	}
	cap, err := a.Authorize(ctx, f.request, f.solution)
	if err != nil {
		t.Fatal(err)
	}
	key := rotated.Public().(ed25519.PublicKey)
	if _, _, err := s.Prepare(ctx, "operation:other", cap, key, f.mandate, f.request, f.now); !errors.Is(err, ErrReplay) {
		t.Fatalf("key rotation replay: %v", err)
	}
	existing, created, err := s.Prepare(ctx, "operation:one", cap, key, f.mandate, f.request, f.now)
	if err != nil || created || existing != r {
		t.Fatalf("exact reissued capability failed: %+v %v %v", existing, created, err)
	}
	if err := ConsumeCapability(ctx, cap, key, f.mandate, f.request, f.now, s); !errors.Is(err, ErrReplay) {
		t.Fatalf("raw consumption bypassed operation reservation: %v", err)
	}
	f.mandate.ID = "mandate:other"
	f.config.Mandate = f.mandate
	a, err = NewAuthorizer(f.config)
	if err != nil {
		t.Fatal(err)
	}
	cap, err = a.Authorize(ctx, f.request, f.solution)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Prepare(ctx, "operation:one", cap, key, f.mandate, f.request, f.now); !errors.Is(err, ErrExecutionConflict) {
		t.Fatalf("operation substitution: %v", err)
	}
}

func TestDurableExpiredExecutionIdentitiesRemainReserved(t *testing.T) {
	for _, reuse := range []struct {
		name, operationID, mandateID string
		want                         error
	}{
		{name: "operation", operationID: "operation:one", mandateID: "mandate:two", want: ErrExecutionConflict},
		{name: "mandate", operationID: "operation:two", mandateID: "mandate:one", want: ErrReplay},
	} {
		t.Run(reuse.name, func(t *testing.T) {
			s, f := createDurableFixtureStore(t, 4)
			ctx := context.Background()
			calls := 0
			effect := func(context.Context, string, Request) (EffectResult, error) {
				calls++
				return EffectResult{State: ExecutionSucceeded, EvidenceDigest: f.mandate.ActionDigest}, nil
			}
			original, err := s.Run(ctx, "operation:one", f.cap, f.key, f.mandate, f.request, f.now, effect)
			if err != nil {
				t.Fatal(err)
			}
			future := f.mandate.ExpiresAt.Add(time.Minute)
			// Commit retention cleanup, then reopen so this exercises persisted
			// identity protection rather than an in-memory remembered record.
			if err := s.Use(ctx, "fresh-session", future.Add(time.Hour), future); err != nil {
				t.Fatal(err)
			}
			s, err = OpenDurableStore(s.directory)
			if err != nil {
				t.Fatal(err)
			}
			request := f.request
			request.Action.Resource = "object:two"
			mandate := f.mandate
			mandate.ID = reuse.mandateID
			mandate.NotBefore, mandate.ExpiresAt = future.Add(-time.Second), future.Add(time.Hour)
			mandate.ActionDigest, err = DigestAction(request.Action)
			if err != nil {
				t.Fatal(err)
			}
			config := f.config
			config.Mandate, config.Clock = mandate, func() time.Time { return future }
			authorizer, err := NewAuthorizer(config)
			if err != nil {
				t.Fatal(err)
			}
			capability, err := authorizer.Authorize(ctx, request, f.solution)
			if err != nil {
				t.Fatal(err)
			}
			_, err = s.Run(ctx, reuse.operationID, capability, f.key, mandate, request, future, effect)
			if !errors.Is(err, reuse.want) || calls != 1 {
				t.Fatalf("expired identity authorized another effect: calls=%d error=%v, want %v", calls, err, reuse.want)
			}
			retained, err := s.Lookup(ctx, original.OperationID, original.RequestDigest)
			if err != nil || retained != original {
				t.Fatalf("terminal evidence lost: %+v %v", retained, err)
			}
		})
	}
}

func TestDurableRunSerializesConcurrentEffects(t *testing.T) {
	s, f := createDurableFixtureStore(t, 2)
	var calls atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			reopened, err := OpenDurableStore(s.directory)
			if err != nil {
				t.Error(err)
				return
			}
			_, err = reopened.Run(context.Background(), "operation:one", f.cap, f.key, f.mandate, f.request, f.now, func(_ context.Context, id string, r Request) (EffectResult, error) {
				calls.Add(1)
				if id != "operation:one" || !bytes.Equal(r.Action.Arguments, f.request.Action.Arguments) {
					t.Error("effect binding changed")
				}
				r.Action.Arguments[0] = 'X'
				return EffectResult{State: ExecutionSucceeded, EvidenceDigest: f.mandate.ActionDigest}, nil
			})
			if err != nil && !errors.Is(err, ErrOutcomeUnknown) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if calls.Load() != 1 || string(f.request.Action.Arguments) != "version:one" {
		t.Fatalf("dispatch count=%d, caller bytes=%s", calls.Load(), f.request.Action.Arguments)
	}
}

func TestDurableUnknownRequiresAuthoritativeReconciliation(t *testing.T) {
	s, f := createDurableFixtureStore(t, 2)
	ctx := context.Background()
	calls := 0
	effect := func(context.Context, string, Request) (EffectResult, error) {
		calls++
		return EffectResult{}, errors.New("acknowledgment lost")
	}
	r, err := s.Run(ctx, "operation:one", f.cap, f.key, f.mandate, f.request, f.now, effect)
	if !errors.Is(err, ErrOutcomeUnknown) || r.State != ExecutionUnknown {
		t.Fatalf("uncertainty lost: %+v %v", r, err)
	}
	reopened, err := OpenDurableStore(s.directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Run(ctx, "operation:one", f.cap, f.key, f.mandate, f.request, f.now, effect); !errors.Is(err, ErrOutcomeUnknown) || calls != 1 {
		t.Fatalf("blind retry: %d %v", calls, err)
	}
	if _, err := reopened.Complete(ctx, r.OperationID, r.RequestDigest, ExecutionSucceeded, ""); !errors.Is(err, ErrBinding) {
		t.Fatalf("missing evidence accepted: %v", err)
	}
	if _, err := reopened.Complete(ctx, r.OperationID, f.mandate.ActionDigest, ExecutionSucceeded, f.mandate.ActionDigest); !errors.Is(err, ErrExecutionConflict) {
		t.Fatalf("wrong recovery digest accepted: %v", err)
	}
	r, err = reopened.Complete(ctx, r.OperationID, r.RequestDigest, ExecutionSucceeded, f.mandate.ActionDigest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Run(ctx, "operation:one", f.cap, f.key, f.mandate, f.request, f.now, effect); err != nil || calls != 1 {
		t.Fatalf("completed replay dispatched: %d %v", calls, err)
	}
	if _, err := reopened.Complete(ctx, r.OperationID, r.RequestDigest, ExecutionFailed, f.mandate.ActionDigest); !errors.Is(err, ErrExecutionConflict) {
		t.Fatalf("terminal outcome overwritten: %v", err)
	}
}

func TestDurableUnknownNotEvictedAfterExpiry(t *testing.T) {
	s, f := createDurableFixtureStore(t, 1)
	ctx := context.Background()
	r, _, err := s.Prepare(ctx, "operation:one", f.cap, f.key, f.mandate, f.request, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Start(ctx, r.OperationID, r.RequestDigest); err != nil {
		t.Fatal(err)
	}
	future := f.mandate.ExpiresAt.Add(time.Hour)
	if err := s.Use(ctx, "other", future.Add(time.Hour), future); !errors.Is(err, ErrCapacity) {
		t.Fatalf("uncertain operation was evicted: %v", err)
	}
	if _, err := s.Lookup(ctx, r.OperationID, r.RequestDigest); err != nil {
		t.Fatalf("lost reconciliation record: %v", err)
	}
}

func TestDurableTerminalCommitErrorRecoversWithoutRedispatch(t *testing.T) {
	s, f := createDurableFixtureStore(t, 2)
	calls := 0
	r, err := s.Run(context.Background(), "operation:one", f.cap, f.key, f.mandate, f.request, f.now,
		func(context.Context, string, Request) (EffectResult, error) {
			calls++
			s.cutpoint = func(point string) error {
				if point == "after-rename" {
					return errors.New("directory synchronization unavailable")
				}
				return nil
			}
			return EffectResult{State: ExecutionSucceeded, EvidenceDigest: f.mandate.ActionDigest}, nil
		})
	if !errors.Is(err, ErrOutcomeUnknown) || r.State != ExecutionRunning || calls != 1 {
		t.Fatalf("uncertain commit exposed terminal success: %+v %d %v", r, calls, err)
	}
	reopened, err := OpenDurableStore(s.directory)
	if err != nil {
		t.Fatal(err)
	}
	r, err = reopened.Run(context.Background(), "operation:one", f.cap, f.key, f.mandate, f.request, f.now,
		func(context.Context, string, Request) (EffectResult, error) { calls++; return EffectResult{}, nil })
	if err != nil || r.State != ExecutionSucceeded || calls != 1 {
		t.Fatalf("exact readback did not recover terminal write: %+v %d %v", r, calls, err)
	}
}

func TestDurableCancelAcceptedNeverCancelsRunningEffect(t *testing.T) {
	for _, start := range []bool{false, true} {
		s, f := createDurableFixtureStore(t, 1)
		ctx := context.Background()
		r, _, err := s.Prepare(ctx, "operation:one", f.cap, f.key, f.mandate, f.request, f.now)
		if err != nil {
			t.Fatal(err)
		}
		if start {
			if _, _, err := s.Start(ctx, r.OperationID, r.RequestDigest); err != nil {
				t.Fatal(err)
			}
			if _, err := s.CancelAccepted(ctx, r.OperationID, r.RequestDigest); !errors.Is(err, ErrExecutionConflict) {
				t.Fatalf("running effect canceled: %v", err)
			}
			continue
		}
		r, err = s.CancelAccepted(ctx, r.OperationID, r.RequestDigest)
		if err != nil || r.State != ExecutionFailed {
			t.Fatalf("undispatched cancellation: %+v %v", r, err)
		}
		if _, started, err := s.Start(ctx, r.OperationID, r.RequestDigest); err != nil || started {
			t.Fatalf("canceled operation started: %v %v", started, err)
		}
		future := f.mandate.ExpiresAt.Add(time.Minute)
		if err := s.Use(ctx, "new", future.Add(time.Hour), future); !errors.Is(err, ErrCapacity) {
			t.Fatalf("canceled execution identity evicted to free capacity: %v", err)
		}
		retained, err := s.Lookup(ctx, r.OperationID, r.RequestDigest)
		if err != nil || retained != r {
			t.Fatalf("canceled execution evidence lost: %+v %v", retained, err)
		}
	}
}

func TestDurableCreatePreservesExistingAndPartialInitialization(t *testing.T) {
	s, f := createDurableFixtureStore(t, 1)
	ctx := context.Background()
	if err := s.Use(ctx, "reserved", f.mandate.ExpiresAt, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateDurableStore(s.directory, 1); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("existing store was recreated: %v", err)
	}
	reopened, err := OpenDurableStore(s.directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Use(ctx, "reserved", f.mandate.ExpiresAt, f.now); !errors.Is(err, ErrReplay) {
		t.Fatalf("recreation attempt erased consumption: %v", err)
	}
	// A path left before state publication must also require investigation;
	// missing state is not evidence that retrying initialization is safe.
	partial := filepath.Join(t.TempDir(), "partial")
	if err := os.Mkdir(partial, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDurableStore(partial); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("incomplete state opened: %v", err)
	}
	if _, err := CreateDurableStore(partial, 1); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("incomplete state reset: %v", err)
	}
	if info, err := os.Stat(partial); err != nil || !info.IsDir() {
		t.Fatalf("failed initialization removed existing path: %v", err)
	}
}

func TestDurableOutageCancellationAndMissingHistoryFailClosed(t *testing.T) {
	s, f := createDurableFixtureStore(t, 2)
	ctx := context.Background()
	lock, err := acquireDurableLock(ctx, filepath.Join(s.directory, "lock"))
	if err != nil {
		t.Fatal(err)
	}
	deadline, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	err = s.Use(deadline, "blocked", f.mandate.ExpiresAt, f.now)
	cancel()
	releaseDurableLock(lock)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lock wait ignored cancellation: %v", err)
	}
	if err := os.Remove(filepath.Join(s.directory, "state.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDurableStore(s.directory); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("missing history reopened: %v", err)
	}
	called := false
	if _, err := s.Run(ctx, "operation:one", f.cap, f.key, f.mandate, f.request, f.now, func(context.Context, string, Request) (EffectResult, error) {
		called = true
		return EffectResult{}, nil
	}); !errors.Is(err, ErrStoreUnavailable) || called {
		t.Fatalf("outage dispatched: %v %v", called, err)
	}
}

func TestDurableCorruptionFailsClosed(t *testing.T) {
	for _, bad := range []string{"", `{}`, `{"schema":"future"}`, `{"schema":`, strings.Repeat("x", maxDurableBytes+1)} {
		s, _ := createDurableFixtureStore(t, 1)
		if err := os.WriteFile(filepath.Join(s.directory, "state.json"), []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenDurableStore(s.directory); !errors.Is(err, ErrStoreUnavailable) {
			t.Fatalf("bad state accepted: length=%d err=%v", len(bad), err)
		}
	}
	s, f := createDurableFixtureStore(t, 1)
	if err := s.Use(context.Background(), "mandate:old", f.mandate.ExpiresAt, f.now); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.directory, "state.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// A syntactically valid mutation must also fail, not only malformed JSON.
	raw = bytes.Replace(raw, []byte("mandate:old"), []byte("mandate:new"), 1)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDurableStore(s.directory); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("valid JSON corruption accepted: %v", err)
	}
}

func TestDurableUnsupportedPlatformFailsClosed(t *testing.T) {
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		return
	}
	if _, err := CreateDurableStore(filepath.Join(t.TempDir(), "store"), 1); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("unsupported platform accepted durable store: %v", err)
	}
}

func TestDurableIndependentProcessesShareSingleUse(t *testing.T) {
	s, _ := createDurableFixtureStore(t, 4)
	var commands []*exec.Cmd
	var outputs []*bytes.Buffer
	for range 4 {
		cmd := durableHelper(t, s.directory, "run", "")
		buf := new(bytes.Buffer)
		cmd.Stdout = buf
		cmd.Stderr = buf
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		commands = append(commands, cmd)
		outputs = append(outputs, buf)
	}
	for i, cmd := range commands {
		if err := cmd.Wait(); err != nil {
			t.Fatalf("child: %v %s", err, outputs[i])
		}
	}
	raw, err := os.ReadFile(filepath.Join(s.directory, "effects"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != durableEffectLine {
		t.Fatalf("multiple independent processes dispatched: %q", raw)
	}
}

func TestDurableProcessCrashesAtCommitCutpoints(t *testing.T) {
	for _, point := range []string{"after-write", "before-rename", "after-rename", "after-directory-sync"} {
		t.Run(point, func(t *testing.T) {
			s, f := createDurableFixtureStore(t, 2)
			cmd := durableHelper(t, s.directory, "prepare-crash", point)
			if out, err := cmd.CombinedOutput(); err == nil {
				t.Fatalf("child did not crash: %s", out)
			}
			reopened, err := OpenDurableStore(s.directory)
			if err != nil {
				t.Fatal(err)
			}
			digest, err := DigestExecution("operation:one", f.mandate, f.request)
			if err != nil {
				t.Fatal(err)
			}
			_, lookupErr := reopened.Lookup(context.Background(), "operation:one", digest)
			if point == "after-write" || point == "before-rename" {
				if !errors.Is(lookupErr, ErrExecutionNotFound) {
					t.Fatalf("partial reservation committed: %v", lookupErr)
				}
			} else if lookupErr != nil {
				t.Fatalf("post-rename recovery lost committed reservation: %v", lookupErr)
			}
			if out, err := durableHelper(t, s.directory, "run", "").CombinedOutput(); err != nil {
				t.Fatalf("recovery: %v %s", err, out)
			}
			raw, err := os.ReadFile(filepath.Join(s.directory, "effects"))
			if err != nil || string(raw) != durableEffectLine {
				t.Fatalf("effect: %q %v", raw, err)
			}
		})
	}
}

func TestDurableProcessCrashBeforeAndAfterEffectNeverRedispatches(t *testing.T) {
	for _, mode := range []string{"crash-before-effect", "crash-after-effect", "complete-crash"} {
		t.Run(mode, func(t *testing.T) {
			s, f := createDurableFixtureStore(t, 2)
			if out, err := durableHelper(t, s.directory, mode, "").CombinedOutput(); err == nil {
				t.Fatalf("child did not crash: %s", out)
			}
			reopened, err := OpenDurableStore(s.directory)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			r, err := reopened.Run(context.Background(), "operation:one", f.cap, f.key, f.mandate, f.request, f.now, func(context.Context, string, Request) (EffectResult, error) { calls++; return EffectResult{}, nil })
			if !errors.Is(err, ErrOutcomeUnknown) || calls != 0 || r.State != ExecutionRunning {
				t.Fatalf("crash dispatched twice: %+v %d %v", r, calls, err)
			}
			if mode != "crash-before-effect" {
				raw, err := os.ReadFile(filepath.Join(s.directory, "effects"))
				if err != nil || string(raw) != durableEffectLine {
					t.Fatalf("effect disappeared: %q %v", raw, err)
				}
			}
		})
	}
}

func durableHelper(t *testing.T, path, mode, point string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestDurableProcessHelper$")
	cmd.Env = append(os.Environ(), "ASB_DURABLE_HELPER="+mode, "ASB_DURABLE_DIRECTORY="+path, "ASB_DURABLE_CUTPOINT="+point)
	return cmd
}

func TestDurableProcessHelper(t *testing.T) {
	mode := os.Getenv("ASB_DURABLE_HELPER")
	if mode == "" {
		return
	}
	s, err := OpenDurableStore(os.Getenv("ASB_DURABLE_DIRECTORY"))
	if err != nil {
		t.Fatal(err)
	}
	f := newDurableFixture(t)
	if mode == "prepare-crash" {
		s.cutpoint = func(point string) error {
			if point == os.Getenv("ASB_DURABLE_CUTPOINT") {
				os.Exit(88)
			}
			return nil
		}
		_, _, err = s.Prepare(context.Background(), "operation:one", f.cap, f.key, f.mandate, f.request, f.now)
		if err != nil {
			t.Fatal(err)
		}
		t.Fatal("cutpoint not reached")
	}
	_, err = s.Run(context.Background(), "operation:one", f.cap, f.key, f.mandate, f.request, f.now, func(_ context.Context, id string, _ Request) (EffectResult, error) {
		if mode == "crash-before-effect" {
			os.Exit(88)
		}
		file, err := os.OpenFile(filepath.Join(s.directory, "effects"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return EffectResult{}, err
		}
		_, err = fmt.Fprintln(file, id)
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return EffectResult{}, err
		}
		if mode == "crash-after-effect" {
			os.Exit(88)
		}
		if mode == "complete-crash" {
			s.cutpoint = func(point string) error {
				if point == "before-rename" {
					os.Exit(88)
				}
				return nil
			}
		}
		return EffectResult{State: ExecutionSucceeded, EvidenceDigest: f.mandate.ActionDigest}, nil
	})
	if err != nil && !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatal(err)
	}
}
