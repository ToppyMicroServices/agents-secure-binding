//go:build linux

// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanrelay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const missingRelayTestCase = "missing"

func TestFileRelayRequiresPrivateImmediateDirectory(t *testing.T) {
	fixture := newRelayFixture(t)
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileStore(filepath.Join(parent, "relay.json"), fixture.directory); !errors.Is(err, ErrStoreUnavailable) || !strings.Contains(err.Error(), "state directory must be private") {
		t.Fatalf("non-private immediate directory accepted: %v", err)
	}
	// A new dedicated child is created privately without changing its parent.
	path := filepath.Join(parent, "private", "relay.json")
	if _, err := OpenFileStore(path, fixture.directory); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Dir(path))
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("state directory mode = %v, error = %v", info, err)
	}
	info, err = os.Stat(parent)
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("opening store changed parent permissions: %v, %v", info, err)
	}
}

func openRelayFileTest(t *testing.T, path string, fixture *relayFixture) *FileStore {
	t.Helper()
	store, err := OpenFileStore(path, fixture.directory)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func queueRelayFileTest(t *testing.T, store *FileStore, fixture *relayFixture) {
	t.Helper()
	if _, err := store.CommitAuthorizedIntent(context.Background(), QueueCommit{fixture.request, fixture.auth, fixture.now}); err != nil {
		t.Fatal(err)
	}
}

func TestFileRelayCrashAfterProviderEffectRecoversWithoutRedispatch(t *testing.T) {
	fixture := newRelayFixture(t)
	path := filepath.Join(t.TempDir(), "private", "relay.json")
	store := openRelayFileTest(t, path, fixture)
	queueRelayFileTest(t, store, fixture)
	cmd := relayChild(path, "crash")
	output, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 86 {
		t.Fatalf("child did not reach callback cut point: %v %s", err, output)
	}
	store = openRelayFileTest(t, path, fixture)
	_, receipt, err := store.LoadIntent(context.Background(), fixture.request.IntentID)
	if err != nil || receipt.Status != StatusDispatching {
		t.Fatalf("lost durable unknown attempt: %+v %v", receipt, err)
	}
	var calls atomic.Int32
	dispatcher := relayDispatchFunc(func(context.Context, DispatchRequest) (ProviderAck, error) {
		calls.Add(1)
		return ProviderAck{}, errors.New("must not redispatch")
	})
	if _, err := store.CommitAuthorizedDispatch(context.Background(), fixture.request.IntentID, dispatcher, time.Now); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("blind redispatch")
	}
	evidence, err := os.ReadFile(path + ".provider")
	if err != nil {
		t.Fatal(err)
	}
	var request DispatchRequest
	if err := json.Unmarshal(bytes.TrimSpace(evidence), &request); err != nil {
		t.Fatal(err)
	}
	provider := relayLookupFunc(func(_ context.Context, actual DispatchRequest) (ProviderAck, bool, error) {
		if !sameJSON(actual, request) {
			return ProviderAck{}, false, errors.New("binding mismatch")
		}
		return ProviderAck{IntentID: actual.IntentID, AckRef: "ack:durable-provider", At: time.Now().Add(24 * time.Hour)}, true, nil
	})
	receipt, err = store.ReconcileDispatch(context.Background(), fixture.request.IntentID, provider, time.Now)
	if err != nil || receipt.Status != StatusProviderAcknowledged || receipt.UpdatedAt.After(time.Now()) {
		t.Fatalf("reconciliation: %+v %v", receipt, err)
	}
	store = openRelayFileTest(t, path, fixture)
	before := receipt
	provider = relayLookupFunc(func(context.Context, DispatchRequest) (ProviderAck, bool, error) {
		t.Fatal("terminal outcome queried again")
		return ProviderAck{}, false, nil
	})
	receipt, err = store.ReconcileDispatch(context.Background(), fixture.request.IntentID, provider, time.Now)
	if err != nil || !sameJSON(before, receipt) {
		t.Fatalf("terminal outcome changed: %+v %v", receipt, err)
	}
}

func TestFileRelayConcurrentProcessesReserveOneProviderAttempt(t *testing.T) {
	fixture := newRelayFixture(t)
	path := filepath.Join(t.TempDir(), "private", "relay.json")
	queueRelayFileTest(t, openRelayFileTest(t, path, fixture), fixture)
	a, b := relayChild(path, "dispatch"), relayChild(path, "dispatch")
	var aOutput, bOutput bytes.Buffer
	a.Stdout, a.Stderr, b.Stdout, b.Stderr = &aOutput, &aOutput, &bOutput, &bOutput
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	if err := b.Start(); err != nil {
		_ = a.Process.Kill()
		_ = a.Wait()
		t.Fatal(err)
	}
	if err := a.Wait(); err != nil {
		t.Fatalf("worker a: %v %s", err, aOutput.String())
	}
	if err := b.Wait(); err != nil {
		t.Fatalf("worker b: %v %s", err, bOutput.String())
	}
	raw, err := os.ReadFile(path + ".provider")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(raw, []byte("\n")) != 1 {
		t.Fatalf("provider called more than once: %s", raw)
	}
}

func relayChild(path, mode string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^TestFileRelayProcessHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), "ASB_RELAY_HELPER_PATH="+path, "ASB_RELAY_HELPER_MODE="+mode)
	return cmd
}

func TestFileRelayProcessHelper(t *testing.T) {
	path := os.Getenv("ASB_RELAY_HELPER_PATH")
	if path == "" {
		return
	}
	fixture := newRelayFixture(t)
	store := openRelayFileTest(t, path, fixture)
	dispatcher := relayDispatchFunc(func(_ context.Context, request DispatchRequest) (ProviderAck, error) {
		raw, err := json.Marshal(request)
		if err != nil {
			return ProviderAck{}, err
		}
		f, err := os.OpenFile(path+".provider", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return ProviderAck{}, err
		}
		if _, err := f.Write(append(raw, '\n')); err != nil {
			_ = f.Close()
			return ProviderAck{}, err
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return ProviderAck{}, err
		}
		if err := f.Close(); err != nil {
			return ProviderAck{}, err
		}
		if os.Getenv("ASB_RELAY_HELPER_MODE") == "crash" {
			os.Exit(86)
		}
		return ProviderAck{IntentID: request.IntentID, AckRef: "ack:process"}, nil
	})
	if _, err := store.CommitAuthorizedDispatch(context.Background(), fixture.request.IntentID, dispatcher, time.Now); err != nil {
		t.Fatal(err)
	}
}

func TestFileRelayFailedDispatchCheckpointNeverCallsProvider(t *testing.T) {
	fixture := newRelayFixture(t)
	path := filepath.Join(t.TempDir(), "private", "relay.json")
	store := openRelayFileTest(t, path, fixture)
	queueRelayFileTest(t, store, fixture)
	store.beforePersist = func(state relayDiskState) error {
		if state.Records[fixture.request.IntentID].Receipt.Status == StatusDispatching {
			return ErrStoreUnavailable
		}
		return nil
	}
	var calls atomic.Int32
	dispatcher := relayDispatchFunc(func(context.Context, DispatchRequest) (ProviderAck, error) { calls.Add(1); return ProviderAck{}, nil })
	if _, err := store.CommitAuthorizedDispatch(context.Background(), fixture.request.IntentID, dispatcher, time.Now); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("checkpoint failure: %v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("provider called before durable reservation")
	}
	_, receipt, err := openRelayFileTest(t, path, fixture).LoadIntent(context.Background(), fixture.request.IntentID)
	if err != nil || receipt.Status != StatusQueued {
		t.Fatalf("failed checkpoint changed state: %+v %v", receipt, err)
	}
}

func TestFileRelayRechecksTimeAfterDurableReservation(t *testing.T) {
	for _, mode := range []string{"expired", "rollback", "zero"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newRelayFixture(t)
			path := filepath.Join(t.TempDir(), "private", "relay.json")
			store := openRelayFileTest(t, path, fixture)
			queueRelayFileTest(t, store, fixture)
			at := fixture.now
			store.beforePersist = func(state relayDiskState) error {
				if state.Records[fixture.request.IntentID].Receipt.Status == StatusDispatching {
					switch mode {
					case "expired":
						at = fixture.grant.ExpiresAt
					case "rollback":
						at = fixture.now.Add(-time.Hour)
					case "zero":
						at = time.Time{}
					}
				}
				return nil
			}
			var calls int
			dispatcher := relayDispatchFunc(func(context.Context, DispatchRequest) (ProviderAck, error) { calls++; return ProviderAck{}, nil })
			if _, err := store.CommitAuthorizedDispatch(context.Background(), fixture.request.IntentID, dispatcher, func() time.Time { return at }); !errors.Is(err, ErrDispatchUnavailable) {
				t.Fatalf("invalid post-checkpoint time: %v", err)
			}
			if calls != 0 {
				t.Fatal("provider received expired or not-yet-valid authorization")
			}
			_, receipt, err := openRelayFileTest(t, path, fixture).LoadIntent(context.Background(), fixture.request.IntentID)
			if err != nil || receipt.Status != StatusDispatching {
				t.Fatalf("reservation was reset: %+v %v", receipt, err)
			}
		})
	}
}

func TestFileRelayPostRenameFailureFencesHandle(t *testing.T) {
	fixture := newRelayFixture(t)
	path := filepath.Join(t.TempDir(), "private", "relay.json")
	store := openRelayFileTest(t, path, fixture)
	queueRelayFileTest(t, store, fixture)
	store.afterRename = func() error { return ErrStoreUnavailable }
	var calls atomic.Int32
	dispatcher := relayDispatchFunc(func(context.Context, DispatchRequest) (ProviderAck, error) { calls.Add(1); return ProviderAck{}, nil })
	if _, err := store.CommitAuthorizedDispatch(context.Background(), fixture.request.IntentID, dispatcher, time.Now); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("post-rename error: %v", err)
	}
	if _, err := store.Pending(context.Background(), "", 1); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("fenced handle remained usable: %v", err)
	}
	store = openRelayFileTest(t, path, fixture)
	receipt, err := store.CommitAuthorizedDispatch(context.Background(), fixture.request.IntentID, dispatcher, time.Now)
	if err != nil || receipt.Status != StatusDispatching || calls.Load() != 0 {
		t.Fatalf("ambiguous marker permitted dispatch: %+v %v calls=%d", receipt, err, calls.Load())
	}
}

func TestFileRelayReconciliationMissingInvalidAndPrivateErrorsRemainUnknown(t *testing.T) {
	for _, mode := range []string{missingRelayTestCase, "error", "mismatch", "clock rollback", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newRelayFixture(t)
			path := filepath.Join(t.TempDir(), "private", "relay.json")
			store := openRelayFileTest(t, path, fixture)
			queueRelayFileTest(t, store, fixture)
			if _, err := store.CommitAuthorizedDispatch(context.Background(), fixture.request.IntentID, &failingDispatcher{}, time.Now); !errors.Is(err, ErrDispatchUnavailable) {
				t.Fatal(err)
			}
			provider := relayLookupFunc(func(ctx context.Context, request DispatchRequest) (ProviderAck, bool, error) {
				switch mode {
				case missingRelayTestCase:
					return ProviderAck{}, false, nil
				case "error":
					return ProviderAck{}, false, errors.New("private-recipient@example.test")
				case "mismatch":
					return ProviderAck{IntentID: "other", AckRef: "ack"}, true, nil
				case "timeout":
					<-ctx.Done()
					return ProviderAck{}, false, ctx.Err()
				default:
					return ProviderAck{IntentID: request.IntentID, AckRef: "ack"}, true, nil
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			now := time.Now
			if mode == "clock rollback" {
				now = func() time.Time { return fixture.now.Add(-time.Minute) }
			}
			_, err := store.ReconcileDispatch(ctx, fixture.request.IntentID, provider, now)
			if mode != missingRelayTestCase && err == nil {
				t.Fatal("invalid observation accepted")
			}
			if err != nil && strings.Contains(err.Error(), "private-recipient") {
				t.Fatal("provider-private error leaked")
			}
			_, receipt, err := openRelayFileTest(t, path, fixture).LoadIntent(context.Background(), fixture.request.IntentID)
			if err != nil || receipt.Status != StatusDispatching {
				t.Fatalf("unknown was lost: %+v %v", receipt, err)
			}
		})
	}
}

func TestFileRelayRejectsCorruptionMissingStateSymlinkAndPermissiveFiles(t *testing.T) {
	for _, mode := range []string{"duplicate", "unknown", "history", missingRelayTestCase, "symlink", "mode", "lock symlink", "state hardlink", "lock hardlink", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newRelayFixture(t)
			path := filepath.Join(t.TempDir(), "private", "relay.json")
			queueRelayFileTest(t, openRelayFileTest(t, path, fixture), fixture)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "duplicate":
				err = os.WriteFile(path, append([]byte(`{"schema":"bad",`), raw[1:]...), 0o600)
			case "unknown":
				err = os.WriteFile(path, append([]byte(`{"surprise":true,`), raw[1:]...), 0o600)
			case "history":
				var state relayDiskState
				if err := json.Unmarshal(raw, &state); err != nil {
					t.Fatal(err)
				}
				record := state.Records[fixture.request.IntentID]
				record.Receipt.Status = StatusProviderAcknowledged
				state.Records[fixture.request.IntentID] = record
				raw, err = json.Marshal(state)
				if err == nil {
					err = os.WriteFile(path, raw, 0o600)
				}
			case missingRelayTestCase:
				err = os.Remove(path)
			case "symlink":
				if err := os.Rename(path, path+".target"); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(path+".target", path)
			case "state hardlink":
				err = os.Link(path, path+".alias")
			case "lock hardlink":
				err = os.Link(path+".lock", path+".alias.lock")
			case "lock symlink":
				if err := os.Rename(path+".lock", path+".target"); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(path+".target", path+".lock")
			case "mode":
				err = os.Chmod(path, 0o644)
			case "oversize":
				err = os.WriteFile(path, bytes.Repeat([]byte(" "), maxRelayStateBytes+1), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := OpenFileStore(path, fixture.directory); !errors.Is(err, ErrStoreUnavailable) {
				t.Fatalf("unsafe state accepted: %v", err)
			}
		})
	}
}

func TestFileRelayLockWaitHonorsCancellation(t *testing.T) {
	fixture := newRelayFixture(t)
	path := filepath.Join(t.TempDir(), "private", "relay.json")
	store := openRelayFileTest(t, path, fixture)
	queueRelayFileTest(t, store, fixture)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	dispatcher := relayDispatchFunc(func(context.Context, DispatchRequest) (ProviderAck, error) {
		close(entered)
		<-release
		return ProviderAck{IntentID: fixture.request.IntentID, AckRef: "ack"}, nil
	})
	go func() {
		_, err := store.CommitAuthorizedDispatch(context.Background(), fixture.request.IntentID, dispatcher, time.Now)
		done <- err
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	_, _, err := store.LoadIntent(ctx, fixture.request.IntentID)
	close(release)
	if workerErr := <-done; workerErr != nil {
		t.Fatal(workerErr)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lock did not cancel: %v", err)
	}
}

type relayDispatchFunc func(context.Context, DispatchRequest) (ProviderAck, error)

func (f relayDispatchFunc) Dispatch(ctx context.Context, request DispatchRequest) (ProviderAck, error) {
	return f(ctx, request)
}

type relayLookupFunc func(context.Context, DispatchRequest) (ProviderAck, bool, error)

func (f relayLookupFunc) Lookup(ctx context.Context, request DispatchRequest) (ProviderAck, bool, error) {
	return f(ctx, request)
}
