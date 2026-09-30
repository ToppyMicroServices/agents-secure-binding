// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package s3product

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege/asbbinding"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege/awsiam"
)

type diagnosticEvent struct {
	Time        time.Time          `json:"time"`
	Stage       string             `json:"stage"`
	Code        string             `json:"code"`
	Correlation string             `json:"correlation,omitempty"`
	Suppressed  uint64             `json:"suppressed,omitempty"`
	CLI         *awsiam.CLIFailure `json:"cli,omitempty"`
}

// At most 60 events per 30 seconds and 64 queued records. A stalled journal
// never stalls an execution. There is one writer per process; the supervisor's
// final kill remains the bound for a kernel-blocked write, as for other I/O.
type diagnostics struct {
	mu         sync.Mutex
	queue      chan diagnosticEvent
	done       chan struct{}
	closed     bool
	window     time.Time
	count      int
	suppressed uint64
}

func newDiagnostics(out io.Writer) *diagnostics {
	d := &diagnostics{queue: make(chan diagnosticEvent, 64), done: make(chan struct{})}
	go func() {
		defer close(d.done)
		encoder := json.NewEncoder(out)
		for event := range d.queue {
			// Logging failure must not change an already committed outcome.
			if err := encoder.Encode(event); err != nil {
				d.mu.Lock()
				// The failed event also carried counts that were not delivered.
				d.suppressed += event.Suppressed + 1
				d.mu.Unlock()
				// Encoder retains I/O errors. Let the next event reach a recovered
				// sink without replaying this failed event or its AWS operation.
				encoder = json.NewEncoder(out)
			}
		}
	}()
	return d
}

func (d *diagnostics) emit(stage, code, id string) {
	d.emitCLI(stage, code, id, nil)
}

func (d *diagnostics) emitCLI(stage, code, id string, cli *awsiam.CLIFailure) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	now := time.Now().UTC()
	if now.Sub(d.window) >= 30*time.Second {
		d.window, d.count = now, 0
	}
	if d.count >= 60 {
		d.suppressed++
		return
	}
	event := diagnosticEvent{Time: now, Stage: stage, Code: code, Suppressed: d.suppressed, CLI: cli}
	if id != "" {
		hash := sha256.Sum256([]byte(id))
		event.Correlation = hex.EncodeToString(hash[:16])
	}
	select {
	case d.queue <- event:
		d.count++
		d.suppressed = 0
	default:
		d.suppressed++
	}
}

// Write intentionally discards the HTTP server's raw, peer-influenced text.
func (d *diagnostics) Write(raw []byte) (int, error) {
	d.emit("transport", "server_error", "")
	return len(raw), nil
}

func (d *diagnostics) Close() {
	d.mu.Lock()
	if !d.closed {
		d.closed = true
		close(d.queue)
	}
	d.mu.Unlock()
	select {
	case <-d.done:
	case <-time.After(time.Second):
	}
}

func (d *diagnostics) executor(next asbbinding.Executor) asbbinding.Executor {
	return func(ctx context.Context, id string, request lp.Request, solution lp.Solution) (lp.EffectResult, error) {
		result, err := next(ctx, id, request, solution)
		if err != nil {
			stage, code := awsiam.Diagnostic(err)
			d.emitCLI(stage, code, id, awsiam.CLIDiagnostic(err))
		}
		return result, err
	}
}

type observedStore struct {
	*lp.SQLiteStore
	diagnostics *diagnostics
}

func (s *observedStore) Run(ctx context.Context, id string, cap lp.Capability, key ed25519.PublicKey, mandate lp.Mandate, request lp.Request, now time.Time, effect lp.Effect) (lp.ExecutionRecord, error) {
	result, err := s.SQLiteStore.Run(ctx, id, cap, key, mandate, request, now, effect)
	if errors.Is(err, lp.ErrStoreUnavailable) {
		s.diagnostics.emit("journal", "execution_persistence_failed", id)
	} else if errors.Is(err, lp.ErrOutcomeUnknown) {
		s.diagnostics.emit("execution", "outcome_unknown", id)
	}
	return result, err
}

func (s *observedStore) Use(ctx context.Context, key string, expiry, now time.Time) error {
	err := s.SQLiteStore.Use(ctx, key, expiry, now)
	if errors.Is(err, lp.ErrStoreUnavailable) {
		s.diagnostics.emit("journal", "proof_persistence_failed", "")
	}
	return err
}
