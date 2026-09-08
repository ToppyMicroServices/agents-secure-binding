// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionlifecycle

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDecodeSnapshotRejectsDuplicateMembersAndOversize(t *testing.T) {
	t.Parallel()
	snapshot := newTestSnapshot(t, RecoveryPolicy{Mode: RecoveryManual, MaxAttempts: 1})
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string][]byte{
		"top-level duplicate": bytes.Replace(raw, []byte(`"action_id":`), []byte(`"action_id":"shadow","action_id":`), 1),
		"escaped duplicate":   bytes.Replace(raw, []byte(`"action_id":`), []byte(`"action_id":"shadow","action_i\u0064":`), 1),
		"nested duplicate":    bytes.Replace(raw, []byte(`"code":`), []byte(`"code":"SHADOW","code":`), 1),
		"oversized":           append(append([]byte(nil), raw...), bytes.Repeat([]byte{' '}, MaxSnapshotBytes-len(raw)+1)...),
	}
	for name, document := range tests {
		document := document
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeSnapshot(bytes.NewReader(document)); !errors.Is(err, ErrInvalidSnapshot) {
				t.Fatalf("DecodeSnapshot() error = %v, want %v", err, ErrInvalidSnapshot)
			}
		})
	}
	if _, err := DecodeSnapshot(strings.NewReader(string(raw))); err != nil {
		t.Fatalf("valid snapshot rejected: %v", err)
	}
	var typedNil *bytes.Reader
	if _, err := DecodeSnapshot(typedNil); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("typed-nil reader error = %v, want %v", err, ErrInvalidSnapshot)
	}
}
