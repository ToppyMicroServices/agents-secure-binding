// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionlifecycle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"
)

// DecodeSnapshot strictly decodes and validates one bounded durable snapshot.
func DecodeSnapshot(r io.Reader) (Snapshot, error) {
	if r == nil {
		return Snapshot{}, fmt.Errorf("%w: missing JSON input", ErrInvalidSnapshot)
	}
	raw, err := io.ReadAll(io.LimitReader(r, MaxSnapshotBytes+1))
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: read JSON: %v", ErrInvalidSnapshot, err)
	}
	if len(raw) > MaxSnapshotBytes {
		return Snapshot{}, fmt.Errorf("%w: JSON exceeds %d bytes", ErrInvalidSnapshot, MaxSnapshotBytes)
	}
	if !utf8.Valid(raw) {
		return Snapshot{}, fmt.Errorf("%w: JSON is not valid UTF-8", ErrInvalidSnapshot)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var snapshot Snapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("%w: decode JSON: %v", ErrInvalidSnapshot, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Snapshot{}, fmt.Errorf("%w: trailing JSON value", ErrInvalidSnapshot)
	}
	if err := snapshot.Validate(); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}
