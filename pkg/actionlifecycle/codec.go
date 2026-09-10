// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionlifecycle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/strictjson"
)

// DecodeSnapshot strictly decodes and validates one bounded durable snapshot.
func DecodeSnapshot(r io.Reader) (Snapshot, error) {
	if r == nil {
		return Snapshot{}, fmt.Errorf("%w: missing JSON input", ErrInvalidSnapshot)
	}
	raw, err := strictjson.ReadDocument(r, MaxSnapshotBytes)
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrInvalidSnapshot, err)
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
