// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"context"
	"errors"
	"testing"
)

func TestNilEvidenceSourceFuncFailsClosed(t *testing.T) {
	var source EvidenceSourceFunc
	if _, err := source.GetEvidence(context.Background(), EvidenceRequest{}); !errors.Is(err, ErrNilEvidenceSourceFunc) {
		t.Fatalf("GetEvidence() error = %v, want %v", err, ErrNilEvidenceSourceFunc)
	}
}
