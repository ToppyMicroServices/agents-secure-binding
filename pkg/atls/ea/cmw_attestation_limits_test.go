// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package ea

import (
	"errors"
	"testing"
)

func TestCMWAttestationDataExtensionLengthBoundary(t *testing.T) {
	maximum := make([]byte, 0xFFFF-cmwAttestationLengthBytes)
	if _, err := CMWAttestationDataExtension(maximum); err != nil {
		t.Fatalf("maximum payload rejected: %v", err)
	}

	tooLarge := make([]byte, len(maximum)+1)
	if _, err := CMWAttestationDataExtension(tooLarge); !errors.Is(err, ErrInvalidLength) {
		t.Fatalf("oversized payload error = %v, want %v", err, ErrInvalidLength)
	}
}
