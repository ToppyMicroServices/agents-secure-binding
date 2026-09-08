// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanrelay

import (
	"strings"
	"testing"
)

func TestRelayIdentifierSemanticOctetAndUnicodeRules(t *testing.T) {
	t.Parallel()
	valid := []string{
		strings.Repeat("a", 256), strings.Repeat("é", 128),
		"intent:é", "intent:e\u0301", "Case:SENSITIVE", "interior whitespace",
	}
	invalid := []string{
		"", strings.Repeat("a", 257), strings.Repeat("é", 129),
		" leading", "trailing ", "\u00a0leading", "trailing\u3000",
		"control\u0001", "control\u0085",
	}
	for _, value := range valid {
		if err := validateID("identifier", value); err != nil {
			t.Errorf("valid relay identifier %q rejected: %v", value, err)
		}
	}
	for _, value := range invalid {
		if err := validateID("identifier", value); err == nil {
			t.Errorf("invalid relay identifier %q accepted", value)
		}
	}
}
