// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import "testing"

func TestHumanAssuranceVocabulary(t *testing.T) {
	t.Parallel()

	want := []HumanAssuranceLevel{
		"gateway-asserted-for-human",
		"authenticated-human-evidence",
		"human-held-key-exact-request",
	}
	got := []HumanAssuranceLevel{
		HumanAssuranceGatewayAssertedForHuman,
		HumanAssuranceAuthenticatedHumanEvidence,
		HumanAssuranceHumanHeldKeyExactRequest,
	}
	for index := range want {
		if got[index] != want[index] {
			t.Errorf("assurance level %d = %q, want %q", index, got[index], want[index])
		}
	}
	if CurrentHumanAssuranceLevel != HumanAssuranceGatewayAssertedForHuman {
		t.Fatalf("current assurance = %q, want %q", CurrentHumanAssuranceLevel, HumanAssuranceGatewayAssertedForHuman)
	}
}
