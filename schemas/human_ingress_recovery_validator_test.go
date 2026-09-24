// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package schemas

import (
	"strings"
	"testing"
)

func TestHumanIngressRecoveryRouteIsSeparate(t *testing.T) {
	recovery := `{"challenge_id":"` + strings.Repeat("a", 64) + `","operation":"OPERATION_RECOVER","request":{"participant_id":"human:alice","operation_id":"event:1","request_digest":"` + strings.Repeat("b", 64) + `"},"grant_jwt":"grant","session_binding_jwt":"proof"}`
	if err := ValidateHumanIngressRecoverJSON([]byte(recovery)); err != nil {
		t.Fatal(err)
	}
	if err := ValidateHumanIngressJSON([]byte(recovery)); err != nil {
		t.Fatal(err)
	}
	if err := ValidateHumanIngressExecuteJSON([]byte(recovery)); err == nil {
		t.Fatal("recovery accepted as mutation")
	}
	if err := ValidateHumanIngressChallengeJSON([]byte(recovery)); err == nil {
		t.Fatal("proof envelope accepted as challenge")
	}
	for name, mutated := range map[string]string{
		"peer Actor projection": strings.Replace(recovery, `"participant_id":"human:alice"`, `"participant_id":"human:alice","actor_id":"gateway:1"`, 1),
		"duplicate operation":   strings.Replace(recovery, `"operation_id":"event:1"`, `"operation_id":"event:1","operation_id":"event:2"`, 1),
		"unknown mode":          strings.Replace(recovery, "OPERATION_RECOVER", "ASSIGNMENT_TRANSITION", 1),
		"missing digest":        strings.Replace(recovery, `,"request_digest":"`+strings.Repeat("b", 64)+`"`, "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateHumanIngressRecoverJSON([]byte(mutated)); err == nil {
				t.Fatal("invalid recovery accepted")
			}
		})
	}
}
