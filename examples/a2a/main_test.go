// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunDemo(t *testing.T) {
	var out bytes.Buffer
	if err := runDemo(&out); err != nil {
		t.Fatalf("runDemo() error = %v\noutput:\n%s", err, out.String())
	}

	for _, expected := range []string{
		"allowed task         ALLOW status=200",
		"scope escalation     BLOCK status=403 risk=privilege_escalation reason=policy_mismatch",
		"resource substitution BLOCK status=403 risk=data_exfiltration reason=message_policy_mismatch",
		"wrong audience       BLOCK status=403 risk=cross_audience_confusion reason=audience_mismatch",
		"borrowed session     BLOCK status=403 risk=session_borrowing reason=session_binding_mismatch",
		"replay first use     ALLOW status=200",
		"replayed request     BLOCK status=403 risk=replay reason=replay_detected",
		"summary: 7/7 expected decisions observed",
	} {
		if !strings.Contains(out.String(), expected) {
			t.Fatalf("runDemo() output missing %q\noutput:\n%s", expected, out.String())
		}
	}
}
