// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package schemas

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/thinksyncs/agents-secure-binding/pkg/a2asecuritytest"
)

func TestA2ASecurityTestReportSchemaAcceptsReport(t *testing.T) {
	t.Parallel()
	startedAt := time.Date(2026, 8, 24, 9, 0, 0, 0, time.UTC)
	scenarios := []a2asecuritytest.Scenario{{
		ID: "replay", Name: "Replay", Risk: "A reused interaction is accepted",
		Expected: a2asecuritytest.Decision{Decision: a2asecuritytest.DecisionBlock, HTTPStatus: 409, Reason: "REPLAY_DETECTED"},
		Observed: a2asecuritytest.Decision{Decision: a2asecuritytest.DecisionBlock, HTTPStatus: 409, Reason: "REPLAY_DETECTED"},
		Status:   a2asecuritytest.StatusPass,
	}}
	summary, status := a2asecuritytest.Summarize(scenarios)
	report := a2asecuritytest.Report{
		Schema: a2asecuritytest.ReportSchemaV1,
		Tool:   a2asecuritytest.Tool{Name: "asb-a2a-security-test", Version: "1.0.0", Commit: "abc123"},
		RunID:  "run-1", Profile: "asb-a2a-v1", Mode: a2asecuritytest.ModeTarget,
		Attestation: a2asecuritytest.Attestation{Mode: "external", Platform: "external"},
		StartedAt:   startedAt, FinishedAt: startedAt.Add(time.Second),
		Status: status, Summary: summary, Scenarios: scenarios,
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateA2ASecurityTestReportJSON(raw); err != nil {
		t.Fatalf("valid report rejected: %v", err)
	}
}

func TestA2ASecurityTestReportSchemaRejectsSensitiveAndUnknownFields(t *testing.T) {
	t.Parallel()
	base := `{
		"schema":"urn:asb:a2a-security-test-report:v1",
		"tool":{"name":"asb-a2a-security-test","version":"1.0.0","commit":"abc123"},
		"run_id":"run-1",
		"profile":"asb-a2a-v1",
		"mode":"selftest",
		"attestation":{"mode":"simulation","platform":"simulated"},
		"started_at":"2026-08-24T09:00:00Z",
		"finished_at":"2026-08-24T09:00:01Z",
		"status":"PASS",
		"summary":{"total":1,"passed":1,"failed":0,"indeterminate":0,"errors":0},
		"scenarios":[{
			"id":"baseline","name":"Baseline","risk":"A valid interaction is rejected",
			"expected":{"decision":"ALLOW","http_status":200,"reason":"ACCEPTED"},
			"observed":{"decision":"ALLOW","http_status":200,"reason":"ACCEPTED"},
			"status":"PASS"
		}]
	}`
	tests := []string{
		strings.Replace(base, `"run_id":`, `"token":"secret","run_id":`, 1),
		strings.Replace(base, `"status":"PASS"`, `"status":"UNKNOWN"`, 1),
		strings.Replace(base, `"observed":{`, `"proof":"secret","observed":{`, 1),
		strings.Replace(base, `"reason":"ACCEPTED"`, `"reason":"ACCEPTED","nonce":"secret"`, 1),
		strings.Replace(base, `"reason":"ACCEPTED"`, `"reason":"ACCEPTED","private_key":"secret"`, 1),
		strings.Replace(base, `"http_status":200`, `"http_status":0`, 1),
	}
	for _, document := range tests {
		if err := ValidateA2ASecurityTestReportJSON([]byte(document)); err == nil {
			t.Fatalf("invalid report accepted: %s", document)
		}
	}
}

func TestA2ASecurityTestReportSchemaRejectsAmbiguousJSON(t *testing.T) {
	t.Parallel()
	base := `{
		"schema":"urn:asb:a2a-security-test-report:v1",
		"tool":{"name":"asb-a2a-security-test","version":"1.0.0","commit":"abc123"},
		"run_id":"run-1",
		"profile":"asb-a2a-v1",
		"mode":"selftest",
		"attestation":{"mode":"simulation","platform":"simulated"},
		"started_at":"2026-08-24T09:00:00Z",
		"finished_at":"2026-08-24T09:00:01Z",
		"status":"PASS",
		"summary":{"total":1,"passed":1,"failed":0,"indeterminate":0,"errors":0},
		"scenarios":[{
			"id":"baseline","name":"Baseline","risk":"A valid interaction is rejected",
			"expected":{"decision":"ALLOW","http_status":200,"reason":"ACCEPTED"},
			"observed":{"decision":"ALLOW","http_status":200,"reason":"ACCEPTED"},
			"status":"PASS"
		}]
	}`
	tests := map[string]string{
		"duplicate top level": strings.Replace(base, `"status":"PASS"`, `"status":"FAIL","status":"PASS"`, 1),
		"duplicate nested":    strings.Replace(base, `"passed":1`, `"passed":0,"passed":1`, 1),
		"escaped duplicate":   strings.Replace(base, `"status":"PASS"`, `"status":"FAIL","st\u0061tus":"PASS"`, 1),
		"valid then invalid":  strings.Replace(base, `"http_status":200`, `"http_status":200,"http_status":0`, 1),
		"trailing value":      base + `{}`,
	}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			if err := ValidateA2ASecurityTestReportJSON([]byte(document)); err == nil {
				t.Fatalf("ambiguous report accepted: %s", document)
			}
		})
	}
	if err := ValidateA2ASecurityTestReportJSON([]byte{'{', '"', 0xff, '"', ':', '1', '}'}); err == nil {
		t.Fatal("invalid UTF-8 report accepted")
	}
}
