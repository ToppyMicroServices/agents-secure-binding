// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package a2asecuritytest

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestReportValidateAndDecode(t *testing.T) {
	t.Parallel()
	report := validReport()
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeReport(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("valid report rejected: %v", err)
	}
	if decoded.RunID != report.RunID || decoded.Summary != report.Summary {
		t.Fatalf("decoded report differs: %#v", decoded)
	}
}

func TestSummarizeIsDeterministic(t *testing.T) {
	t.Parallel()
	scenarios := []Scenario{
		{Status: StatusPass},
		{Status: StatusFail},
		{Status: StatusIndeterminate},
		{Status: StatusError},
	}
	summary, status := Summarize(scenarios)
	want := Summary{Total: 4, Passed: 1, Failed: 1, Indeterminate: 1, Errors: 1}
	if summary != want || status != StatusError {
		t.Fatalf("got (%#v, %q), want (%#v, %q)", summary, status, want, StatusError)
	}

	precedence := []struct {
		statuses []Status
		want     Status
	}{
		{statuses: []Status{StatusPass}, want: StatusPass},
		{statuses: []Status{StatusPass, StatusIndeterminate}, want: StatusIndeterminate},
		{statuses: []Status{StatusIndeterminate, StatusFail}, want: StatusFail},
		{statuses: []Status{StatusFail, StatusError}, want: StatusError},
	}
	for _, test := range precedence {
		items := make([]Scenario, len(test.statuses))
		for i, itemStatus := range test.statuses {
			items[i].Status = itemStatus
		}
		_, got := Summarize(items)
		if got != test.want {
			t.Fatalf("Summarize(%v) status = %q, want %q", test.statuses, got, test.want)
		}
	}
}

func TestReportRejectsInconsistentResults(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*Report){
		"unsupported schema":  func(report *Report) { report.Schema = "v2" },
		"unsupported mode":    func(report *Report) { report.Mode = "peer" },
		"missing tool commit": func(report *Report) { report.Tool.Commit = "" },
		"missing attestation": func(report *Report) { report.Attestation.Mode = "" },
		"reversed timestamps": func(report *Report) { report.FinishedAt = report.StartedAt.Add(-time.Second) },
		"duplicate scenario id": func(report *Report) {
			report.Scenarios = append(report.Scenarios, report.Scenarios[0])
			report.Summary, report.Status = Summarize(report.Scenarios)
		},
		"wrong summary":        func(report *Report) { report.Summary.Passed = 0 },
		"wrong overall status": func(report *Report) { report.Status = StatusFail },
		"PASS mismatch":        func(report *Report) { report.Scenarios[0].Observed.Reason = "POLICY_MISMATCH" },
		"unsupported decision": func(report *Report) { report.Scenarios[0].Observed.Decision = "ACCEPT" },
		"FAIL match": func(report *Report) {
			report.Scenarios[0].Status = StatusFail
			report.Summary, report.Status = Summarize(report.Scenarios)
		},
		"missing expected HTTP status": func(report *Report) { report.Scenarios[0].Expected.HTTPStatus = 0 },
		"no response marked PASS": func(report *Report) {
			report.Scenarios[0].Expected.HTTPStatus = 0
			report.Scenarios[0].Observed.HTTPStatus = 0
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			report := validReport()
			mutate(&report)
			if err := report.Validate(); !errors.Is(err, ErrInvalidReport) {
				t.Fatalf("got %v, want ErrInvalidReport", err)
			}
		})
	}
}

func TestDecodeReportRejectsUnsafeJSON(t *testing.T) {
	t.Parallel()
	validRaw, err := json.Marshal(validReport())
	if err != nil {
		t.Fatal(err)
	}
	unknown := strings.Replace(string(validRaw), `"run_id":`, `"access_token":"secret","run_id":`, 1)
	duplicate := strings.Replace(string(validRaw), `"run_id":`, `"run_id":"duplicate","run_id":`, 1)
	nestedDuplicate := strings.Replace(string(validRaw), `"decision":"ALLOW",`, `"decision":"BLOCK","decision":"ALLOW",`, 1)
	caseAlias := strings.Replace(string(validRaw), `"status":`, `"STATUS":`, 1)
	caseDuplicate := strings.Replace(string(validRaw), `"status":"PASS"`, `"status":"PASS","STATUS":"PASS"`, 1)

	tests := map[string]struct {
		reader *bytes.Reader
	}{
		"unknown sensitive field": {reader: bytes.NewReader([]byte(unknown))},
		"duplicate member":        {reader: bytes.NewReader([]byte(duplicate))},
		"nested duplicate member": {reader: bytes.NewReader([]byte(nestedDuplicate))},
		"case-folded alias":       {reader: bytes.NewReader([]byte(caseAlias))},
		"case-folded duplicate":   {reader: bytes.NewReader([]byte(caseDuplicate))},
		"trailing value":          {reader: bytes.NewReader(append(validRaw, []byte(` {}`)...))},
		"invalid UTF-8":           {reader: bytes.NewReader([]byte{'{', '"', 0xff, '"', '}', '\n'})},
		"oversized":               {reader: bytes.NewReader(bytes.Repeat([]byte{' '}, MaxReportBytes+1))},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeReport(test.reader); !errors.Is(err, ErrInvalidReport) {
				t.Fatalf("got %v, want ErrInvalidReport", err)
			}
		})
	}
	if _, err := DecodeReport(nil); !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("nil input: got %v, want ErrInvalidReport", err)
	}
}

func validReport() Report {
	startedAt := time.Date(2026, 8, 24, 9, 0, 0, 0, time.UTC)
	scenario := Scenario{
		ID:   "positive-baseline",
		Name: "Positive baseline",
		Risk: "Rejecting a valid bound interaction",
		Expected: Decision{
			Decision: DecisionAllow, HTTPStatus: 200, Reason: "ACCEPTED",
		},
		Observed: Decision{
			Decision: DecisionAllow, HTTPStatus: 200, Reason: "ACCEPTED",
		},
		Status: StatusPass,
	}
	scenarios := []Scenario{scenario}
	summary, status := Summarize(scenarios)
	return Report{
		Schema: ReportSchemaV1,
		Tool:   Tool{Name: "asb-a2a-security-test", Version: "1.0.0", Commit: "abc123"},
		RunID:  "run-20260824-001", Profile: "asb-a2a-v1", Mode: ModeSelfTest,
		Attestation: Attestation{Mode: "simulation", Platform: "simulated"},
		StartedAt:   startedAt, FinishedAt: startedAt.Add(time.Second),
		Status: status, Summary: summary, Scenarios: scenarios,
	}
}
