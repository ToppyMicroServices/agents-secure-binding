// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Package a2asecuritytest defines the versioned, machine-readable result of an
// A2A Security Test Kit run. Reports contain decisions and reason codes only;
// request bodies, response bodies, credentials, proofs, keys, and nonces are
// deliberately outside this model.
package a2asecuritytest

import "time"

const (
	// ReportSchemaV1 identifies the first report format.
	ReportSchemaV1 = "urn:asb:a2a-security-test-report:v1"
	// MaxReportBytes bounds strict report decoding to one MiB.
	MaxReportBytes = 1 << 20
	// MaxScenarios bounds work performed while validating one report.
	MaxScenarios = 1024
)

// Mode identifies whether the kit tested its bundled reference pair or an
// external target.
type Mode string

const (
	ModeSelfTest Mode = "selftest"
	ModeTarget   Mode = "target"
)

// Status is the result of a scenario or complete run.
type Status string

const (
	StatusPass          Status = "PASS"
	StatusFail          Status = "FAIL"
	StatusIndeterminate Status = "INDETERMINATE"
	StatusError         Status = "ERROR"
)

// Tool identifies the implementation that produced a report.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// Attestation identifies the requested evidence path for the run. Platform may
// be "auto" when hardware discovery selected the concrete platform at runtime.
type Attestation struct {
	Mode     string `json:"mode"`
	Platform string `json:"platform"`
}

// DecisionValue is the target's security decision.
type DecisionValue string

const (
	DecisionAllow DecisionValue = "ALLOW"
	DecisionBlock DecisionValue = "BLOCK"
)

// Decision is the bounded, non-sensitive result of one endpoint interaction.
// Reason is a reason code, not a raw response or diagnostic dump. HTTPStatus is
// zero only when the target produced no HTTP response.
type Decision struct {
	Decision   DecisionValue `json:"decision"`
	HTTPStatus int           `json:"http_status"`
	Reason     string        `json:"reason"`
}

// Scenario records one expected and observed interaction result.
type Scenario struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Risk     string   `json:"risk"`
	Expected Decision `json:"expected"`
	Observed Decision `json:"observed"`
	Status   Status   `json:"status"`
}

// Summary contains deterministic counts derived from Scenarios.
type Summary struct {
	Total         uint32 `json:"total"`
	Passed        uint32 `json:"passed"`
	Failed        uint32 `json:"failed"`
	Indeterminate uint32 `json:"indeterminate"`
	Errors        uint32 `json:"errors"`
}

// Report is the versioned v1 output of one test run.
type Report struct {
	Schema      string      `json:"schema"`
	Tool        Tool        `json:"tool"`
	RunID       string      `json:"run_id"`
	Profile     string      `json:"profile"`
	Mode        Mode        `json:"mode"`
	Attestation Attestation `json:"attestation"`
	StartedAt   time.Time   `json:"started_at"`
	FinishedAt  time.Time   `json:"finished_at"`
	Status      Status      `json:"status"`
	Summary     Summary     `json:"summary"`
	Scenarios   []Scenario  `json:"scenarios"`
}
