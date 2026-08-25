// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package a2asecuritytest

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

var ErrInvalidReport = errors.New("a2a security test: invalid report")

const (
	maxIDLength      = 256
	maxNameLength    = 256
	maxVersionLength = 64
	maxReasonLength  = 256
	maxRiskLength    = 256
)

// Validate checks the report shape and every invariant that JSON Schema cannot
// express, including scenario status, summary counts, and overall status.
func (r Report) Validate() error {
	if r.Schema != ReportSchemaV1 {
		return invalidReport("unsupported schema")
	}
	if err := validateText("tool.name", r.Tool.Name, maxNameLength); err != nil {
		return invalidReportError(err)
	}
	if err := validateText("tool.version", r.Tool.Version, maxVersionLength); err != nil {
		return invalidReportError(err)
	}
	if err := validateText("tool.commit", r.Tool.Commit, maxVersionLength); err != nil {
		return invalidReportError(err)
	}
	if err := validateText("run_id", r.RunID, maxIDLength); err != nil {
		return invalidReportError(err)
	}
	if err := validateText("profile", r.Profile, maxIDLength); err != nil {
		return invalidReportError(err)
	}
	if r.Mode != ModeSelfTest && r.Mode != ModeTarget {
		return invalidReport("unsupported mode")
	}
	if err := validateText("attestation.mode", r.Attestation.Mode, maxVersionLength); err != nil {
		return invalidReportError(err)
	}
	if err := validateText("attestation.platform", r.Attestation.Platform, maxVersionLength); err != nil {
		return invalidReportError(err)
	}
	if r.StartedAt.IsZero() || r.FinishedAt.IsZero() || r.FinishedAt.Before(r.StartedAt) {
		return invalidReport("invalid report timestamps")
	}
	if len(r.Scenarios) == 0 || len(r.Scenarios) > MaxScenarios {
		return invalidReport(fmt.Sprintf("scenarios must contain between 1 and %d items", MaxScenarios))
	}

	seen := make(map[string]struct{}, len(r.Scenarios))
	for i, scenario := range r.Scenarios {
		if err := scenario.validate(); err != nil {
			return invalidReport(fmt.Sprintf("scenarios[%d]: %v", i, err))
		}
		if _, ok := seen[scenario.ID]; ok {
			return invalidReport(fmt.Sprintf("duplicate scenario id %q", scenario.ID))
		}
		seen[scenario.ID] = struct{}{}
	}

	wantSummary, wantStatus := Summarize(r.Scenarios)
	if r.Summary != wantSummary {
		return invalidReport("summary does not match scenarios")
	}
	if r.Status != wantStatus {
		return invalidReport("status does not match scenarios")
	}
	return nil
}

// Summarize derives the only valid summary and overall status for scenarios.
// ERROR takes precedence over FAIL, which takes precedence over INDETERMINATE.
func Summarize(scenarios []Scenario) (Summary, Status) {
	var summary Summary
	for _, scenario := range scenarios {
		summary.Total++
		switch scenario.Status {
		case StatusPass:
			summary.Passed++
		case StatusFail:
			summary.Failed++
		case StatusIndeterminate:
			summary.Indeterminate++
		case StatusError:
			summary.Errors++
		}
	}
	switch {
	case summary.Errors > 0:
		return summary, StatusError
	case summary.Failed > 0:
		return summary, StatusFail
	case summary.Indeterminate > 0:
		return summary, StatusIndeterminate
	default:
		return summary, StatusPass
	}
}

func (s Scenario) validate() error {
	if err := validateText("id", s.ID, maxIDLength); err != nil {
		return err
	}
	if err := validateText("name", s.Name, maxNameLength); err != nil {
		return err
	}
	if err := validateText("risk", s.Risk, maxRiskLength); err != nil {
		return err
	}
	if err := s.Expected.validate("expected", false); err != nil {
		return err
	}
	if err := s.Observed.validate("observed", true); err != nil {
		return err
	}
	if !validStatus(s.Status) {
		return fmt.Errorf("unsupported status")
	}
	match := s.Expected == s.Observed
	switch s.Status {
	case StatusPass:
		if !match {
			return fmt.Errorf("PASS requires observed result to match expected result")
		}
	case StatusFail:
		if match {
			return fmt.Errorf("FAIL requires observed result to differ from expected result")
		}
	}
	if s.Observed.HTTPStatus == 0 && (s.Status == StatusPass || s.Status == StatusFail) {
		return fmt.Errorf("no HTTP response requires INDETERMINATE or ERROR")
	}
	return nil
}

func (d Decision) validate(field string, allowNoResponse bool) error {
	if d.Decision != DecisionAllow && d.Decision != DecisionBlock {
		return fmt.Errorf("%s.decision must be ALLOW or BLOCK", field)
	}
	if err := validateText(field+".reason", d.Reason, maxReasonLength); err != nil {
		return err
	}
	if d.HTTPStatus == 0 && allowNoResponse {
		return nil
	}
	if d.HTTPStatus < 100 || d.HTTPStatus > 599 {
		return fmt.Errorf("%s.http_status must be between 100 and 599", field)
	}
	return nil
}

func validStatus(status Status) bool {
	switch status {
	case StatusPass, StatusFail, StatusIndeterminate, StatusError:
		return true
	default:
		return false
	}
}

func validateText(field, value string, maxLength int) error {
	if value == "" || strings.TrimSpace(value) != value {
		return fmt.Errorf("%s is required and must not have surrounding whitespace", field)
	}
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > maxLength {
		return fmt.Errorf("%s must be valid UTF-8 and at most %d characters", field, maxLength)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("%s must not contain control characters", field)
		}
	}
	return nil
}

func invalidReport(detail string) error {
	return fmt.Errorf("%w: %s", ErrInvalidReport, detail)
}

func invalidReportError(err error) error {
	return fmt.Errorf("%w: %v", ErrInvalidReport, err)
}
