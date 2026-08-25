// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/thinksyncs/agents-secure-binding/pkg/a2asecuritytest"
	"github.com/thinksyncs/agents-secure-binding/schemas"
)

const acceptedReason = "accepted"

type testRunReporter struct {
	report      a2asecuritytest.Report
	opts        options
	format      string
	path        string
	out         outputWriter
	hasFailure  bool
	outputError error
	finished    bool
}

func newTestRunReporter(opts options, out outputWriter) (*testRunReporter, error) {
	runID, err := randomID("run-")
	if err != nil {
		return nil, err
	}
	attestationMode := strings.ToLower(opts.attestationMode)
	if attestationMode == "" {
		attestationMode = modeSimulation
	}
	attestationPlatform := strings.ToLower(opts.attestationPlatform)
	if attestationMode == modeSimulation {
		attestationPlatform = platformSimulated
	} else if attestationPlatform == "" {
		attestationPlatform = platformAuto
	}
	profile := "direct-agent-v1"
	if opts.bindingProfile == bindingProfileDraft06V2 {
		profile = bindingProfileDraft06V2
	}
	if effectiveWorkflow(opts.workflow) == workflowLLMConversation {
		profile += "+llm-conversation-v1"
	}
	mode := a2asecuritytest.ModeSelfTest
	if opts.deploymentConfig != "" {
		mode = a2asecuritytest.ModeTarget
	}
	return &testRunReporter{
		report: a2asecuritytest.Report{
			Schema:  a2asecuritytest.ReportSchemaV1,
			Tool:    a2asecuritytest.Tool{Name: "asb-a2a-test", Version: version, Commit: commit},
			RunID:   runID,
			Profile: profile,
			Mode:    mode,
			Attestation: a2asecuritytest.Attestation{
				Mode: attestationMode, Platform: attestationPlatform,
			},
			StartedAt: time.Now().UTC(),
		},
		opts:   opts,
		format: opts.reportFormat,
		path:   opts.reportFile,
		out:    out,
	}, nil
}

func (r *testRunReporter) printConversationHeader(attestationMode string) {
	if r.format != reportFormatText {
		return
	}
	r.writeTextf("ASB A2A LLM Conversation: %s\n", r.report.Profile)
	r.writeTextf("processes: Manager, Attester (%s), Verifier, durable Replay Store, Agent B, Agent A\n", attestationMode)
	r.writeTextf("Agent A text is bound before delivery; Agent B is called only after acceptance\n\n")
}

func (r *testRunReporter) printHeader(attestationMode string) {
	if r.format != reportFormatText {
		return
	}
	r.writeTextf("ASB A2A Security Test Kit: %s\n", r.report.Profile)
	r.writeTextf("processes: Manager, Attester (%s), Verifier, durable Replay Store, Agent B, Agent A\n", attestationMode)
	r.writeTextf("transport: TLS 1.3 mutual authentication; application: A2A HTTP+JSON Send Message subset\n\n")
}

func (r *testRunReporter) record(id, name, risk string, result a2aResult, expectedStatus int, expectedReason string) error {
	expected := reportDecision(expectedStatus, expectedReason)
	observed := reportDecision(result.status, result.reason)
	status := a2asecuritytest.StatusPass
	if expected != observed {
		status = a2asecuritytest.StatusFail
		r.hasFailure = true
	}
	r.report.Scenarios = append(r.report.Scenarios, a2asecuritytest.Scenario{
		ID: id, Name: name, Risk: risk,
		Expected: expected, Observed: observed, Status: status,
	})
	if r.format == reportFormatText {
		r.writeTextf("[%s] %-24s %-5s status=%d risk=%s", status, name, expected.Decision, result.status, risk)
		if result.reason != "" {
			r.writeTextf(" reason=%s", result.reason)
		}
		r.writeTextf("\n")
	}
	if status == a2asecuritytest.StatusFail {
		return fmt.Errorf("scenario %q: status=%d reason=%q, want status=%d reason=%q", name, result.status, result.reason, expectedStatus, expectedReason)
	}
	return nil
}

func (r *testRunReporter) recordInfrastructureError() {
	if r.hasFailure {
		return
	}
	r.report.Scenarios = append(r.report.Scenarios, a2asecuritytest.Scenario{
		ID:   "ASB-A2A-INFRA-001",
		Name: "Test run completed",
		Risk: "The target did not produce a complete test decision",
		Expected: a2asecuritytest.Decision{
			Decision: a2asecuritytest.DecisionAllow, HTTPStatus: 200, Reason: "completed",
		},
		Observed: a2asecuritytest.Decision{
			Decision: a2asecuritytest.DecisionBlock, HTTPStatus: 0, Reason: "infrastructure-error",
		},
		Status: a2asecuritytest.StatusError,
	})
	r.hasFailure = true
}

func (r *testRunReporter) finish() error {
	if r.finished {
		return nil
	}
	r.finished = true
	r.report.FinishedAt = time.Now().UTC()
	r.report.Summary, r.report.Status = a2asecuritytest.Summarize(r.report.Scenarios)
	payload, err := marshalReport(r.report)
	if err != nil {
		return err
	}
	if r.path != "" {
		if err := writeReportAtomically(r.path, payload); err != nil {
			return err
		}
	}
	if r.opts.deploymentEvidence != "" {
		if err := writeMultiHostRunEvidence(r.opts, payload, r.report); err != nil {
			return err
		}
	}
	if r.format == reportFormatJSON {
		if _, err := r.out.Write(payload); err != nil {
			return fmt.Errorf("write JSON report: %w", err)
		}
	} else {
		r.writeTextf("\nsummary: %d/%d expected decisions observed\n", r.report.Summary.Passed, r.report.Summary.Total)
		r.writeTextf("report contains decisions only; grants, bindings, evidence, and private keys were not logged\n")
	}
	return r.outputError
}

func reportDecision(status int, reason string) a2asecuritytest.Decision {
	decision := a2asecuritytest.DecisionAllow
	if status >= 400 || status == 0 {
		decision = a2asecuritytest.DecisionBlock
	}
	if reason == "" {
		reason = acceptedReason
	}
	return a2asecuritytest.Decision{Decision: decision, HTTPStatus: status, Reason: reason}
}

func marshalReport(report a2asecuritytest.Report) ([]byte, error) {
	if err := report.Validate(); err != nil {
		return nil, fmt.Errorf("validate A2A security test report: %w", err)
	}
	payload, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode A2A security test report: %w", err)
	}
	payload = append(payload, '\n')
	if err := schemas.ValidateA2ASecurityTestReportJSON(payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func writeReportAtomically(path string, payload []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".asb-a2a-report-*")
	if err != nil {
		return fmt.Errorf("create A2A security test report: %w", err)
	}
	temporaryName := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("protect A2A security test report: %w", err)
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write A2A security test report: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync A2A security test report: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close A2A security test report: %w", err)
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("commit A2A security test report: %w", err)
	}
	removeTemporary = false
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open A2A security test report directory: %w", err)
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return fmt.Errorf("sync A2A security test report directory: %w", err)
	}
	return nil
}

func (r *testRunReporter) writeTextf(format string, values ...any) {
	if r.outputError != nil {
		return
	}
	_, r.outputError = fmt.Fprintf(r.out, format, values...)
}
