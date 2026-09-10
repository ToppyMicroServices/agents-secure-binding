// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDebugSimpleCLIWritesEvidenceReport(t *testing.T) {
	t.Parallel()
	reportPath := filepath.Join(t.TempDir(), "nested", "human-coordination-report.json")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := runCLI(
		[]string{"--debug-simple", "--report", reportPath},
		&stdout,
		&stderr,
	); code != 0 {
		t.Fatalf("runCLI() code = %d, stderr = %s", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("runCLI() stderr = %q", stderr.String())
	}
	if got := stdout.String(); got != "debug-simple evidence report written\n" {
		t.Fatalf("runCLI() stdout = %q", got)
	}
	raw, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var report evidenceReport
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if !report.Success || report.Mode != "debug-simple" || report.Schema != reportSchema || report.Version != reportVersion {
		t.Fatalf("unexpected report header: %+v", report)
	}
	wantStates := []string{
		"ACTIVE",
		"OFFERED",
		"ACCEPTED",
		"QUESTION",
		"ACTIVE",
		"QUEUED",
		"PROVIDER_ACKNOWLEDGED",
		"RESPONSE",
		"ACCEPTED",
		"NOT_ELIGIBLE",
		"RUNNING",
		"WAITING",
		"RUNNING",
		"SUCCEEDED",
		"ELIGIBLE",
		"FULFILLED",
	}
	if len(report.Checks) != len(wantStates) {
		t.Fatalf("check count = %d, want %d", len(report.Checks), len(wantStates))
	}
	for index, want := range wantStates {
		if report.Checks[index].Sequence != index+1 || report.Checks[index].State != want {
			t.Fatalf("check %d = %+v, want state %s", index, report.Checks[index], want)
		}
	}
}

func TestCLIRequiresExplicitDebugSimpleAndReportPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "missing debug flag",
			args: []string{"--report", filepath.Join(t.TempDir(), "must-not-exist.json")},
		},
		{
			name: "missing report path",
			args: []string{"--debug-simple"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			if code := runCLI(test.args, &stdout, &stderr); code != 2 {
				t.Fatalf("runCLI() code = %d, want 2", code)
			}
			if stdout.Len() != 0 {
				t.Fatalf("runCLI() stdout = %q", stdout.String())
			}
			message := stderr.String()
			for _, required := range []string{"--debug-simple", "--report <path>", "non-production"} {
				if !strings.Contains(message, required) {
					t.Fatalf("runCLI() stderr does not contain %q: %s", required, message)
				}
			}
			if test.name == "missing debug flag" {
				if _, err := os.Stat(test.args[1]); !os.IsNotExist(err) {
					t.Fatalf("report was written without --debug-simple: %v", err)
				}
			}
		})
	}
}

func TestEvidenceReportIsDeterministic(t *testing.T) {
	t.Parallel()
	first, err := runScenario(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := runScenario(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	firstRaw, err := marshalEvidenceReport(first)
	if err != nil {
		t.Fatal(err)
	}
	secondRaw, err := marshalEvidenceReport(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstRaw, secondRaw) {
		t.Fatalf("reports differ:\nfirst:\n%s\nsecond:\n%s", firstRaw, secondRaw)
	}
}

func TestEvidenceReportHasNoHardwareOrProductionClaim(t *testing.T) {
	t.Parallel()
	report, err := runScenario(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.ProductionClaim || !report.Runtime.SoftwareOnly || !report.Runtime.InProcess ||
		report.Runtime.NetworkCalls || report.Runtime.LiveTLS || report.Runtime.HardwareAttestation ||
		report.Runtime.ExternalProvider {
		t.Fatalf("unexpected runtime assurance: %+v", report.Runtime)
	}
	if report.Participants.Human == report.Actors.HumanGateway {
		t.Fatal("Human Participant and Human gateway Actor are not distinct")
	}
	labels := strings.Join(report.Labels, ",")
	for _, required := range []string{"simulated", "software-only", "no-network", "no-hardware-attestation"} {
		if !strings.Contains(labels, required) {
			t.Fatalf("labels do not contain %q: %s", required, labels)
		}
	}
	wantBoundaries := []boundaryEvidence{
		{ID: "human-taskcoord", Classification: "external-asb", ProfileID: "asb.taskcoord-human-request/v1", AssuranceLevel: "gateway-asserted-for-human", EvidenceSource: "signed-simulated-asb"},
		{ID: "agent-relay-authorization", Classification: "external-asb", ProfileID: "asb.taskcoord-agent-relay/v1", EvidenceSource: "signed-simulated-asb"},
		{ID: "agent-taskcoord", Classification: "trusted-internal", EvidenceSource: "fixture-projection"},
		{ID: "action-acceptance", Classification: "trusted-internal", EvidenceSource: "fixture-projection"},
		{ID: "action-mutation", Classification: "trusted-internal", EvidenceSource: "fixture-projection"},
		{ID: "human-matching", Classification: "trusted-internal", EvidenceSource: "fixture-projection"},
		{ID: "reachability-administration", Classification: "trusted-internal", EvidenceSource: "fixture-projection"},
		{ID: "relay-queue", Classification: "trusted-internal", EvidenceSource: "asb-derived-projection"},
		{ID: "relay-dispatch", Classification: "trusted-internal", EvidenceSource: "trusted-worker"},
	}
	if len(report.Boundaries) != len(wantBoundaries) {
		t.Fatalf("boundaries = %#v, want %#v", report.Boundaries, wantBoundaries)
	}
	for index, want := range wantBoundaries {
		if report.Boundaries[index] != want {
			t.Fatalf("boundary %d = %#v, want %#v", index, report.Boundaries[index], want)
		}
	}
	wantLimitations := []string{
		"MemoryStores and LocalGatewaySink are in-process reference implementations.",
		"Human TaskCoord and Agent relay operations use signed simulated ASB evidence.",
		"Human TaskCoord evidence is gateway-asserted-for-human; it is not authenticated-Human, Human-held-key, liveness, UI-confirmation, or legal-consent evidence.",
		"No live TLS, hardware attestation, or external provider is used.",
		"Agent TaskCoord, Action acceptance and mutation, Human matching, and reachability administration are explicitly trusted-internal fixture boundaries without external ASB profiles.",
		"TaskCoord and Task-Action use separate reference stores; eligibility and fulfillment are not one durable transaction.",
	}
	if len(report.Limitations) != len(wantLimitations) {
		t.Fatalf("limitations = %#v, want %#v", report.Limitations, wantLimitations)
	}
	for index, want := range wantLimitations {
		if report.Limitations[index] != want {
			t.Fatalf("limitation %d = %q, want %q", index, report.Limitations[index], want)
		}
	}
	raw, err := marshalEvidenceReport(report)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(raw))
	for _, forbidden := range []string{
		`"production_claim": true`,
		`"hardware_attestation": true`,
		`"live_tls": true`,
		`"external_provider": true`,
		"production-ready",
		"hardware-qualified",
		"mailto:",
		"tel:",
		"contact_request_ref",
		"relay_session_ref",
		strings.ToLower(debugManagerKey),
		strings.ToLower(debugActorKey),
		"eyjhb",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("report contains forbidden material %q", forbidden)
		}
	}
}
