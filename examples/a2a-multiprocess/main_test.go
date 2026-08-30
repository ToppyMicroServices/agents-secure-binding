// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/a2asecuritytest"
	"gopkg.in/yaml.v3"
)

func TestDurableReplayStoreSurvivesRestartWithoutRawKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), replayStateFile)
	store, err := openDurableReplayStore(path)
	if err != nil {
		t.Fatal(err)
	}
	const rawKey = "binding-id|secret-nonce"
	inserted, err := store.SetNX(context.Background(), rawKey, time.Minute)
	if err != nil || !inserted {
		t.Fatalf("first SetNX() = %v, %v; want true, nil", inserted, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(rawKey)) {
		t.Fatal("durable replay state contains the raw replay key")
	}
	restarted, err := openDurableReplayStore(path)
	if err != nil {
		t.Fatal(err)
	}
	inserted, err = restarted.SetNX(context.Background(), rawKey, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if inserted {
		t.Fatal("restarted replay store accepted a consumed key")
	}
}

func TestDurableReplayStoreFailsClosedOnMalformedState(t *testing.T) {
	path := filepath.Join(t.TempDir(), replayStateFile)
	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openDurableReplayStore(path); err == nil {
		t.Fatal("openDurableReplayStore() error = nil, want malformed-state rejection")
	}
}

func TestSimulationEvidenceIsExplicitAndSessionBound(t *testing.T) {
	stateDir := t.TempDir()
	if err := bootstrapState(stateDir); err != nil {
		t.Fatal(err)
	}
	binder := []byte("test-live-session-binder")
	reportData := sha512.Sum512(binder)
	evidence, err := collectEvidence(modeSimulation, platformAuto, filepath.Join(roleDirectory(stateDir, "attester"), signingKeyFile), reportData[:])
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := loadPublicKey(filepath.Join(roleDirectory(stateDir, "verifier"), simPublicFile))
	if err != nil {
		t.Fatal(err)
	}
	claims, err := appraiseEvidence(context.Background(), evidence, binder, "", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !claims.Simulation || claims.Platform != platformSimulated || claims.BinderSHA256 != sha256String(binder) {
		t.Fatalf("simulation claims = %+v", claims)
	}

	tampered, err := tamperCompactJWT(evidence.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	evidence.Evidence = tampered
	if _, err := appraiseEvidence(context.Background(), evidence, binder, "", publicKey); err == nil {
		t.Fatal("appraiseEvidence() accepted tampered simulation evidence")
	}
}

func TestHardwareAppraisalRequiresExactNonzeroMeasurement(t *testing.T) {
	for _, value := range []string{"", "00", strings.Repeat("00", 48)} {
		if _, err := decodeExpectedMeasurement(value); err == nil {
			t.Fatalf("decodeExpectedMeasurement(%q) error = nil", value)
		}
	}
	value := strings.Repeat("01", 48)
	measurement, err := decodeExpectedMeasurement(value)
	if err != nil || len(measurement) != 48 {
		t.Fatalf("decodeExpectedMeasurement(valid) len=%d err=%v", len(measurement), err)
	}
}

func TestCanonicalContextCoversApplicationFieldsButNotExtensionPayloads(t *testing.T) {
	first := newTaskRequest(demoResource)
	first.Message.Metadata = map[string]json.RawMessage{
		securityBindingExtension:   json.RawMessage(`{"first":true}`),
		attestationResultExtension: json.RawMessage(`"token-one"`),
	}
	second := first
	second.Message.Metadata = map[string]json.RawMessage{
		securityBindingExtension:   json.RawMessage(`{"second":true}`),
		attestationResultExtension: json.RawMessage(`"token-two"`),
	}
	firstContext, err := canonicalRequestContext(first)
	if err != nil {
		t.Fatal(err)
	}
	secondContext, err := canonicalRequestContext(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstContext, secondContext) {
		t.Fatal("security extension payloads changed canonical request context")
	}
	second.Message.Parts[0].Metadata["resource"] = demoOtherResource
	changedContext, err := canonicalRequestContext(second)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstContext, changedContext) {
		t.Fatal("application resource did not change canonical request context")
	}
}

func TestComposeFilesAreValidYAML(t *testing.T) {
	for _, name := range []string{"compose.yaml", "compose.hardware.yaml"} {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]any
		if err := yaml.Unmarshal(raw, &document); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if document["services"] == nil {
			t.Fatalf("%s has no services", name)
		}
	}
}

func TestA2AProtocolErrorUsesGoogleStatusEnvelope(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeA2AProtocolError(recorder, http.StatusNotFound, "TASK_NOT_FOUND", "Task not found")
	response := recorder.Result()
	defer response.Body.Close()
	if got := response.Header.Get("Content-Type"); got != a2aMediaType {
		t.Fatalf("Content-Type = %q, want %q", got, a2aMediaType)
	}
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", response.StatusCode)
	}
	var body a2aErrorResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != http.StatusNotFound || body.Error.Status != "NOT_FOUND" || len(body.Error.Details) != 1 {
		t.Fatalf("A2A error = %+v", body.Error)
	}
	detail := body.Error.Details[0]
	if detail.Type != a2aErrorInfoType || detail.Reason != "TASK_NOT_FOUND" || detail.Domain != a2aErrorDomain {
		t.Fatalf("A2A ErrorInfo = %+v", detail)
	}
}

func TestA2APreconditionErrorsUseCanonicalStatus(t *testing.T) {
	for _, reason := range []string{"VERSION_NOT_SUPPORTED", "EXTENSION_SUPPORT_REQUIRED"} {
		if got := a2aStatusName(http.StatusBadRequest, reason); got != "FAILED_PRECONDITION" {
			t.Fatalf("a2aStatusName(400, %q) = %q, want FAILED_PRECONDITION", reason, got)
		}
	}
}

func TestAgentAProcessArgsCarryReportProvenanceInputs(t *testing.T) {
	opts := options{
		attestationMode: modeHardware, attestationPlatform: platformSNP,
		bindingProfile: bindingProfileV1, reportFormat: "json", reportFile: "report.json",
	}
	args := agentAProcessArgs(opts, "state", "manager", "attester", "verifier", "agent-b")
	want := map[string]string{
		"--attestation-mode": modeHardware, "--attestation-platform": platformSNP,
		"--binding-profile": bindingProfileV1, "--format": "json", "--report": "report.json",
	}
	for i := 0; i+1 < len(args); i += 2 {
		if _, ok := want[args[i]]; ok {
			if args[i+1] != want[args[i]] {
				t.Fatalf("%s = %q, want %q", args[i], args[i+1], want[args[i]])
			}
			delete(want, args[i])
		}
	}
	if len(want) != 0 {
		t.Fatalf("Agent A arguments omitted provenance inputs: %v", want)
	}
}

func TestOrchestratorReportsFailureBeforeAgentStarts(t *testing.T) {
	temporaryDirectory := t.TempDir()
	invalidStateDirectory := filepath.Join(temporaryDirectory, "not-a-directory")
	if err := os.WriteFile(invalidStateDirectory, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(temporaryDirectory, "error-report.json")
	var output bytes.Buffer
	err := runOrchestrator(context.Background(), options{
		stateDir: invalidStateDirectory, bindingProfile: bindingProfileV1,
		attestationMode: modeSimulation, attestationPlatform: platformAuto,
		reportFormat: "json", reportFile: reportPath,
	}, &output)
	if err == nil {
		t.Fatal("runOrchestrator() error = nil")
	}
	report := decodeA2ATestReport(t, output.Bytes())
	if report.Status != a2asecuritytest.StatusError || report.Summary.Errors != 1 {
		t.Fatalf("stdout report result = status %q summary %+v", report.Status, report.Summary)
	}
	fileReport, readErr := os.ReadFile(reportPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if decoded := decodeA2ATestReport(t, fileReport); decoded.RunID != report.RunID {
		t.Fatalf("file report run_id = %q, want %q", decoded.RunID, report.RunID)
	}
	if bytes.Contains(output.Bytes(), []byte(invalidStateDirectory)) {
		t.Fatal("machine report contains the internal state path")
	}
}

func TestDebugSimpleRejectsNonOrchestratorBeforeStartup(t *testing.T) {
	if testing.Short() {
		t.Skip("binary startup test disabled in short mode")
	}
	binary := filepath.Join(t.TempDir(), "asb-a2a")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Env = os.Environ()
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build demo: %v\n%s", err, output)
	}

	var stdout, stderr bytes.Buffer
	run := exec.Command(binary, "--debug-simple", "--role", "agent-b", "--listen", "0.0.0.0:0")
	run.Stdout = &stdout
	run.Stderr = &stderr
	if err := run.Run(); err == nil {
		t.Fatalf("debug-simple non-orchestrator run succeeded\nstdout:\n%s\nstderr:\n%s", stdout.Bytes(), stderr.Bytes())
	}
	if stdout.Len() != 0 {
		t.Fatalf("rejected debug-simple run wrote stdout:\n%s", stdout.Bytes())
	}
	if !bytes.Contains(stderr.Bytes(), []byte("--debug-simple requires --role=orchestrator")) {
		t.Fatalf("rejected debug-simple run reported the wrong error:\n%s", stderr.Bytes())
	}
	if bytes.Contains(stderr.Bytes(), []byte(debugSimpleWarning)) || bytes.Contains(stderr.Bytes(), []byte("started ")) {
		t.Fatalf("rejected debug-simple run reached startup or emitted the run warning:\n%s", stderr.Bytes())
	}
}

func TestMultiprocessSimulationEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("multiprocess loopback test disabled in short mode")
	}
	temporaryDirectory := t.TempDir()
	binary := filepath.Join(temporaryDirectory, "asb-a2a")
	reportPath := filepath.Join(temporaryDirectory, "report.json")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Env = os.Environ()
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build demo: %v\n%s", err, output)
	}
	run := exec.Command(binary, "--role", "orchestrator", "--report", reportPath)
	output, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run demo: %v\n%s", err, output)
	}
	for _, expected := range []string{
		"authorized Send Message", "tampered attestation result", "unknown client task",
		"expired session proof", "durable replay",
		"borrowed TLS session", "bound resource substitution", "version downgrade",
		"summary: 8/8 expected decisions observed",
	} {
		if !bytes.Contains(output, []byte(expected)) {
			t.Fatalf("demo output missing %q\n%s", expected, output)
		}
	}

	reportBytes, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	report := decodeA2ATestReport(t, reportBytes)
	if report.Status != a2asecuritytest.StatusPass || report.Summary.Total != 8 || report.Summary.Passed != 8 {
		t.Fatalf("report result = status %q summary %+v", report.Status, report.Summary)
	}
	if report.Tool.Commit == "" || report.Attestation.Mode != modeSimulation || report.Attestation.Platform != platformSimulated {
		t.Fatalf("report provenance = tool %+v attestation %+v", report.Tool, report.Attestation)
	}
	for i, scenario := range report.Scenarios {
		wantID := fmt.Sprintf("ASB-A2A-%03d", i+1)
		if scenario.ID != wantID || scenario.Status != a2asecuritytest.StatusPass {
			t.Fatalf("scenario[%d] = id %q status %q, want %q PASS", i, scenario.ID, scenario.Status, wantID)
		}
	}
	info, err := os.Stat(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("report permissions = %04o, want 0600", got)
	}
	for _, forbidden := range []string{`"grant":`, `"proof":`, `"private_key":`, `"nonce":`, `"tls_exporter":`, `"endpoint":`, `"pid":`, `"request":`, `"response":`} {
		if bytes.Contains(reportBytes, []byte(forbidden)) {
			t.Fatalf("report contains forbidden field %s", forbidden)
		}
	}

	jsonRun := exec.Command(binary, "--debug-simple", "--format", "json")
	var jsonStdout, jsonStderr bytes.Buffer
	jsonRun.Stdout = &jsonStdout
	jsonRun.Stderr = &jsonStderr
	if err := jsonRun.Run(); err != nil {
		t.Fatalf("run JSON report: %v\nstdout:\n%s\nstderr:\n%s", err, jsonStdout.Bytes(), jsonStderr.Bytes())
	}
	if bytes.Contains(jsonStdout.Bytes(), []byte(debugSimpleWarning)) {
		t.Fatalf("debug warning contaminated JSON stdout:\n%s", jsonStdout.Bytes())
	}
	if count := bytes.Count(jsonStderr.Bytes(), []byte(debugSimpleWarning)); count != 1 {
		t.Fatalf("debug warning count on stderr = %d, want 1\n%s", count, jsonStderr.Bytes())
	}
	jsonReport := decodeA2ATestReport(t, jsonStdout.Bytes())
	if jsonReport.Status != a2asecuritytest.StatusPass || jsonReport.Summary.Passed != 8 {
		t.Fatalf("JSON stdout result = status %q summary %+v", jsonReport.Status, jsonReport.Summary)
	}

	versionOutput, err := exec.Command(binary, "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("run --version: %v\n%s", err, versionOutput)
	}
	if !bytes.Contains(versionOutput, []byte("asb-a2a-test dev (unknown)")) {
		t.Fatalf("unexpected version output: %s", versionOutput)
	}
}

func decodeA2ATestReport(t *testing.T, raw []byte) a2asecuritytest.Report {
	t.Helper()
	report, err := a2asecuritytest.DecodeReport(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("decode A2A security test report: %v\n%s", err, raw)
	}
	return report
}

func TestMultiprocessDraft06V2EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("multiprocess loopback test disabled in short mode")
	}
	binary := filepath.Join(t.TempDir(), "asb-a2a-v2")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Env = os.Environ()
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build demo: %v\n%s", err, output)
	}
	run := exec.Command(binary, "--role", "orchestrator", "--binding-profile", bindingProfileDraft06V2)
	output, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run draft-06 demo: %v\n%s", err, output)
	}
	for _, expected := range []string{
		"authorized Send Message v2", "nonce reuse on another task",
		"borrowed challenge on TLS", "target substitution", "operation substitution",
		"wrong endpoint role", "wrong interaction type", "missing exporter",
		"reserialized grant hash", "missing attestation binder", "missing attestation result",
		"summary: 11/11 expected decisions observed",
	} {
		if !bytes.Contains(output, []byte(expected)) {
			t.Fatalf("draft-06 demo output missing %q\n%s", expected, output)
		}
	}

	jsonRun := exec.Command(binary, "--role", "orchestrator", "--binding-profile", bindingProfileDraft06V2, "--format", "json")
	jsonOutput, err := jsonRun.CombinedOutput()
	if err != nil {
		t.Fatalf("run draft-06 JSON demo: %v\n%s", err, jsonOutput)
	}
	report := decodeA2ATestReport(t, jsonOutput)
	if report.Profile != bindingProfileDraft06V2 || report.Status != a2asecuritytest.StatusPass || report.Summary.Total != 11 || report.Summary.Passed != 11 {
		t.Fatalf("draft-06 JSON report = profile %q status %q summary %+v", report.Profile, report.Status, report.Summary)
	}
}
