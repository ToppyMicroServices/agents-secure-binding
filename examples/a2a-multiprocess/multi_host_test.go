// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/a2asecuritytest"
)

const multiHostExamplePath = "testdata/multihost-deployment.example.json"

func TestMultiHostDeploymentFixtureIsExplicitAndNonLoopback(t *testing.T) {
	deployment, err := loadMultiHostDeployment(multiHostExamplePath)
	if err != nil {
		t.Fatal(err)
	}
	if deployment.BindingProfile != bindingProfileDraft06V2 || deployment.DeploymentID != "asb-multihost-example-v1" {
		t.Fatalf("deployment identity = %q profile %q", deployment.DeploymentID, deployment.BindingProfile)
	}
	origins := make(map[string]struct{})
	for _, role := range multiHostServerRoles {
		endpoint := deployment.Endpoints[role]
		if endpoint.Listen == "" || strings.Contains(endpoint.URL, "localhost") || strings.Contains(endpoint.URL, "127.0.0.1") {
			t.Fatalf("%s endpoint has an ambient loopback value: %+v", role, endpoint)
		}
		origins[endpoint.URL] = struct{}{}
	}
	if len(origins) != len(multiHostServerRoles) {
		t.Fatalf("fixture has %d distinct origins, want %d", len(origins), len(multiHostServerRoles))
	}
}

func TestMultiHostDeploymentRejectsUnsafeOrAmbiguousTopology(t *testing.T) {
	tests := map[string]func(*multiHostDeploymentV1){
		"HTTP origin": func(value *multiHostDeploymentV1) {
			endpoint := value.Endpoints["agent-b"]
			endpoint.URL = "http://agent-b.asb.example:8447"
			value.Endpoints["agent-b"] = endpoint
		},
		"loopback origin": func(value *multiHostDeploymentV1) {
			endpoint := value.Endpoints["agent-b"]
			endpoint.URL = "https://127.0.0.1:8447"
			value.Endpoints["agent-b"] = endpoint
		},
		"unspecified origin": func(value *multiHostDeploymentV1) {
			endpoint := value.Endpoints["agent-b"]
			endpoint.URL = "https://0.0.0.0:8447"
			value.Endpoints["agent-b"] = endpoint
		},
		"loopback listen": func(value *multiHostDeploymentV1) {
			endpoint := value.Endpoints["agent-b"]
			endpoint.Listen = "127.0.0.1:8447"
			value.Endpoints["agent-b"] = endpoint
		},
		"shared origin": func(value *multiHostDeploymentV1) {
			endpoint := value.Endpoints["agent-b"]
			endpoint.URL = value.Endpoints["manager"].URL
			value.Endpoints["agent-b"] = endpoint
		},
		"URL path": func(value *multiHostDeploymentV1) {
			endpoint := value.Endpoints["agent-b"]
			endpoint.URL += "/proxy"
			value.Endpoints["agent-b"] = endpoint
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			deployment, err := loadMultiHostDeployment(multiHostExamplePath)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&deployment)
			path := writeMultiHostDeploymentForTest(t, deployment)
			if _, err := loadMultiHostDeployment(path); err == nil {
				t.Fatal("unsafe deployment was accepted")
			}
		})
	}
}

func TestMultiHostDeploymentRejectsDuplicateJSONMembers(t *testing.T) {
	raw, err := os.ReadFile(multiHostExamplePath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(raw, []byte(`"deployment_id": "asb-multihost-example-v1",`), []byte(`"deployment_id": "first", "deployment_id": "second",`), 1)
	path := filepath.Join(t.TempDir(), "duplicate.json")
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadMultiHostDeployment(path); err == nil || !strings.Contains(err.Error(), "duplicate JSON member") {
		t.Fatalf("duplicate-member error = %v", err)
	}
}

func TestMultiHostDeploymentRejectsCaseFoldedMemberAlias(t *testing.T) {
	raw, err := os.ReadFile(multiHostExamplePath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(raw, []byte(`"deployment_id"`), []byte(`"Deployment_ID"`), 1)
	path := filepath.Join(t.TempDir(), "case-alias.json")
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadMultiHostDeployment(path); err == nil || !strings.Contains(err.Error(), "exact member") {
		t.Fatalf("case-alias error = %v", err)
	}
}

func TestBootstrapMultiHostStateBindsCertificatesToConfiguredOrigins(t *testing.T) {
	deployment, err := loadMultiHostDeployment(multiHostExamplePath)
	if err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(t.TempDir(), "state")
	trustPath := filepath.Join(stateDir, multiHostTrustFile)
	if err := bootstrapMultiHostState(stateDir, deployment, trustPath); err != nil {
		t.Fatal(err)
	}
	for _, role := range multiHostServerRoles {
		raw, err := os.ReadFile(filepath.Join(roleDirectory(stateDir, role), tlsCertFile))
		if err != nil {
			t.Fatal(err)
		}
		certificate, err := firstCertificateFromPEM(raw)
		if err != nil {
			t.Fatal(err)
		}
		parsed, _ := url.Parse(deployment.Endpoints[role].URL)
		if err := certificate.VerifyHostname(parsed.Hostname()); err != nil {
			t.Fatalf("%s certificate does not cover %s: %v", role, parsed.Hostname(), err)
		}
		if certificate.VerifyHostname("localhost") == nil || certificate.VerifyHostname("127.0.0.1") == nil {
			t.Fatalf("%s multi-host certificate retained a loopback SAN", role)
		}
	}
	var manifest multiHostTrustManifestV1
	if _, err := decodeStrictMultiHostFile(trustPath, &manifest); err != nil {
		t.Fatal(err)
	}
	if err := validateMultiHostTrustManifest(manifest, deployment); err != nil {
		t.Fatal(err)
	}
	if err := verifyLocalAgentATrust(stateDir, manifest); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(trustPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("trust manifest permissions = %v, want 0600", info.Mode().Perm())
	}
}

func TestBootstrapMultiHostStateDoesNotReplaceExistingState(t *testing.T) {
	deployment, err := loadMultiHostDeployment(multiHostExamplePath)
	if err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	marker := filepath.Join(stateDir, "operator-data")
	if err := os.WriteFile(marker, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := bootstrapMultiHostState(stateDir, deployment, filepath.Join(stateDir, multiHostTrustFile)); err == nil {
		t.Fatal("bootstrap replaced a non-empty state directory")
	}
	if raw, err := os.ReadFile(marker); err != nil || string(raw) != "preserve" {
		t.Fatalf("operator data changed: %q err=%v", raw, err)
	}
}

func TestApplyMultiHostDeploymentSuppliesRoleInputs(t *testing.T) {
	deployment, err := loadMultiHostDeployment(multiHostExamplePath)
	if err != nil {
		t.Fatal(err)
	}
	opts := applyMultiHostDeployment(options{role: "agent-b"}, deployment)
	if opts.listen != deployment.Endpoints["agent-b"].Listen || opts.publicURL != deployment.Endpoints["agent-b"].URL || opts.replayURL != deployment.Endpoints["replay"].URL {
		t.Fatalf("Agent B deployment inputs = %+v", opts)
	}
	if !opts.allowSimulation || opts.bindingProfile != bindingProfileDraft06V2 {
		t.Fatalf("Agent B policy inputs = simulation %v profile %q", opts.allowSimulation, opts.bindingProfile)
	}
	agentA := applyMultiHostDeployment(options{role: "agent-a", listen: "127.0.0.1:0"}, deployment)
	if agentA.agentBURL != deployment.Endpoints["agent-b"].URL || agentA.listen != "127.0.0.1:0" {
		t.Fatalf("Agent A deployment inputs = %+v", agentA)
	}
}

func TestMultiHostEvidenceLinksDeploymentTrustAndReport(t *testing.T) {
	deployment, err := loadMultiHostDeployment(multiHostExamplePath)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	trustPath := filepath.Join(stateDir, multiHostTrustFile)
	if err := bootstrapMultiHostState(stateDir, deployment, trustPath); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(root, "report.json")
	evidencePath := filepath.Join(root, "evidence.json")
	opts := options{
		role: "agent-a", stateDir: stateDir, bindingProfile: deployment.BindingProfile,
		attestationMode: modeSimulation, attestationPlatform: platformAuto,
		reportFormat: "json", reportFile: reportPath,
		deploymentConfig: multiHostExamplePath, trustManifest: trustPath,
		deploymentEvidence: evidencePath,
	}
	var output bytes.Buffer
	reporter, err := newTestRunReporter(opts, &output)
	if err != nil {
		t.Fatal(err)
	}
	if reporter.report.Mode != a2asecuritytest.ModeTarget {
		t.Fatalf("report mode = %q, want target", reporter.report.Mode)
	}
	if err := reporter.record("ASB-A2A-MULTIHOST-001", "configured receiver accepted request", "none", a2aResult{status: 200}, 200, ""); err != nil {
		t.Fatal(err)
	}
	if err := reporter.finish(); err != nil {
		t.Fatal(err)
	}
	reportRaw, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var evidence multiHostRunEvidenceV1
	if _, err := decodeStrictMultiHostFile(evidencePath, &evidence); err != nil {
		t.Fatal(err)
	}
	if err := validateMultiHostRunEvidence(evidence); err != nil {
		t.Fatal(err)
	}
	if evidence.ReportSHA256 != digestWithPrefix(reportRaw) || evidence.DeploymentID != deployment.DeploymentID || evidence.Status != a2asecuritytest.StatusPass {
		t.Fatalf("evidence linkage = %+v", evidence)
	}
	evidenceRaw, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatal(err)
	}
	trustRaw, err := os.ReadFile(trustPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"PRIVATE KEY", "identity_grant", "session_binding\"", "verifier_nonce", "api_key"} {
		if bytes.Contains(evidenceRaw, []byte(forbidden)) || bytes.Contains(trustRaw, []byte(forbidden)) {
			t.Fatalf("multi-host non-secret artifacts contain forbidden value %q", forbidden)
		}
	}
	info, err := os.Stat(evidencePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("evidence permissions = %v, want 0600", info.Mode().Perm())
	}
	var verificationOutput bytes.Buffer
	verifyOpts := opts
	verifyOpts.role = "verify-evidence"
	if err := verifyMultiHostRunEvidence(verifyOpts, &verificationOutput); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(verificationOutput.String(), deployment.DeploymentID) {
		t.Fatalf("verification output = %q", verificationOutput.String())
	}
	tamperedReportPath := filepath.Join(root, "tampered-report.json")
	if err := os.WriteFile(tamperedReportPath, append(append([]byte(nil), reportRaw...), ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	verifyOpts.reportFile = tamperedReportPath
	if err := verifyMultiHostRunEvidence(verifyOpts, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("tampered report verification error = %v", err)
	}
}

func writeMultiHostDeploymentForTest(t *testing.T, deployment multiHostDeploymentV1) string {
	t.Helper()
	raw, err := json.Marshal(deployment)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "deployment.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
