// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestMultiprocessSimulationEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("multiprocess loopback test disabled in short mode")
	}
	binary := filepath.Join(t.TempDir(), "asb-a2a")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Env = os.Environ()
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build demo: %v\n%s", err, output)
	}
	run := exec.Command(binary, "--role", "orchestrator")
	output, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run demo: %v\n%s", err, output)
	}
	for _, expected := range []string{
		"authorized Send Message", "tampered evidence", "durable replay",
		"borrowed TLS session", "resource substitution", "version downgrade",
		"summary: 6/6 expected decisions observed",
	} {
		if !bytes.Contains(output, []byte(expected)) {
			t.Fatalf("demo output missing %q\n%s", expected, output)
		}
	}
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
		"summary: 11/11 expected draft06-v2 decisions observed",
	} {
		if !bytes.Contains(output, []byte(expected)) {
			t.Fatalf("draft-06 demo output missing %q\n%s", expected, output)
		}
	}
}
