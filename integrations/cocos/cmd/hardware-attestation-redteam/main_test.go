// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sevsnppb "github.com/google/go-sev-guest/proto/sevsnp"
	"google.golang.org/protobuf/proto"
)

func TestValidateChallengeBindingRejectsStaleEvidence(t *testing.T) {
	challengeA := make([]byte, reportDataSize)
	challengeB := make([]byte, reportDataSize)
	challengeA[0] = 1
	challengeB[0] = 2

	if err := validateChallengeBinding(challengeA, challengeA); err != nil {
		t.Fatalf("validateChallengeBinding() rejected matching challenge: %v", err)
	}
	err := validateChallengeBinding(challengeA, challengeB)
	if !errors.Is(err, errChallengeMismatch) {
		t.Fatalf("validateChallengeBinding() error = %v, want errChallengeMismatch", err)
	}
}

func TestExtractSEVSNPEvidence(t *testing.T) {
	reportData := make([]byte, reportDataSize)
	reportData[0] = 0x7a
	hostData := make([]byte, 32)
	hostData[0] = 0x42
	encoded, err := proto.Marshal(&sevsnppb.Attestation{
		Report: &sevsnppb.Report{
			ReportData: reportData,
			HostData:   hostData,
		},
	})
	if err != nil {
		t.Fatalf("proto.Marshal() error = %v", err)
	}

	extracted, err := extractSEVSNPEvidence(encoded)
	if err != nil {
		t.Fatalf("extractSEVSNPEvidence() error = %v", err)
	}
	if got := extracted.ReportData[0]; got != 0x7a {
		t.Fatalf("ReportData[0] = %#x, want 0x7a", got)
	}
	if got := extracted.HostData[0]; got != 0x42 {
		t.Fatalf("HostData[0] = %#x, want 0x42", got)
	}
}

func TestResolvePlatformRejectsUnsupportedInput(t *testing.T) {
	for _, platform := range []string{"", "auto", "snp-vtpm", "vtpm", "azure"} {
		if _, err := resolvePlatform(platform); err == nil {
			t.Fatalf("resolvePlatform(%q) accepted unsupported platform", platform)
		}
	}
}

func TestPrepareSEVSNPCertificateCache(t *testing.T) {
	called := false
	if err := prepareSEVSNPCertificateCache(2, func(vmpl uint) error {
		called = true
		if vmpl != 2 {
			t.Fatalf("VMPL = %d, want 2", vmpl)
		}
		return nil
	}); err != nil {
		t.Fatalf("prepareSEVSNPCertificateCache() error = %v", err)
	}
	if !called {
		t.Fatal("prepareSEVSNPCertificateCache() did not fetch certificates")
	}

	err := prepareSEVSNPCertificateCache(0, func(uint) error { return errors.New("offline") })
	if err == nil || !strings.Contains(err.Error(), "AMD KDS") {
		t.Fatalf("prepareSEVSNPCertificateCache() error = %v, want AMD KDS context", err)
	}
}

func TestFullModuleVerificationRequiresBothPolicies(t *testing.T) {
	_, err := verifyFullModulePath(platformSNP, nil, nil, nil, nil, runOptions{})
	if err == nil {
		t.Fatal("verifyFullModulePath() accepted missing policy inputs")
	}
}

func TestQualificationBindingCopiesReportDataAndCreatesNonce(t *testing.T) {
	reportData := make([]byte, reportDataSize)
	reportData[0] = 0x42
	binding, nonce, err := qualificationBinding(reportData)
	if err != nil {
		t.Fatal(err)
	}
	if binding.ReportData[0] != 0x42 || len(nonce) != len(binding.Nonce) {
		t.Fatalf("unexpected qualification binding: report=%x nonce_len=%d", binding.ReportData[0], len(nonce))
	}
	if string(nonce) != string(binding.Nonce[:]) {
		t.Fatal("returned nonce does not match binding nonce")
	}
}

func TestWriteSummary(t *testing.T) {
	dir := t.TempDir()
	summary := &runSummary{
		TimestampUTC:     "2026-06-30T00:00:00Z",
		Platform:         platformSNP,
		EvidenceASHA256:  "evidence-a",
		EvidenceBSHA256:  "evidence-b",
		ChallengeASHA256: "challenge-a",
		ChallengeBSHA256: "challenge-b",
	}
	if err := writeSummary(dir, summary); err != nil {
		t.Fatalf("writeSummary() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "summary.json")); err != nil {
		t.Fatalf("summary.json was not written: %v", err)
	}
}
