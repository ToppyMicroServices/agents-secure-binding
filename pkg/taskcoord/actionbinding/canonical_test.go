// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionbinding

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/actionlifecycle"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

type actionTranscriptGolden struct {
	TranscriptHex string `json:"transcript_hex"`
	Digest        string `json:"digest"`
}

type actionTranscriptGoldenFile struct {
	Vectors map[string]actionTranscriptGolden `json:"vectors"`
}

func TestAcceptanceContextTranscriptV1Golden(t *testing.T) {
	t.Parallel()
	assignment := goldenAcceptedAssignment(t)
	want := loadActionTranscriptGolden(t, "acceptance_context")

	transcript, err := AcceptanceContextTranscript(assignment)
	if err != nil {
		t.Fatal(err)
	}
	wantBytes, err := hex.DecodeString(want.TranscriptHex)
	if err != nil {
		t.Fatalf("golden transcript hex: %v", err)
	}
	if !bytes.Equal(transcript, wantBytes) {
		t.Fatalf("transcript = %x\nwant       = %x", transcript, wantBytes)
	}
	digest, err := AcceptanceContextDigest(assignment)
	if err != nil {
		t.Fatal(err)
	}
	if digest != want.Digest {
		t.Fatalf("digest = %s, want %s", digest, want.Digest)
	}
}

func TestIntegratedAcceptanceRequestMatchesV1Golden(t *testing.T) {
	t.Parallel()
	assignment := goldenAcceptedAssignment(t)
	request := AcceptRequest{
		AssignmentID: assignment.AssignmentID, EventID: "e", ActionID: "a",
		ActionDigest: "sha256:" + strings.Repeat("1", 64),
		RecoveryPolicy: actionlifecycle.RecoveryPolicy{
			Mode: actionlifecycle.RecoveryManual, MaxAttempts: 1,
		},
	}
	want := loadActionTranscriptGolden(t, "acceptance_request")
	digest, err := AcceptanceRequestDigest(assignment, request)
	if err != nil {
		t.Fatal(err)
	}
	if digest != want.Digest {
		t.Fatalf("digest = %s, want %s", digest, want.Digest)
	}
}

func TestAcceptanceAttemptTranscriptV1Golden(t *testing.T) {
	t.Parallel()
	auth := &actionlifecycle.AuthenticatedOperation{
		ActorID:         "actor",
		AuthorizationID: "authorization",
		ProofID:         "proof",
		Operation:       actionlifecycle.EventAccept,
		ActionID:        "a",
		ActionDigest:    "sha256:" + strings.Repeat("1", 64),
		MutationDigest:  "sha256:" + strings.Repeat("2", 64),
		VerifierNonce:   "nonce",
		IssuedAt:        time.Date(2026, 9, 1, 0, 0, 0, 123456789, time.UTC),
		ExpiresAt:       time.Date(2026, 9, 1, 0, 5, 0, 987654321, time.UTC),
	}
	want := loadActionTranscriptGolden(t, "acceptance_attempt")
	transcript, err := AcceptanceAttemptTranscript(auth)
	if err != nil {
		t.Fatal(err)
	}
	wantBytes, err := hex.DecodeString(want.TranscriptHex)
	if err != nil {
		t.Fatalf("golden transcript hex: %v", err)
	}
	if !bytes.Equal(transcript, wantBytes) {
		t.Fatalf("transcript = %x\nwant       = %x", transcript, wantBytes)
	}
	fingerprint, err := AcceptanceAttemptFingerprint(auth)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint != want.Digest {
		t.Fatalf("fingerprint = %s, want %s", fingerprint, want.Digest)
	}
}

func TestAcceptanceAttemptFingerprintBindsVerifierProjection(t *testing.T) {
	t.Parallel()
	base := actionlifecycle.AuthenticatedOperation{
		ActorID:         "actor",
		AuthorizationID: "authorization",
		ProofID:         "proof",
		Operation:       actionlifecycle.EventAccept,
		ActionID:        "action",
		ActionDigest:    "sha256:" + strings.Repeat("1", 64),
		MutationDigest:  "sha256:" + strings.Repeat("2", 64),
		VerifierNonce:   "nonce",
		IssuedAt:        time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		ExpiresAt:       time.Date(2026, 9, 1, 0, 5, 0, 0, time.UTC),
	}
	want, err := AcceptanceAttemptFingerprint(&base)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]func(*actionlifecycle.AuthenticatedOperation){
		"actor":         func(candidate *actionlifecycle.AuthenticatedOperation) { candidate.ActorID += ":changed" },
		"authorization": func(candidate *actionlifecycle.AuthenticatedOperation) { candidate.AuthorizationID += ":changed" },
		"proof":         func(candidate *actionlifecycle.AuthenticatedOperation) { candidate.ProofID += ":changed" },
		"action":        func(candidate *actionlifecycle.AuthenticatedOperation) { candidate.ActionID += ":changed" },
		"action digest": func(candidate *actionlifecycle.AuthenticatedOperation) {
			candidate.ActionDigest = "sha256:" + strings.Repeat("3", 64)
		},
		"mutation digest": func(candidate *actionlifecycle.AuthenticatedOperation) {
			candidate.MutationDigest = "sha256:" + strings.Repeat("4", 64)
		},
		"nonce": func(candidate *actionlifecycle.AuthenticatedOperation) { candidate.VerifierNonce += ":changed" },
		"issued at": func(candidate *actionlifecycle.AuthenticatedOperation) {
			candidate.IssuedAt = candidate.IssuedAt.Add(time.Nanosecond)
		},
		"expires at": func(candidate *actionlifecycle.AuthenticatedOperation) {
			candidate.ExpiresAt = candidate.ExpiresAt.Add(time.Nanosecond)
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate := base
			mutate(&candidate)
			got, err := AcceptanceAttemptFingerprint(&candidate)
			if err != nil {
				t.Fatal(err)
			}
			if got == want {
				t.Fatal("changed verifier projection retained the same fingerprint")
			}
		})
	}

	wrongOperation := base
	wrongOperation.Operation = actionlifecycle.EventStart
	if _, err := AcceptanceAttemptFingerprint(&wrongOperation); err == nil {
		t.Fatal("non-ACCEPT verifier projection was fingerprinted")
	}
}

func goldenAcceptedAssignment(t *testing.T) taskcoord.Assignment {
	t.Helper()
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	assignment := acceptedAssignment(t, "a", "t", "p", at)
	assignment.Role = taskcoord.RoleOwner
	assignment.AuthorityDigest = strings.Repeat("0", 64)
	if assignment.Revision != 2 {
		t.Fatalf("golden Assignment revision = %d, want 2", assignment.Revision)
	}
	if err := assignment.Validate(); err != nil {
		t.Fatalf("golden Assignment: %v", err)
	}
	return assignment
}

func loadActionTranscriptGolden(t *testing.T, name string) actionTranscriptGolden {
	t.Helper()
	raw, err := os.ReadFile("../../../testdata/action-transcript-v1-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture actionTranscriptGoldenFile
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("golden vector JSON: %v", err)
	}
	vector, ok := fixture.Vectors[name]
	if !ok {
		t.Fatalf("golden vector %q is missing", name)
	}
	return vector
}
