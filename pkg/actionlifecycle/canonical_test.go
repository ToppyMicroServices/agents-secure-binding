// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionlifecycle

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

type transcriptGolden struct {
	TranscriptHex string `json:"transcript_hex"`
	Digest        string `json:"digest"`
}

type transcriptGoldenFile struct {
	Vectors map[string]transcriptGolden `json:"vectors"`
}

func TestMutationRequestTranscriptV1Golden(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 9, 1, 0, 0, 0, 123456789, time.UTC)
	notBefore := time.Date(2026, 9, 1, 0, 1, 0, 0, time.UTC)
	event := goldenMutationEvent(at, notBefore)
	want := loadTranscriptGolden(t, "mutation_request")

	transcript, err := MutationRequestTranscript(event)
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
	digest, err := MutationRequestDigest(event)
	if err != nil {
		t.Fatal(err)
	}
	if digest != want.Digest {
		t.Fatalf("digest = %s, want %s", digest, want.Digest)
	}
}

func TestAcceptanceRequestTranscriptV1Golden(t *testing.T) {
	t.Parallel()
	definition := Definition{
		EventID: "e", ActionID: "a",
		ActionDigest: "sha256:" + strings.Repeat("1", 64), OwnerID: "p",
		RecoveryPolicy:          RecoveryPolicy{Mode: RecoveryManual, MaxAttempts: 1},
		AcceptanceContextDigest: "sha256:965b87ed6a9f2e6cddf277658572fa4b735a2e65666ad1745e1a662ccb7a93de",
	}
	want := loadTranscriptGolden(t, "acceptance_request")
	transcript, err := AcceptanceRequestTranscript(definition)
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
	digest, err := AcceptanceRequestDigest(definition)
	if err != nil {
		t.Fatal(err)
	}
	if digest != want.Digest {
		t.Fatalf("digest = %s, want %s", digest, want.Digest)
	}
}

func TestTranscriptsRejectFieldBoundaryAmbiguity(t *testing.T) {
	t.Parallel()
	base := Definition{
		EventID: "a", ActionID: "bc",
		ActionDigest: "sha256:" + strings.Repeat("1", 64), OwnerID: "p",
		RecoveryPolicy:          RecoveryPolicy{Mode: RecoveryManual, MaxAttempts: 1},
		AcceptanceContextDigest: "sha256:" + strings.Repeat("2", 64),
	}
	shifted := base
	shifted.EventID = "ab"
	shifted.ActionID = "c"
	left, leftErr := AcceptanceRequestTranscript(base)
	right, rightErr := AcceptanceRequestTranscript(shifted)
	if leftErr != nil || rightErr != nil {
		t.Fatalf("transcript errors = %v, %v", leftErr, rightErr)
	}
	if bytes.Equal(left, right) {
		t.Fatal("different field boundaries produced the same transcript")
	}
}

func TestMutationTranscriptOptionalAndTimeEncoding(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 9, 1, 0, 0, 0, 123456789, time.UTC)
	notBefore := at.Add(time.Minute)
	base := goldenMutationEvent(at, notBefore)

	zone := time.FixedZone("example", 9*60*60)
	equivalent := base
	equivalent.At = base.At.In(zone)
	equivalentNotBefore := base.ResumeCondition.NotBefore.In(zone)
	equivalent.ResumeCondition = &ResumeCondition{Type: ResumeAtTime, NotBefore: &equivalentNotBefore}
	equivalentCheckpoint := *base.Checkpoint
	equivalentCheckpoint.CreatedAt = base.Checkpoint.CreatedAt.In(zone)
	equivalent.Checkpoint = &equivalentCheckpoint
	baseBytes, baseErr := MutationRequestTranscript(base)
	equivalentBytes, equivalentErr := MutationRequestTranscript(equivalent)
	if baseErr != nil || equivalentErr != nil {
		t.Fatalf("transcript errors = %v, %v", baseErr, equivalentErr)
	}
	if !bytes.Equal(baseBytes, equivalentBytes) {
		t.Fatal("the same timestamp instants produced different transcripts")
	}

	absent := base
	absent.Fence = nil
	absentBytes, err := MutationRequestTranscript(absent)
	if err != nil {
		t.Fatal(err)
	}
	presentEmpty := base
	presentEmpty.Fence = &LeaseFence{}
	presentBytes, err := MutationRequestTranscript(presentEmpty)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(absentBytes, presentBytes) {
		t.Fatal("absent and present-empty fence encodings collide")
	}
}

func TestMutationTranscriptRejectsInvalidUTF8AndOversize(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	event := Event{
		ID: "e", Kind: EventPause, ExpectedRevision: 1, At: at,
		Reason: Reason{Code: ReasonOperatorPause, Detail: string([]byte{0xff})},
	}
	if transcript, err := MutationRequestTranscript(event); err == nil || transcript != nil {
		t.Fatalf("invalid UTF-8 transcript = %x, %v", transcript, err)
	}
	event.Reason.Detail = strings.Repeat("a", 16<<10)
	if transcript, err := MutationRequestTranscript(event); err == nil || transcript != nil {
		t.Fatalf("oversize transcript = %x, %v", transcript, err)
	}
}

func goldenMutationEvent(at, notBefore time.Time) Event {
	return Event{
		ID: "evt", Kind: EventWait, ExpectedRevision: 1, At: at,
		Reason: Reason{Code: ReasonScheduled},
		Fence:  &LeaseFence{LeaseID: "l", ExecutorID: "x", Generation: 2},
		ResumeCondition: &ResumeCondition{
			Type: ResumeAtTime, NotBefore: &notBefore,
		},
		Checkpoint: &Checkpoint{
			Sequence: 1, PayloadDigest: "sha256:" + strings.Repeat("2", 64),
			StorageRef: "urn:c", CreatedAt: at,
		},
	}
}

func loadTranscriptGolden(t *testing.T, name string) transcriptGolden {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/action-transcript-v1-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture transcriptGoldenFile
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("golden vector JSON: %v", err)
	}
	vector, ok := fixture.Vectors[name]
	if !ok {
		t.Fatalf("golden vector %q is missing", name)
	}
	return vector
}
