// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/humanrelay"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
	taskcoordbinding "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord/asbbinding"
)

func TestRelayCanonicalTranscriptUsesExactUnicodeBytes(t *testing.T) {
	t.Parallel()

	nfc := relayCanonicalRedTeamRequest()
	nfc.Purpose = "review-caf\u00e9"
	nfd := nfc
	nfd.Purpose = "review-cafe\u0301"

	nfcDigest, err := humanrelay.RequestDigest(nfc)
	if err != nil {
		t.Fatalf("NFC request rejected: %v", err)
	}
	nfdDigest, err := humanrelay.RequestDigest(nfd)
	if err != nil {
		t.Fatalf("NFD request rejected: %v", err)
	}
	if nfcDigest == nfdDigest {
		t.Fatal("canonically equivalent but byte-distinct relay fields produced the same digest")
	}
}

func TestRelayCanonicalValidationUsesUTF8ByteLimits(t *testing.T) {
	t.Parallel()

	atIDLimit := relayCanonicalRedTeamRequest()
	atIDLimit.Purpose = strings.Repeat("é", 128)
	if len(atIDLimit.Purpose) != 256 {
		t.Fatalf("test purpose length = %d, want 256", len(atIDLimit.Purpose))
	}
	if _, err := humanrelay.RequestDigest(atIDLimit); err != nil {
		t.Fatalf("relay field at byte limit rejected: %v", err)
	}

	overIDLimit := atIDLimit
	overIDLimit.Purpose += "é"
	if _, err := humanrelay.RequestDigest(overIDLimit); !errors.Is(err, humanrelay.ErrInvalidRequest) {
		t.Fatalf("relay field over byte limit error = %v, want ErrInvalidRequest", err)
	}

	const prefix = "https://content.example.test/"
	atReferenceLimit := relayCanonicalRedTeamRequest()
	remaining := 2048 - len(prefix)
	atReferenceLimit.ContentRef = prefix + strings.Repeat("é", remaining/2) + strings.Repeat("a", remaining%2)
	if len(atReferenceLimit.ContentRef) != 2048 {
		t.Fatalf("test content_ref length = %d, want 2048", len(atReferenceLimit.ContentRef))
	}
	if _, err := humanrelay.RequestDigest(atReferenceLimit); err != nil {
		t.Fatalf("content_ref at byte limit rejected: %v", err)
	}

	overReferenceLimit := atReferenceLimit
	overReferenceLimit.ContentRef += "a"
	if _, err := humanrelay.RequestDigest(overReferenceLimit); !errors.Is(err, humanrelay.ErrInvalidRequest) {
		t.Fatalf("content_ref over byte limit error = %v, want ErrInvalidRequest", err)
	}
}

func TestHumanAndRelayProfilesSeparateTheSameDigestBytes(t *testing.T) {
	t.Parallel()

	var raw [32]byte
	for index := range raw {
		raw[index] = byte(index)
	}
	relayDigest := humanrelay.Digest(raw)
	humanDigest := taskcoordbinding.Digest(raw)

	if AuthorizationDetail(relayDigest) == taskcoordbinding.AuthorizationDetail(humanDigest) {
		t.Fatal("Human and relay profiles produced the same authorization detail")
	}
	if bytes.Equal(RequestContext(relayDigest), taskcoordbinding.RequestContext(humanDigest)) {
		t.Fatal("Human and relay profiles produced the same request context")
	}
	if RequestContextSHA256(relayDigest) == taskcoordbinding.RequestContextSHA256(humanDigest) {
		t.Fatal("Human and relay profiles produced the same request-context hash")
	}
}

func relayCanonicalRedTeamRequest() humanrelay.RelayIntentRequest {
	return humanrelay.RelayIntentRequest{
		IntentID:               "intent:redteam",
		GrantID:                "grant:redteam",
		RequesterParticipantID: "agent:redteam",
		Purpose:                "human-review",
		Capability:             "review-document",
		Channel:                taskcoord.ReachabilityEmail,
		ContentRef:             "https://content.example.test/redteam",
		ContentDigest:          strings.Repeat("a", 64),
	}
}
