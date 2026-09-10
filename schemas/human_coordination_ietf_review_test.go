// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package schemas

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHumanCoordinationIETFReviewTopics(t *testing.T) {
	t.Parallel()

	documentPath := filepath.Join(
		humanCoordinationRepositoryRoot(t),
		"docs",
		"human-coordination-ietf-review.md",
	)
	raw, err := os.ReadFile(documentPath)
	if err != nil {
		t.Fatalf("read IETF review topics: %v", err)
	}
	document := string(raw)

	required := []string{
		"Active Internet-Draft (individual)",
		"adopted Working Group item",
		"IETF consensus",
		"Human Participant",
		"gateway Actor",
		"verifier-local policy context",
		"caller-controlled `realm_id`",
		"`gateway-asserted-for-human`",
		"`authenticated-human-evidence`",
		"`human-held-key-exact-request`",
		"source authority",
		"destination audience",
		"outcome is unknown",
		"reconciliation",
		"`accepted`",
		"`delivered`",
		"`read`",
		"`approved`",
		"`completed`",
		"pairwise",
		"existence-sensitive lookup",
		"revocable",
		"retention and deletion",
		"low-entropy content",
		"reverse proxy",
		"Forwarded HTTP",
		"Redis, Valkey",
		"Go APIs",
		"database ownership",
		"request no IANA action",
		"independently developed implementations",
	}
	for _, fragment := range required {
		if !strings.Contains(document, fragment) {
			t.Errorf("IETF review topics missing %q", fragment)
		}
	}

	officialURLs := []string{
		"https://datatracker.ietf.org/doc/draft-okutomi-agent-human-interaction/",
		"https://datatracker.ietf.org/doc/draft-okutomi-session-bound-agent-identity/",
		"https://datatracker.ietf.org/wg/agentproto/about/",
		"https://datatracker.ietf.org/wg/dmsc/about/",
		"https://datatracker.ietf.org/doc/draft-rosenberg-aiproto-cheq/",
	}
	for _, officialURL := range officialURLs {
		if !strings.Contains(document, officialURL) {
			t.Errorf("IETF review topics missing official URL %q", officialURL)
		}
	}
}
