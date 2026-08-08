// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package agtpdiscover

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"
)

// TestLiveASBDiscoverAgainstAGTP runs the complete ASB gate against a real
// local AGTP coordinator when ASB_AGTP_UPSTREAM is set. It is skipped in the
// ordinary unit suite so the repository does not acquire an AGTP runtime
// dependency.
func TestLiveASBDiscoverAgainstAGTP(t *testing.T) {
	address := os.Getenv("ASB_AGTP_UPSTREAM")
	if address == "" {
		t.Skip("set ASB_AGTP_UPSTREAM to a local AGTP coordinator address")
	}
	capability := os.Getenv("ASB_AGTP_CAPABILITY")
	if capability == "" {
		capability = "generate"
	}
	fixture := newTestFixtureForUpstream(t, TCPUpstream{Address: address})
	session := fixture.dial(t)
	defer session.conn.Close()
	query := Query{Capability: capability, Limit: 100}
	headers := fixture.headers(t, session, query)

	status, body := sendQuery(t, session, query, headers)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", status, http.StatusOK, body)
	}
	var response struct {
		Results []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode AGTP response: %v; body = %s", err, body)
	}
	if len(response.Results) == 0 {
		t.Fatalf("AGTP returned no results for capability %q", capability)
	}
	t.Logf("ASB accepted DISCOVER and AGTP returned %d result(s)", len(response.Results))
}
