// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/agtp/discovery"
)

func TestSelectDiscoveredTargetRequiresObservedAndPinnedIdentity(t *testing.T) {
	target := targetConfig{AgentID: roleAgentB, Name: "sum-worker.example", Capability: "sum", Endpoint: "https://127.0.0.1:9443"}
	tests := []struct {
		name   string
		change func(*discovery.Response, *discovery.NameBinding, *bool)
		valid  bool
	}{
		{name: "exact-discovered-target", valid: true},
		{name: "missing-record-has-no-fallback", change: func(response *discovery.Response, _ *discovery.NameBinding, _ *bool) {
			*response = discovery.Response{}
		}},
		{name: "ambiguous-records", change: func(response *discovery.Response, _ *discovery.NameBinding, _ *bool) {
			response.TotalMatches = 2
		}},
		{name: "missing-returned-match", change: func(response *discovery.Response, _ *discovery.NameBinding, _ *bool) {
			response.Returned = 0
		}},
		{name: "wrong-discovered-agent", change: func(response *discovery.Response, _ *discovery.NameBinding, _ *bool) {
			response.Results[0].AgentID = "other-agent"
		}},
		{name: "wrong-discovered-name", change: func(response *discovery.Response, _ *discovery.NameBinding, _ *bool) {
			response.Results[0].Name = "other-worker.example"
		}},
		{name: "wrong-discovered-capability", change: func(response *discovery.Response, _ *discovery.NameBinding, _ *bool) {
			response.Results[0].Capabilities = []string{"other"}
		}},
		{name: "unexpected-extra-capability", change: func(response *discovery.Response, _ *discovery.NameBinding, _ *bool) {
			response.Results[0].Capabilities = []string{"sum", "other"}
		}},
		{name: "missing-name-has-no-fallback", change: func(_ *discovery.Response, _ *discovery.NameBinding, found *bool) {
			*found = false
		}},
		{name: "wrong-resolved-agent", change: func(_ *discovery.Response, binding *discovery.NameBinding, _ *bool) {
			binding.AgentID = "other-agent"
		}},
		{name: "wrong-resolved-name", change: func(_ *discovery.Response, binding *discovery.NameBinding, _ *bool) {
			binding.Name = "other-worker.example"
		}},
		{name: "unapproved-endpoint", change: func(_ *discovery.Response, binding *discovery.NameBinding, _ *bool) {
			binding.Endpoint = "https://127.0.0.1:9444"
		}},
		{name: "wrong-resolved-capability", change: func(_ *discovery.Response, binding *discovery.NameBinding, _ *bool) {
			binding.Capabilities = []string{"other"}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := discovery.Response{
				TotalMatches: 1, Returned: 1,
				Results: []discovery.Match{{AgentID: target.AgentID, Name: target.Name, Capabilities: []string{target.Capability}}},
			}
			binding := discovery.NameBinding{
				AgentID: target.AgentID, Name: target.Name, Endpoint: target.Endpoint, Capabilities: []string{target.Capability}, Version: 1,
			}
			found := true
			if test.change != nil {
				test.change(&response, &binding, &found)
			}
			resolvedName := ""
			got, err := selectDiscoveredTarget(response, func(name string) (discovery.NameBinding, bool) {
				resolvedName = name
				return binding, found
			}, target)
			if (err == nil) != test.valid {
				t.Fatalf("selectDiscoveredTarget() = %+v, %v, want valid=%v", got, err, test.valid)
			}
			if test.valid && (resolvedName != target.Name || got.Endpoint != binding.Endpoint || got.AgentID != target.AgentID) {
				t.Fatalf("selected target was not the resolved binding: %+v (name %q)", got, resolvedName)
			}
			if !test.valid && got.Endpoint != "" {
				t.Fatalf("rejected selection exposed a fallback endpoint: %q", got.Endpoint)
			}
		})
	}
}

func TestSelectDiscoveredTargetRejectsMissingResolver(t *testing.T) {
	response := discovery.Response{TotalMatches: 1, Returned: 1, Results: []discovery.Match{{AgentID: roleAgentB}}}
	if _, err := selectDiscoveredTarget(response, nil, targetConfig{AgentID: roleAgentB}); err == nil {
		t.Fatal("missing resolver was accepted")
	}
}
