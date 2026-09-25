// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func TestDemoNetworkRequiresExactPrivateHosts(t *testing.T) {
	config := processConfig{AllowedCIDRs: []string{"10.203.0.11/32", "10.203.0.12/32", "10.203.0.13/32"}}
	for _, test := range []struct {
		endpoint string
		valid    bool
	}{
		{"10.203.0.11:9443", true},
		{"10.203.0.13:9444", true},
		{"10.203.0.14:9443", false},
		{"127.0.0.1:9443", false},
		{"0.0.0.0:9443", false},
		{"10.203.0.11:0", false},
		{"example.test:9443", false},
	} {
		if err := config.validateEndpoint(test.endpoint); (err == nil) != test.valid {
			t.Errorf("endpoint %q: error=%v, want valid=%v", test.endpoint, err, test.valid)
		}
	}
	for _, invalid := range []string{"10.203.0.0/24", "0.0.0.0/0", "192.0.2.1/32", "127.0.0.1/32", "10.203.0.12/32", "invalid"} {
		changed := processConfig{AllowedCIDRs: append([]string(nil), config.AllowedCIDRs...)}
		changed.AllowedCIDRs[0] = invalid
		if _, err := changed.networkPrefixes(); err == nil {
			t.Errorf("accepted route %q", invalid)
		}
	}
	if err := (processConfig{}).validateEndpoint("10.203.0.11:9443"); err == nil {
		t.Fatal("default demo accepted a non-loopback address")
	}
}
