// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"net/netip"
	"testing"
)

func TestNetworkPolicyValidate(t *testing.T) {
	tests := []struct {
		name   string
		policy *NetworkPolicy
		valid  bool
	}{
		{name: "default-loopback", valid: true},
		{name: "empty", policy: &NetworkPolicy{}},
		{name: "invalid-prefix", policy: &NetworkPolicy{AllowedCIDRs: []netip.Prefix{{}}}},
		{name: "ipv4", policy: testNetworkPolicy("10.20.30.0/24"), valid: true},
		{name: "ipv6", policy: testNetworkPolicy("fd12:3456:789a::/48"), valid: true},
		{name: "public-network", policy: testNetworkPolicy("192.0.2.0/24", "2001:db8::/32"), valid: true},
		{name: "host-networks", policy: testNetworkPolicy("192.0.2.7/32", "2001:db8::7/128"), valid: true},
		{name: "ipv4-default-route", policy: testNetworkPolicy("0.0.0.0/0")},
		{name: "ipv6-default-route", policy: testNetworkPolicy("::/0")},
		{name: "ipv4-host-bits", policy: testNetworkPolicy("10.20.30.7/24")},
		{name: "ipv6-host-bits", policy: testNetworkPolicy("fd12:3456:789a::7/48")},
		{name: "mapped-ipv4-prefix", policy: testNetworkPolicy("::ffff:10.20.30.0/120")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.policy.validate(); (err == nil) != test.valid {
				t.Fatalf("validate() = %v, want valid=%v", err, test.valid)
			}
		})
	}
}

func TestNetworkPolicyEndpoint(t *testing.T) {
	lan := testNetworkPolicy("10.20.30.0/24", "fd12:3456:789a::/48", "192.0.2.0/24")
	tests := []struct {
		name      string
		policy    *NetworkPolicy
		address   string
		allowZero bool
		valid     bool
	}{
		{name: "loopback-ipv4", address: "127.0.0.1:9443", valid: true},
		{name: "loopback-range", address: "127.0.0.2:9443", valid: true},
		{name: "loopback-ipv6", address: "[::1]:9443", valid: true},
		{name: "loopback-mapped", address: "[::ffff:127.0.0.1]:9443", valid: true},
		{name: "localhost", address: "localhost:9443", valid: true},
		{name: "loopback-dynamic-port", address: "127.0.0.1:0", allowZero: true, valid: true},
		{name: "localhost-dynamic-port", address: "localhost:0", allowZero: true, valid: true},
		{name: "loopback-zero-port-rejected", address: "127.0.0.1:0"},
		{name: "localhost-zero-port-rejected", address: "localhost:0"},
		{name: "loopback-mode-lan", address: "10.20.30.7:9443"},
		{name: "ipv4-allowed", policy: lan, address: "10.20.30.7:9443", valid: true},
		{name: "ipv4-mapped-allowed", policy: lan, address: "[::ffff:10.20.30.7]:9443", valid: true},
		{name: "ipv6-allowed", policy: lan, address: "[fd12:3456:789a::7]:9443", valid: true},
		{name: "public-allowed", policy: lan, address: "192.0.2.7:65535", valid: true},
		{name: "ipv4-outside", policy: lan, address: "10.20.31.7:9443"},
		{name: "ipv6-outside", policy: lan, address: "[fd12:3456:789b::7]:9443"},
		{name: "loopback-not-implicit", policy: lan, address: "127.0.0.1:9443"},
		{name: "loopback-explicit", policy: testNetworkPolicy("127.0.0.0/8"), address: "127.0.0.1:9443", valid: true},
		{name: "lan-zero-port-rejected", policy: lan, address: "10.20.30.7:0", allowZero: true},
		{name: "dns-host-rejected", policy: lan, address: "node.example.test:9443"},
		{name: "localhost-rejected-in-lan", policy: lan, address: "localhost:9443"},
		{name: "zone-rejected", policy: lan, address: "[fd12:3456:789a::7%en0]:9443"},
		{name: "wildcard-ipv4", policy: testNetworkPolicy("0.0.0.0/1"), address: "0.0.0.0:9443"},
		{name: "wildcard-ipv6", policy: testNetworkPolicy("::/1"), address: "[::]:9443"},
		{name: "wildcard-mapped", policy: testNetworkPolicy("0.0.0.0/1"), address: "[::ffff:0.0.0.0]:9443"},
		{name: "multicast-ipv4", policy: testNetworkPolicy("224.0.0.0/4"), address: "224.0.0.7:9443"},
		{name: "multicast-ipv6", policy: testNetworkPolicy("ff00::/8"), address: "[ff02::7]:9443"},
		{name: "broadcast-ipv4", policy: testNetworkPolicy("255.255.255.255/32"), address: "255.255.255.255:9443"},
		{name: "invalid-policy", policy: &NetworkPolicy{}, address: "10.20.30.7:9443"},
		{name: "empty-host", address: ":9443"},
		{name: "missing-port", address: "127.0.0.1"},
		{name: "oversized-port", address: "127.0.0.1:65536"},
		{name: "negative-port", address: "127.0.0.1:-1"},
		{name: "padded-port", address: "127.0.0.1:09443"},
		{name: "localhost-padded-port", address: "localhost:09443"},
		{name: "localhost-signed-port", address: "localhost:+9443"},
		{name: "service-port", address: "localhost:https"},
		{name: "trailing-dot-host", address: "localhost.:9443"},
		{name: "bracketed-localhost", address: "[localhost]:9443"},
		{name: "noncanonical-ipv6", address: "[0:0:0:0:0:0:0:1]:9443"},
		{name: "uppercase-ipv6", policy: lan, address: "[FD12:3456:789a::7]:9443"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.policy.validateEndpoint(test.address, test.allowZero); (err == nil) != test.valid {
				t.Fatalf("validateEndpoint(%q) = %v, want valid=%v", test.address, err, test.valid)
			}
		})
	}
}

func TestNetworkPolicyRemoteAddress(t *testing.T) {
	lan := testNetworkPolicy("10.20.30.0/24", "fd12:3456:789a::/48")
	tests := []struct {
		name    string
		policy  *NetworkPolicy
		address string
		allowed bool
	}{
		{name: "default-loopback", address: "127.0.0.1:43210", allowed: true},
		{name: "default-ipv6", address: "[::1]:43210", allowed: true},
		{name: "default-mapped", address: "[::ffff:127.0.0.1]:43210", allowed: true},
		{name: "default-lan-rejected", address: "10.20.30.7:43210"},
		{name: "lan-ipv4", policy: lan, address: "10.20.30.7:43210", allowed: true},
		{name: "lan-mapped", policy: lan, address: "[::ffff:10.20.30.7]:43210", allowed: true},
		{name: "lan-ipv6", policy: lan, address: "[fd12:3456:789a::7]:43210", allowed: true},
		{name: "lan-outside", policy: lan, address: "10.20.31.7:43210"},
		{name: "dns-rejected", address: "localhost:43210"},
		{name: "zero-port", address: "127.0.0.1:0"},
		{name: "invalid-address", address: "127.0.0.1"},
		{name: "zone-rejected", policy: lan, address: "[fd12:3456:789a::7%en0]:43210"},
		{name: "invalid-policy", policy: testNetworkPolicy("0.0.0.0/0"), address: "10.20.30.7:43210"},
		{name: "multicast", policy: testNetworkPolicy("224.0.0.0/4"), address: "224.0.0.7:43210"},
		{name: "unspecified", policy: testNetworkPolicy("::/1"), address: "[::]:43210"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.policy.allowsRemoteAddress(test.address); got != test.allowed {
				t.Fatalf("allowsRemoteAddress(%q) = %v, want %v", test.address, got, test.allowed)
			}
		})
	}
}

func TestNetworkPolicyClone(t *testing.T) {
	var defaultPolicy *NetworkPolicy
	if defaultPolicy.clone() != nil {
		t.Fatal("cloning the default policy should preserve nil")
	}
	original := testNetworkPolicy("10.20.30.0/24")
	clone := original.clone()
	original.AllowedCIDRs[0] = netip.MustParsePrefix("192.0.2.0/24")
	if err := clone.validateEndpoint("10.20.30.7:9443", false); err != nil {
		t.Fatalf("caller mutation changed the cloned policy: %v", err)
	}
	if clone.validateEndpoint("192.0.2.7:9443", false) == nil {
		t.Fatal("cloned policy unexpectedly accepted the caller's replacement CIDR")
	}
}

func testNetworkPolicy(prefixes ...string) *NetworkPolicy {
	policy := &NetworkPolicy{AllowedCIDRs: make([]netip.Prefix, len(prefixes))}
	for index, prefix := range prefixes {
		policy.AllowedCIDRs[index] = netip.MustParsePrefix(prefix)
	}
	return policy
}
