// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func TestLoopbackProxyAddress(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		if _, err := loopbackProxyAddress(host, "3128"); err != nil {
			t.Fatalf("loopback host %q rejected: %v", host, err)
		}
	}
	for _, host := range []string{"0.0.0.0", "::", "192.0.2.1", "localhost"} {
		if _, err := loopbackProxyAddress(host, "3128"); err == nil {
			t.Fatalf("non-literal or non-loopback host %q accepted", host)
		}
	}
}
