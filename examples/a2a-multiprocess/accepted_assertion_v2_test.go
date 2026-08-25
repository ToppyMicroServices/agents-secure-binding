// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"
)

func TestAcceptedPeerCredentialExpiryV2UsesEarliestVerifiedPathCertificate(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	leaf := &x509.Certificate{NotAfter: now.Add(3 * time.Minute)}
	intermediate := &x509.Certificate{NotAfter: now.Add(time.Minute)}
	root := &x509.Certificate{NotAfter: now.Add(2 * time.Minute)}
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf, intermediate, root}},
	}

	expiresAt, err := acceptedPeerCredentialExpiryV2(state, now)
	if err != nil {
		t.Fatal(err)
	}
	if !expiresAt.Equal(intermediate.NotAfter) {
		t.Fatalf("expiry = %v, want earliest path expiry %v", expiresAt, intermediate.NotAfter)
	}
	if _, err := acceptedPeerCredentialExpiryV2(state, intermediate.NotAfter); err == nil {
		t.Fatal("certificate path was accepted exactly at expiry")
	}
}

func TestAcceptedPeerCredentialExpiryV2RequiresVerifiedPath(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{NotAfter: now.Add(time.Minute)}}}
	if _, err := acceptedPeerCredentialExpiryV2(state, now); err == nil {
		t.Fatal("unverified peer certificate was accepted")
	}
}
