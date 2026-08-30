// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ToppyMicroServices/agents-secure-binding/integrations/cocos/platformmodule"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	sevabi "github.com/google/go-sev-guest/abi"
	sevcheck "github.com/google/go-sev-guest/proto/check"
	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxcheck "github.com/google/go-tdx-guest/proto/checkconfig"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const testExpectedEATIssuer = "test-attestation-service"

func TestConfigureAttestationModuleDisabled(t *testing.T) {
	cfg := &clients.AttestedClientConfig{}
	if err := configureAttestationModule(cfg, attestationModuleConfig{}); err != nil {
		t.Fatal(err)
	}
	if cfg.AttestationVerificationPolicy.RequiresAttestation() {
		t.Fatal("disabled attested TLS must not configure a platform verifier")
	}
}

func TestConfigureAttestationModuleRequiresExplicitPlatform(t *testing.T) {
	cfg := &clients.AttestedClientConfig{AttestedTLS: true, AttestationPolicy: testAttestationPolicy(t)}
	if err := configureAttestationModule(cfg, attestationModuleConfig{}); !errors.Is(err, platformmodule.ErrUnsupportedPlatform) {
		t.Fatalf("error = %v, want ErrUnsupportedPlatform", err)
	}
}

func TestConfigureAttestationModuleRejectsLegacyAppraisers(t *testing.T) {
	for _, platform := range []platformmodule.Platform{
		"snp-vtpm",
		"vtpm",
		"azure",
	} {
		t.Run(string(platform), func(t *testing.T) {
			cfg := &clients.AttestedClientConfig{AttestedTLS: true, AttestationPolicy: testAttestationPolicy(t)}
			err := configureAttestationModule(cfg, attestationModuleConfig{Name: string(platform)})
			if !errors.Is(err, platformmodule.ErrUnsupportedPlatform) {
				t.Fatalf("error = %v, want ErrUnsupportedPlatform", err)
			}
		})
	}
}

func TestConfigureAttestationModulePinsSNP(t *testing.T) {
	cfg := &clients.AttestedClientConfig{AttestedTLS: true, AttestationPolicy: testAttestationPolicy(t)}
	if err := configureAttestationModule(cfg, attestationModuleConfig{
		Name:                   string(platformmodule.PlatformSNP),
		PlatformPolicyPath:     testSNPPlatformPolicy(t),
		EATVerificationKeyPath: testEATVerificationKey(t),
		ExpectedEATIssuer:      testExpectedEATIssuer,
	}); err != nil {
		t.Fatal(err)
	}
	if !cfg.AttestationVerificationPolicy.RequiresAttestation() {
		t.Fatal("expected an injected attestation verifier")
	}
}

func TestConfigureAttestationModulePinsTDX(t *testing.T) {
	cfg := &clients.AttestedClientConfig{AttestedTLS: true, AttestationPolicy: testAttestationPolicy(t)}
	if err := configureAttestationModule(cfg, attestationModuleConfig{
		Name:                   string(platformmodule.PlatformTDX),
		PlatformPolicyPath:     testTDXPlatformPolicy(t),
		EATVerificationKeyPath: testEATVerificationKey(t),
		ExpectedEATIssuer:      testExpectedEATIssuer,
	}); err != nil {
		t.Fatal(err)
	}
	if !cfg.AttestationVerificationPolicy.RequiresAttestation() {
		t.Fatal("expected an injected TDX attestation verifier")
	}
}

func TestConfigureAttestationModuleRequiresEATTrust(t *testing.T) {
	cfg := &clients.AttestedClientConfig{AttestedTLS: true, AttestationPolicy: testAttestationPolicy(t)}
	err := configureAttestationModule(cfg, attestationModuleConfig{
		Name:               string(platformmodule.PlatformSNP),
		PlatformPolicyPath: testSNPPlatformPolicy(t),
		ExpectedEATIssuer:  testExpectedEATIssuer,
	})
	if err == nil {
		t.Fatal("expected a missing EAT verification key to fail")
	}
}

func testAttestationPolicy(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.corim")
	if err := os.WriteFile(path, []byte("test policy placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testEATVerificationKey(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "eat-public.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testSNPPlatformPolicy(t *testing.T) string {
	t.Helper()
	return writePlatformPolicy(t, "snp-policy.json", &sevcheck.Config{
		RootOfTrust: &sevcheck.RootOfTrust{CheckCrl: true},
		Policy: &sevcheck.Policy{
			Policy:  sevabi.SnpPolicyToBytes(sevabi.SnpPolicy{}),
			Product: sevabi.DefaultSevProduct(),
			Vmpl:    wrapperspb.UInt32(0),
		},
	})
}

func testTDXPlatformPolicy(t *testing.T) string {
	t.Helper()
	return writePlatformPolicy(t, "tdx-policy.json", &tdxcheck.Config{
		RootOfTrust: &tdxcheck.RootOfTrust{CheckCrl: true, GetCollateral: true},
		Policy: &tdxcheck.Policy{
			HeaderPolicy: &tdxcheck.HeaderPolicy{},
			TdQuoteBodyPolicy: &tdxcheck.TDQuoteBodyPolicy{
				TdAttributes: make([]byte, tdxabi.TdAttributesSize),
			},
		},
	})
}

func writePlatformPolicy(t *testing.T, name string, policy proto.Message) string {
	t.Helper()
	payload, err := protojson.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
