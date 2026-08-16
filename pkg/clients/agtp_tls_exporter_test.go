// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package clients

import (
	"errors"
	"testing"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
)

func TestAGTPObservedIdentityRejectsMockedTLSExporterWithRealState(t *testing.T) {
	accepted := realTLSAttestationResultForAGTP(t)
	validation := *accepted.validation
	attestation := *accepted.validation.Attestation
	attestation.Binding.ExportedValue = []byte("mocked-exporter")
	validation.Attestation = &attestation

	fixture := newClientTestAGTPFixture(t, &validation)
	grantToken := fixture.issueGrant(t, nil)

	mockedBinding, err := atls.IdentityBindingFromValidation(&validation)
	if err != nil {
		t.Fatalf("IdentityBindingFromValidation() error = %v", err)
	}
	realBinding, err := atls.IdentityBindingFromConnectionState(&accepted.state, accepted.validation)
	if err != nil {
		t.Fatalf("IdentityBindingFromConnectionState() error = %v", err)
	}
	if mockedBinding.TLSExporterSHA256 == realBinding.TLSExporterSHA256 {
		t.Fatal("mocked validation exporter unexpectedly matched real TLS exporter")
	}
	bindingToken := fixture.agent.issueSessionBinding(t, fixture.now, IdentityGrantHash(grantToken), mockedBinding, map[string]any{
		"jti":   "mocked-exporter-binding",
		"nonce": "mocked-exporter-nonce",
	})

	cfg := fixture.config(grantToken, bindingToken)
	observedIdentity, err := cfg.AGTPObservedIdentity()
	if err != nil {
		t.Fatalf("AGTPObservedIdentity() error = %v", err)
	}
	_, err = observedIdentity(&accepted.state, &validation)
	if !errors.Is(err, identitypolicy.ErrMismatch) {
		t.Fatalf("observed identity error = %v, want %v", err, identitypolicy.ErrMismatch)
	}
}
