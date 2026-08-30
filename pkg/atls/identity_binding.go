// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package atls

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/ea"
	eaattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/eaattestation"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	internaltransport "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/internal_transport"
)

// IdentityBindingFromConnectionState derives identity-policy binding values
// from the accepted TLS session and aTLS validation result.
func IdentityBindingFromConnectionState(st *tls.ConnectionState, validation *ea.ValidationResult) (identitypolicy.Binding, error) {
	if st == nil {
		return identitypolicy.Binding{}, fmt.Errorf("atls: missing TLS connection state")
	}
	if !st.HandshakeComplete {
		return identitypolicy.Binding{}, fmt.Errorf("atls: TLS handshake is not complete")
	}
	if st.Version != tls.VersionTLS13 {
		return identitypolicy.Binding{}, fmt.Errorf("atls: expected TLS 1.3 connection")
	}
	binding, err := internaltransport.ExpectedIdentityBinding(validation)
	if err != nil {
		return identitypolicy.Binding{}, err
	}
	exported, _, err := eaattestation.ExportAttestationValue(st, eaattestation.ExporterLabelAttestation, validation.Context)
	if err != nil {
		return identitypolicy.Binding{}, err
	}
	exporterHash := sha256.Sum256(exported)
	binding.TLSExporterSHA256 = hex.EncodeToString(exporterHash[:])
	return binding, nil
}
