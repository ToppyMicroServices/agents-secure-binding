// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package production

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"

	eaattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/eaattestation"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
)

var ErrInvalidAcceptedBinding = errors.New("production: invalid accepted binding input")

// DirectAgentV1ExporterLabel is fixed by the supported Direct-Agent v1
// production profile. Peers cannot select or override it.
const DirectAgentV1ExporterLabel = eaattestation.ExporterLabelAttestation

// BindingFromTLS derives the verifier-local expected binding from an accepted
// TLS 1.3 session, the authenticated peer certificate, exact canonical action
// bytes, and a verifier-issued nonce.
func BindingFromTLS(state *tls.ConnectionState, peerLeaf *x509.Certificate, actionContext []byte, nonce string) (identitypolicy.Binding, error) {
	return bindingFromTLS(state, peerLeaf, actionContext, nonce, true)
}

// SoftwareBindingFromTLS derives the verifier-local TLS and action binding for
// SoftwareOnlyProfile. It intentionally omits attestation_binder_sha256 so an
// attested proof cannot be reinterpreted as software-only acceptance.
func SoftwareBindingFromTLS(state *tls.ConnectionState, peerLeaf *x509.Certificate, actionContext []byte, nonce string) (identitypolicy.Binding, error) {
	return bindingFromTLS(state, peerLeaf, actionContext, nonce, false)
}

func bindingFromTLS(state *tls.ConnectionState, peerLeaf *x509.Certificate, actionContext []byte, nonce string, includeAttestation bool) (identitypolicy.Binding, error) {
	if state == nil || peerLeaf == nil || len(actionContext) == 0 || strings.TrimSpace(nonce) == "" {
		return identitypolicy.Binding{}, ErrInvalidAcceptedBinding
	}
	exporterContext := bytes.Join([][]byte{
		[]byte("asb.direct-agent.production.v1"),
		[]byte(nonce),
		actionContext,
	}, []byte{0})
	exported, _, attestationBinding, err := eaattestation.ComputeBinding(
		state,
		DirectAgentV1ExporterLabel,
		exporterContext,
		peerLeaf,
	)
	if err != nil {
		return identitypolicy.Binding{}, err
	}
	leafKey := sha256.Sum256(peerLeaf.RawSubjectPublicKeyInfo)
	exporter := sha256.Sum256(exported)
	requestContext := sha256.Sum256(actionContext)
	binding := identitypolicy.Binding{
		LeafPublicKeySHA256:  hex.EncodeToString(leafKey[:]),
		TLSExporterSHA256:    hex.EncodeToString(exporter[:]),
		RequestContextSHA256: hex.EncodeToString(requestContext[:]),
		Nonce:                nonce,
	}
	if includeAttestation {
		attestationBinder := sha256.Sum256(attestationBinding)
		binding.AttestationBinderSHA256 = hex.EncodeToString(attestationBinder[:])
	}
	return binding, nil
}
