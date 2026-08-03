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

	eaattestation "github.com/thinksyncs/agents-secure-binding/pkg/atls/eaattestation"
	"github.com/thinksyncs/agents-secure-binding/pkg/atls/identitypolicy"
)

var ErrInvalidAcceptedBinding = errors.New("production: invalid accepted binding input")

// DirectAgentV1ExporterLabel is fixed by the supported Direct-Agent v1
// production profile. Peers cannot select or override it.
const DirectAgentV1ExporterLabel = eaattestation.ExporterLabelAttestation

// BindingFromTLS derives the verifier-local expected binding from an accepted
// TLS 1.3 session, the authenticated peer certificate, exact canonical action
// bytes, and a verifier-issued nonce.
func BindingFromTLS(state *tls.ConnectionState, peerLeaf *x509.Certificate, actionContext []byte, nonce string) (identitypolicy.Binding, error) {
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
	attestationBinder := sha256.Sum256(attestationBinding)
	return identitypolicy.Binding{
		LeafPublicKeySHA256:     hex.EncodeToString(leafKey[:]),
		TLSExporterSHA256:       hex.EncodeToString(exporter[:]),
		RequestContextSHA256:    hex.EncodeToString(requestContext[:]),
		AttestationBinderSHA256: hex.EncodeToString(attestationBinder[:]),
		Nonce:                   nonce,
	}, nil
}
