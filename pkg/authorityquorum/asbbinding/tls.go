// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	eaattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/eaattestation"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/authorityquorum"
)

var ErrTLSRequired = errors.New("authorityquorum asbbinding: verified TLS 1.3 client connection required")

// BindingFromTLS derives expected ASB values from the TLS connection accepted
// by the application. Peer-supplied headers are not valid inputs.
func BindingFromTLS(
	state *tls.ConnectionState,
	digest authorityquorum.Digest,
	nonce string,
) (identitypolicy.Binding, error) {
	if state == nil || !state.HandshakeComplete || state.Version != tls.VersionTLS13 ||
		len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 ||
		len(state.PeerCertificates) == 0 || strings.TrimSpace(nonce) == "" {
		return identitypolicy.Binding{}, ErrTLSRequired
	}
	leaf := state.PeerCertificates[0]
	if leaf == nil || state.VerifiedChains[0][0] == nil ||
		!bytes.Equal(leaf.Raw, state.VerifiedChains[0][0].Raw) {
		return identitypolicy.Binding{}, ErrTLSRequired
	}
	exported, err := state.ExportKeyingMaterial(
		eaattestation.ExporterLabelAttestation,
		authorityquorum.RequestContext(digest),
		eaattestation.ExportedAttestationValueLen,
	)
	if err != nil {
		return identitypolicy.Binding{}, fmt.Errorf("authorityquorum asbbinding: derive TLS exporter: %w", err)
	}
	leafBytes, err := eaattestation.PublicKeyBytes(leaf)
	if err != nil {
		return identitypolicy.Binding{}, fmt.Errorf("authorityquorum asbbinding: encode client public key: %w", err)
	}
	leafHash := sha256.Sum256(leafBytes)
	exporterHash := sha256.Sum256(exported)
	return identitypolicy.Binding{
		LeafPublicKeySHA256:  hex.EncodeToString(leafHash[:]),
		TLSExporterSHA256:    hex.EncodeToString(exporterHash[:]),
		RequestContextSHA256: authorityquorum.RequestContextSHA256(digest),
		Nonce:                nonce,
	}, nil
}

// ServerTLSConfig requires verified client certificates and TLS 1.3. The
// application must terminate TLS with this configuration before deriving a
// binding or accepting an approval.
func ServerTLSConfig(certificate tls.Certificate, clientCAs *x509.CertPool) (*tls.Config, error) {
	if len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
		return nil, errors.New("authorityquorum asbbinding: missing server certificate")
	}
	if clientCAs == nil {
		return nil, errors.New("authorityquorum asbbinding: missing client CA pool")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: clientCAs, NextProtos: []string{"h2", "http/1.1"},
	}, nil
}
