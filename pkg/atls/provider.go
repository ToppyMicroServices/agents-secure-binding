// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package atls

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/ea"
	eaattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/eaattestation"
)

// CertificateProvider builds leaf extensions for accepted aTLS call sites.
// In the EA-based implementation it provides the leaf certificate-entry extensions
// carried in the exported authenticator instead of generating TLS certificates.
type CertificateProvider interface {
	BuildLeafExtensions(st *tls.ConnectionState, req *ea.AuthenticatorRequest, leaf *x509.Certificate) ([]ea.Extension, error)
}

type provider struct {
	evidenceSource eaattestation.EvidenceSource
}

func NewProvider(evidenceSource eaattestation.EvidenceSource) (CertificateProvider, error) {
	if evidenceSource == nil {
		return nil, fmt.Errorf("atls: missing evidence source")
	}
	return &provider{evidenceSource: evidenceSource}, nil
}

func (p *provider) BuildLeafExtensions(st *tls.ConnectionState, req *ea.AuthenticatorRequest, leaf *x509.Certificate) ([]ea.Extension, error) {
	if st == nil || req == nil || leaf == nil {
		return nil, fmt.Errorf("atls: missing state, request, or leaf certificate")
	}
	exportedValue, aikPubHash, binding, err := eaattestation.ComputeBinding(st, eaattestation.ExporterLabelAttestation, req.Context, leaf)
	if err != nil {
		return nil, err
	}

	reportData := sha512.Sum512(binding)
	nonceBytes := sha256.Sum256(exportedValue)
	var nonce [32]byte
	copy(nonce[:], nonceBytes[:])

	result, err := p.evidenceSource.GetEvidence(context.Background(), eaattestation.EvidenceRequest{
		ReportData: reportData,
		Nonce:      nonce,
	})
	if err != nil {
		return nil, fmt.Errorf("atls: failed to fetch attestation evidence: %w", err)
	}

	payloadBytes, err := eaattestation.MarshalPayload(eaattestation.Payload{
		Version:   1,
		MediaType: result.MediaType,
		Evidence:  result.Evidence,
		Binder: eaattestation.AttestationBinder{
			ExporterLabel: eaattestation.ExporterLabelAttestation,
			AIKPubHash:    aikPubHash,
			Binding:       binding,
		},
	})
	if err != nil {
		return nil, err
	}

	ext, err := ea.CMWAttestationDataExtension(payloadBytes)
	if err != nil {
		return nil, err
	}
	return []ea.Extension{ext}, nil
}
