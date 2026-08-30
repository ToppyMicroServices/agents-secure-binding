// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package tls

import (
	"crypto/tls"
	"crypto/x509"
	"os"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/errors"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation"
)

// Security represents the type of TLS security configuration.
type Security int

const (
	WithoutTLS Security = iota
	WithTLS
	WithMTLS
	WithATLS
	WithMATLS
)

// String returns a human-readable representation of the security level.
func (s Security) String() string {
	switch s {
	case WithTLS:
		return "with TLS"
	case WithMTLS:
		return "with mTLS"
	case WithATLS:
		return "with aTLS"
	case WithMATLS:
		return "with maTLS"
	case WithoutTLS:
		return "without TLS"
	default:
		return "without TLS"
	}
}

const AttestationReportSize = 0x4A0

var (
	ErrFailedToLoadClientCertKey  = errors.New("failed to load client certificate and key")
	ErrFailedToLoadRootCA         = errors.New("failed to load root ca file")
	ErrMissingRootCA              = errors.New("server CA file is required")
	errAttestationPolicyIrregular = errors.New("attestation policy file is not a regular file")
)

// Result contains the result of TLS configuration.
type Result struct {
	Config   *tls.Config
	Security Security
}

// LoadBasicConfig loads standard TLS configuration (TLS/mTLS).
func LoadBasicConfig(serverCAFile, clientCert, clientKey string) (*Result, error) {
	if serverCAFile == "" && clientCert == "" && clientKey == "" {
		return &Result{Config: nil, Security: WithoutTLS}, nil
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	security := WithoutTLS

	if serverCAFile != "" {
		rootCAs, err := loadRootCAs(serverCAFile)
		if err != nil {
			return nil, errors.Wrap(ErrFailedToLoadRootCA, err)
		}
		tlsConfig.RootCAs = rootCAs
		security = WithTLS
	}

	if clientCert != "" || clientKey != "" {
		certificate, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			return nil, errors.Wrap(ErrFailedToLoadClientCertKey, err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
		security = WithMTLS
	}

	return &Result{Config: tlsConfig, Security: security}, nil
}

// LoadATLSConfig configures Attested TLS.
func LoadATLSConfig(attestationPolicy, serverCAFile, clientCert, clientKey string) (*Result, error) {
	if err := validateRegularFile(attestationPolicy); err != nil {
		return nil, err
	}
	if serverCAFile == "" {
		return nil, ErrMissingRootCA
	}

	rootCAs, err := loadRootCAs(serverCAFile)
	if err != nil {
		return nil, err
	}

	attestation.AttestationPolicyPath = attestationPolicy
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    rootCAs,
	}

	security := WithMATLS
	if clientCert != "" || clientKey != "" {
		certificate, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			return nil, errors.Wrap(ErrFailedToLoadClientCertKey, err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}

	return &Result{Config: tlsConfig, Security: security}, nil
}

func validateRegularFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return errors.Wrap(errors.New("failed to stat attestation policy file"), err)
	}
	if !info.Mode().IsRegular() {
		return errAttestationPolicyIrregular
	}
	return nil
}

// loadRootCAs loads root CA certificates from a file.
func loadRootCAs(serverCAFile string) (*x509.CertPool, error) {
	certPEM, err := os.ReadFile(serverCAFile)
	if err != nil {
		return nil, errors.Wrap(errors.New("failed to read certificate file"), err)
	}

	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(certPEM) {
		return nil, errors.New("failed to append root ca to tls.Config")
	}
	return rootCAs, nil
}
