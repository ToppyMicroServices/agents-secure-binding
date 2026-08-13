// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"strings"
	"time"
)

// ServerTLSConfig returns the TLS configuration required by Ingress. Client
// certificates are mandatory and verified against clientCAs; TLS 1.2,
// plaintext, and 0-RTT are not accepted.
func ServerTLSConfig(certificate tls.Certificate, clientCAs *x509.CertPool) (*tls.Config, error) {
	if len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
		return nil, errors.New("asbbinding ingress: missing server certificate")
	}
	if clientCAs == nil {
		return nil, errors.New("asbbinding ingress: missing client CA pool")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}

// NewTLSServer constructs the direct TLS-terminating HTTP server for this
// ingress. Call ListenAndServeTLS with empty certificate paths because the
// certificate is already configured here.
func (s *Ingress) NewTLSServer(addr string, certificate tls.Certificate, clientCAs *x509.CertPool) (*http.Server, error) {
	if strings.TrimSpace(addr) == "" {
		return nil, errors.New("asbbinding ingress: missing listen address")
	}
	handler, err := s.Handler()
	if err != nil {
		return nil, err
	}
	tlsConfig, err := ServerTLSConfig(certificate, clientCAs)
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}, nil
}
