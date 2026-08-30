// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

// Package atls exposes the accepted TLS and exported-authenticator binding
// helpers used by the Direct-Agent verifier surface.
//
// The package does not verify TLS itself. It relies on an accepted TLS 1.3
// connection from the deployment TLS stack and derives profile binding inputs
// from that connection and the accepted endpoint material.
package atls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/ea"
	eaattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/eaattestation"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	internaltransport "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/internal_transport"
)

type Conn = internaltransport.Conn

type Listener = internaltransport.Listener

type ClientConfig = internaltransport.ClientConfig

type ServerConfig = internaltransport.ServerConfig

// ObservedIdentityFunc extracts a session-bound identity assertion after aTLS validation.
type ObservedIdentityFunc = internaltransport.ObservedIdentityFunc

type AuthenticatorRequest = ea.AuthenticatorRequest

// ErrMissingObservedIdentity reports an enabled identity policy without a
// trusted observed-identity source.
var ErrMissingObservedIdentity = internaltransport.ErrMissingObservedIdentity

func Dial(network, address string, cfg *ClientConfig) (*Conn, error) {
	return internaltransport.Dial(network, address, cfg)
}

func DialContext(ctx context.Context, network, address string, cfg *ClientConfig) (*Conn, error) {
	return internaltransport.DialContext(ctx, network, address, cfg)
}

func DialWithDialer(dialer *net.Dialer, network, address string, cfg *ClientConfig) (*Conn, error) {
	return internaltransport.DialWithDialer(dialer, network, address, cfg)
}

func Client(tlsConn *tls.Conn, cfg *ClientConfig) (*Conn, error) {
	return internaltransport.Client(tlsConn, cfg)
}

func Server(tlsConn *tls.Conn, cfg *ServerConfig) (*Conn, error) {
	return internaltransport.Server(tlsConn, cfg)
}

func Listen(network, address string, cfg *ServerConfig) (*Listener, error) {
	return internaltransport.Listen(network, address, cfg)
}

func NewRequest(context []byte) (*ea.AuthenticatorRequest, error) {
	sigExt, err := ea.SignatureAlgorithmsExtension([]uint16{uint16(tls.ECDSAWithP256AndSHA256)})
	if err != nil {
		return nil, err
	}
	return &ea.AuthenticatorRequest{
		Type:    ea.HandshakeTypeClientCertificateRequest,
		Context: context,
		Extensions: []ea.Extension{
			sigExt,
			ea.CMWAttestationOfferExtension(),
		},
	}, nil
}

func NewRandomRequest(contextLen int) (*ea.AuthenticatorRequest, error) {
	context, err := ea.NewRandomContext(contextLen)
	if err != nil {
		return nil, err
	}
	return NewRequest(context)
}

func VerifyOptionsFromTLSConfig(cfg *tls.Config) *x509.VerifyOptions {
	if cfg == nil || cfg.InsecureSkipVerify || cfg.RootCAs == nil {
		return nil
	}
	return &x509.VerifyOptions{Roots: cfg.RootCAs}
}

func VerificationPolicyFromEvidenceVerifier(v eaattestation.EvidenceVerifier) eaattestation.VerificationPolicy {
	return eaattestation.VerificationPolicy{EvidenceVerifier: v}
}

// IdentityBindingFromValidation derives the identity-policy binding values from
// the accepted aTLS validation result.
func IdentityBindingFromValidation(validation *ea.ValidationResult) (identitypolicy.Binding, error) {
	return internaltransport.ExpectedIdentityBinding(validation)
}
