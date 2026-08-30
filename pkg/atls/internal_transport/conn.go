// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package internaltransport

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/ea"
	eaattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/eaattestation"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
)

// ErrMissingObservedIdentity reports an enabled identity policy without a
// trusted observed-identity source.
var (
	ErrMissingObservedIdentity = errors.New("atls: missing observed identity source")
	ErrMissingTLSServerName    = errors.New("atls: TLS server name is required for a non-TCP target")
)

type Conn struct {
	*tls.Conn
	Request          *ea.AuthenticatorRequest
	ValidationResult *ea.ValidationResult
}

// ObservedIdentityFunc extracts a session-bound identity assertion after aTLS validation.
type ObservedIdentityFunc func(*tls.ConnectionState, *ea.ValidationResult) (identitypolicy.Assertion, error)

type ClientConfig struct {
	TLSConfig         *tls.Config
	Session           *ea.Session
	VerifyOptions     *x509.VerifyOptions
	AttestationPolicy eaattestation.VerificationPolicy
	IdentityPolicy    identitypolicy.Policy
	ObservedIdentity  ObservedIdentityFunc
	IdentityGrant     *identitypolicy.VerifiedGrant
	IdentityBinding   *identitypolicy.VerifiedSessionBindingStatement
	IdentityReplay    identitypolicy.ReplayCache
	IdentityLogger    *slog.Logger
	Request           *ea.AuthenticatorRequest
	RequestBuilder    func() (*ea.AuthenticatorRequest, error)
}

type ServerConfig struct {
	TLSConfig           *tls.Config
	Session             *ea.Session
	Identity            tls.Certificate
	BuildLeafExtensions func(*tls.ConnectionState, *ea.AuthenticatorRequest, *x509.Certificate) ([]ea.Extension, error)
}

func Dial(network, address string, cfg *ClientConfig) (*Conn, error) {
	return DialWithDialer(new(net.Dialer), network, address, cfg)
}

func DialContext(ctx context.Context, network, address string, cfg *ClientConfig) (*Conn, error) {
	return DialContextWithDialer(ctx, new(net.Dialer), network, address, cfg)
}

func DialWithDialer(d *net.Dialer, network, address string, cfg *ClientConfig) (*Conn, error) {
	if cfg == nil || cfg.TLSConfig == nil {
		return nil, fmt.Errorf("atls: missing client TLS config")
	}
	tlsConfig, err := clientTLSConfigForTarget(network, address, cfg.TLSConfig)
	if err != nil {
		return nil, err
	}

	rawConn, err := d.Dial(network, address)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(rawConn, tlsConfig)
	conn, err := Client(tlsConn, cfg)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	return conn, nil
}

func DialContextWithDialer(ctx context.Context, d *net.Dialer, network, address string, cfg *ClientConfig) (*Conn, error) {
	if cfg == nil || cfg.TLSConfig == nil {
		return nil, fmt.Errorf("atls: missing client TLS config")
	}
	if ctx == nil {
		return nil, fmt.Errorf("atls: missing client context")
	}
	tlsConfig, err := clientTLSConfigForTarget(network, address, cfg.TLSConfig)
	if err != nil {
		return nil, err
	}

	rawConn, err := d.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(rawConn, tlsConfig)
	conn, err := ClientContext(ctx, tlsConn, cfg)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	return conn, nil
}

func clientTLSConfigForTarget(network, address string, source *tls.Config) (*tls.Config, error) {
	config := source.Clone()
	if config.ServerName != "" || config.InsecureSkipVerify {
		return config, nil
	}
	if !strings.HasPrefix(network, "tcp") {
		return nil, ErrMissingTLSServerName
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("atls: derive TLS server name from %q: %w", address, err)
	}
	if host == "" {
		return nil, fmt.Errorf("atls: derive TLS server name from %q: host is empty", address)
	}
	config.ServerName = host
	return config, nil
}

func Client(tlsConn *tls.Conn, cfg *ClientConfig) (*Conn, error) {
	return ClientContext(context.Background(), tlsConn, cfg)
}

func ClientContext(ctx context.Context, tlsConn *tls.Conn, cfg *ClientConfig) (*Conn, error) {
	if cfg == nil {
		return nil, fmt.Errorf("atls: missing client config")
	}
	if ctx == nil {
		return nil, fmt.Errorf("atls: missing client context")
	}
	var res *Conn
	err := withConnContext(ctx, tlsConn, func() error {
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return err
		}

		req, err := buildRequest(cfg)
		if err != nil {
			return err
		}
		reqBytes, err := req.Marshal()
		if err != nil {
			return err
		}

		if err := writeFrame(tlsConn, frameTypeRequest, reqBytes); err != nil {
			return err
		}
		frameType, authBytes, err := readFrame(tlsConn)
		if err != nil {
			return err
		}

		if frameType != frameTypeAuthenticator {
			return fmt.Errorf("atls: unexpected frame type %d", frameType)
		}

		st := tlsConn.ConnectionState()
		var validation *ea.ValidationResult
		if cfg.Session != nil {
			validation, err = cfg.Session.ValidateAuthenticatorWithAttestation(&st, ea.RoleServer, req, authBytes, cfg.VerifyOptions, cfg.AttestationPolicy)
		} else {
			validation, err = ea.ValidateAuthenticatorWithAttestation(&st, ea.RoleServer, req, authBytes, cfg.VerifyOptions, cfg.AttestationPolicy)
		}
		if err != nil {
			return err
		}

		if err := validateIdentityPolicy(cfg, &st, validation); err != nil {
			return err
		}

		res = &Conn{Conn: tlsConn, Request: req, ValidationResult: validation}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return res, nil
}

func validateIdentityPolicy(cfg *ClientConfig, st *tls.ConnectionState, validation *ea.ValidationResult) error {
	if !cfg.IdentityPolicy.Enabled() {
		return nil
	}
	now := time.Now()
	assertion, statement, err := observedIdentityAssertion(cfg, st, validation, now)
	if err != nil {
		logIdentityPolicyDebug(cfg.IdentityLogger, "source_failed", err)
		return fmt.Errorf("atls: observed identity source failed: %w", err)
	}
	expectedBinding, err := ExpectedIdentityBinding(validation)
	if err != nil {
		logIdentityPolicyDebug(cfg.IdentityLogger, "binding_context_failed", err)
		return err
	}
	if err := cfg.IdentityPolicy.ValidateAssertion(assertion, expectedBinding, now); err != nil {
		logIdentityPolicyDebug(cfg.IdentityLogger, "validation_failed", err)
		return fmt.Errorf("atls: identity policy validation failed: %w", err)
	}
	if statement != nil {
		if err := identitypolicy.MarkSessionBindingUsed(cfg.IdentityReplay, *statement); err != nil {
			logIdentityPolicyDebug(cfg.IdentityLogger, "replay_failed", err)
			return fmt.Errorf("atls: identity replay check failed: %w", err)
		}
	}
	logIdentityPolicyDebug(cfg.IdentityLogger, "accepted", nil)
	return nil
}

func observedIdentityAssertion(cfg *ClientConfig, st *tls.ConnectionState, validation *ea.ValidationResult, now time.Time) (identitypolicy.Assertion, *identitypolicy.VerifiedSessionBindingStatement, error) {
	if cfg.ObservedIdentity != nil {
		assertion, err := cfg.ObservedIdentity(st, validation)
		return assertion, nil, err
	}
	if cfg.IdentityGrant == nil || cfg.IdentityBinding == nil {
		return identitypolicy.Assertion{}, nil, ErrMissingObservedIdentity
	}
	assertion, err := identitypolicy.NewAssertionFromSessionBinding(*cfg.IdentityGrant, *cfg.IdentityBinding, now)
	return assertion, cfg.IdentityBinding, err
}

func ExpectedIdentityBinding(validation *ea.ValidationResult) (identitypolicy.Binding, error) {
	if validation == nil {
		return identitypolicy.Binding{}, fmt.Errorf("atls: missing validation result")
	}
	if len(validation.Chain) == 0 || validation.Chain[0] == nil {
		return identitypolicy.Binding{}, fmt.Errorf("atls: missing validated leaf certificate")
	}
	if len(validation.Context) == 0 {
		return identitypolicy.Binding{}, fmt.Errorf("atls: missing certificate request context")
	}
	pub, err := eaattestation.PublicKeyBytes(validation.Chain[0])
	if err != nil {
		return identitypolicy.Binding{}, err
	}
	leafHash := sha256.Sum256(pub)
	contextHash := sha256.Sum256(validation.Context)
	binding := identitypolicy.Binding{
		LeafPublicKeySHA256:  hex.EncodeToString(leafHash[:]),
		RequestContextSHA256: hex.EncodeToString(contextHash[:]),
	}
	if validation.Attestation != nil && validation.Attestation.BindingVerified && validation.Attestation.Payload != nil {
		if len(validation.Attestation.Binding.ExportedValue) > 0 {
			exporterHash := sha256.Sum256(validation.Attestation.Binding.ExportedValue)
			binding.TLSExporterSHA256 = hex.EncodeToString(exporterHash[:])
		}
		binderHash := sha256.Sum256(validation.Attestation.Payload.Binder.Binding)
		binding.AttestationBinderSHA256 = hex.EncodeToString(binderHash[:])
	}
	return binding, nil
}

func logIdentityPolicyDebug(logger *slog.Logger, reason string, err error) {
	if logger == nil {
		return
	}
	args := []any{"reason", reason}
	if err != nil {
		args = append(args, "error", err)
	}
	logger.Debug("aTLS identity policy check", args...)
}

func Server(tlsConn *tls.Conn, cfg *ServerConfig) (*Conn, error) {
	if cfg == nil {
		return nil, fmt.Errorf("atls: missing server config")
	}

	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	frameType, reqBytes, err := readFrame(tlsConn)
	if err != nil {
		return nil, err
	}
	if frameType != frameTypeRequest {
		return nil, fmt.Errorf("atls: unexpected frame type %d", frameType)
	}
	req, rest, err := ea.UnmarshalAuthenticatorRequest(reqBytes)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("atls: trailing request bytes")
	}
	if cfg.BuildLeafExtensions != nil && !ea.RequestPermitsCertificateExtension(&req, ea.CMWAttestationExtensionType) {
		return nil, fmt.Errorf("atls: cmw_attestation extension not offered")
	}

	st := tlsConn.ConnectionState()
	identity, err := resolveIdentity(cfg)
	if err != nil {
		return nil, err
	}
	exts, err := buildServerExtensions(cfg, &st, &req, identity)
	if err != nil {
		return nil, err
	}

	var authBytes []byte
	if cfg.Session != nil {
		authBytes, err = cfg.Session.CreateAuthenticator(&st, ea.RoleServer, &req, identity, exts)
	} else {
		authBytes, err = ea.CreateAuthenticator(&st, ea.RoleServer, &req, identity, exts)
	}
	if err != nil {
		return nil, err
	}

	if err := writeFrame(tlsConn, frameTypeAuthenticator, authBytes); err != nil {
		return nil, err
	}

	return &Conn{Conn: tlsConn, Request: &req}, nil
}

func buildRequest(cfg *ClientConfig) (*ea.AuthenticatorRequest, error) {
	if cfg.RequestBuilder != nil {
		return cfg.RequestBuilder()
	}
	if cfg.Request != nil {
		return cfg.Request, nil
	}
	ctx, err := ea.NewRandomContext(32)
	if err != nil {
		return nil, err
	}
	sigExt, err := ea.SignatureAlgorithmsExtension([]uint16{uint16(tls.ECDSAWithP256AndSHA256)})
	if err != nil {
		return nil, err
	}
	return &ea.AuthenticatorRequest{
		Type:    ea.HandshakeTypeClientCertificateRequest,
		Context: ctx,
		Extensions: []ea.Extension{
			sigExt,
			ea.CMWAttestationOfferExtension(),
		},
	}, nil
}

func resolveIdentity(cfg *ServerConfig) (tls.Certificate, error) {
	if len(cfg.Identity.Certificate) > 0 && cfg.Identity.PrivateKey != nil {
		return cfg.Identity, nil
	}
	if cfg.TLSConfig != nil && len(cfg.TLSConfig.Certificates) > 0 {
		return cfg.TLSConfig.Certificates[0], nil
	}
	return tls.Certificate{}, fmt.Errorf("atls: missing server identity")
}

func buildServerExtensions(cfg *ServerConfig, st *tls.ConnectionState, req *ea.AuthenticatorRequest, identity tls.Certificate) ([]ea.Extension, error) {
	if cfg.BuildLeafExtensions == nil {
		return nil, nil
	}
	if len(identity.Certificate) == 0 {
		return nil, fmt.Errorf("atls: missing server leaf certificate")
	}
	leaf, err := x509.ParseCertificate(identity.Certificate[0])
	if err != nil {
		return nil, err
	}
	return cfg.BuildLeafExtensions(st, req, leaf)
}

func withConnContext(ctx context.Context, conn interface{ SetDeadline(time.Time) error }, fn func() error) error {
	if ctx == nil {
		return fn()
	}

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return err
		}
		defer func() {
			_ = conn.SetDeadline(time.Time{})
		}()
	} else {
		done := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				_ = conn.SetDeadline(time.Now())
			case <-done:
			}
		}()
		defer func() {
			close(done)
			_ = conn.SetDeadline(time.Time{})
		}()
	}

	err := fn()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}
