// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package clients

import (
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/ea"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
)

var (
	_ ClientConfiguration = (*AttestedClientConfig)(nil)
	_ ClientConfiguration = (*StandardClientConfig)(nil)

	ErrInvalidAttestationRequestContext = errors.New("invalid attestation request context")
	ErrInvalidIdentityJWTConfig         = errors.New("invalid identity JWT config")
)

type ClientConfiguration interface {
	Config() StandardClientConfig
}

// StandardClientConfig represents a basic client configuration without attested TLS.
type StandardClientConfig struct {
	URL          string        `env:"URL"             envDefault:"localhost:7001"`
	Timeout      time.Duration `env:"TIMEOUT"         envDefault:"60s"`
	ClientCert   string        `env:"CLIENT_CERT"     envDefault:""`
	ClientKey    string        `env:"CLIENT_KEY"      envDefault:""`
	ServerCAFile string        `env:"SERVER_CA_CERTS" envDefault:""`
}

// AttestedClientConfig represents a client configuration with attested TLS capabilities.
type AttestedClientConfig struct {
	StandardClientConfig
	AttestationPolicy string `env:"ATTESTATION_POLICY" envDefault:""`
	AttestedTLS       bool   `env:"ATTESTED_TLS"       envDefault:"false"`
	ProductName       string `env:"PRODUCT_NAME"       envDefault:"Milan"`
	// AttestationRequestContextHex, when set, is decoded from hex and used as
	// the exported authenticator certificate_request_context. This lets the
	// caller provide the background-check freshness value directly.
	AttestationRequestContextHex string `env:"ATTESTATION_REQUEST_CONTEXT" envDefault:""`
	// AttestationRequestContext allows callers inside the same process to pass
	// raw request-context bytes directly instead of using the hex string form.
	AttestationRequestContext []byte                                          `env:"-"`
	IdentityPolicy            identitypolicy.Policy                           `env:"-"`
	IdentityGrant             *identitypolicy.VerifiedGrant                   `env:"-"`
	IdentityBinding           *identitypolicy.VerifiedSessionBindingStatement `env:"-"`
	IdentityReplay            identitypolicy.ReplayCache                      `env:"-"`
	IdentityLogger            *slog.Logger                                    `env:"-"`
	IdentityGrantJWT          string                                          `env:"-"`
	IdentityBindingJWT        string                                          `env:"-"`
	IdentityGrantJWTOptions   JWTVerifyOptions                                `env:"-"`
	IdentityBindingJWTOptions JWTVerifyOptions                                `env:"-"`
}

func (c AttestedClientConfig) Config() StandardClientConfig {
	return c.StandardClientConfig
}

func (c StandardClientConfig) Config() StandardClientConfig {
	return c
}

func (c AttestedClientConfig) RequestContext() ([]byte, error) {
	if len(c.AttestationRequestContext) > 0 {
		return append([]byte(nil), c.AttestationRequestContext...), nil
	}
	if c.AttestationRequestContextHex == "" {
		return nil, nil
	}
	requestContext, err := hex.DecodeString(c.AttestationRequestContextHex)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidAttestationRequestContext, err)
	}
	if len(requestContext) == 0 {
		return nil, fmt.Errorf("%w: decoded value is empty", ErrInvalidAttestationRequestContext)
	}
	return requestContext, nil
}

func (c AttestedClientConfig) AGTPObservedIdentity() (atls.ObservedIdentityFunc, error) {
	grantTokenSet := c.IdentityGrantJWT != ""
	bindingTokenSet := c.IdentityBindingJWT != ""
	if !grantTokenSet && !bindingTokenSet {
		return nil, nil
	}
	if !grantTokenSet || !bindingTokenSet {
		return nil, fmt.Errorf("%w: identity grant JWT and session binding JWT must both be set", ErrInvalidIdentityJWTConfig)
	}
	if c.IdentityGrant != nil || c.IdentityBinding != nil {
		return nil, fmt.Errorf("%w: AGTP JWT tokens cannot be combined with pre-verified identity grant or binding", ErrInvalidIdentityJWTConfig)
	}
	if !c.IdentityPolicy.Enabled() {
		return nil, fmt.Errorf("%w: identity policy is required for identity JWT validation", ErrInvalidIdentityJWTConfig)
	}
	if err := ValidateJWTVerifyOptions(c.IdentityGrantJWTOptions); err != nil {
		return nil, fmt.Errorf("%w: identity grant JWT options: %w", ErrInvalidIdentityJWTConfig, err)
	}
	if err := ValidateJWTVerifyOptions(c.IdentityBindingJWTOptions); err != nil {
		return nil, fmt.Errorf("%w: identity binding JWT options: %w", ErrInvalidIdentityJWTConfig, err)
	}
	if c.IdentityReplay == nil {
		return nil, fmt.Errorf("%w: identity replay cache is required for AGTP JWT validation", ErrInvalidIdentityJWTConfig)
	}

	return func(st *tls.ConnectionState, validation *ea.ValidationResult) (identitypolicy.Assertion, error) {
		expectedBinding, err := expectedBindingForAGTP(st, validation)
		if err != nil {
			return identitypolicy.Assertion{}, err
		}
		result, err := VerifySessionIdentityJWT(c.IdentityGrantJWT, c.IdentityBindingJWT, SessionIdentityJWTOptions{
			Grant:           c.IdentityGrantJWTOptions,
			SessionBinding:  c.IdentityBindingJWTOptions,
			Policy:          c.IdentityPolicy,
			ExpectedBinding: expectedBinding,
			ReplayCache:     c.IdentityReplay,
		})
		if err != nil {
			return identitypolicy.Assertion{}, err
		}
		return result.Assertion, nil
	}, nil
}

func expectedBindingForAGTP(st *tls.ConnectionState, validation *ea.ValidationResult) (identitypolicy.Binding, error) {
	if st != nil && st.Version != 0 {
		return atls.IdentityBindingFromConnectionState(st, validation)
	}
	return atls.IdentityBindingFromValidation(validation)
}
