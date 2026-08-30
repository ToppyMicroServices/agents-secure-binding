// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"context"
	stdtls "crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/tls"
)

type Client interface {
	Transport() *http.Transport
	Secure() string
	Timeout() time.Duration
}

type client struct {
	transport *http.Transport
	cfg       clients.ClientConfiguration
	security  tls.Security
}

var _ Client = (*client)(nil)

func NewClient(cfg clients.ClientConfiguration) (Client, error) {
	transport, security, err := createTransport(cfg)
	if err != nil {
		return nil, err
	}

	return &client{
		transport: transport,
		cfg:       cfg,
		security:  security,
	}, nil
}

func (c *client) Transport() *http.Transport {
	return c.transport
}

func (c *client) Secure() string {
	return c.security.String()
}

func (c *client) Timeout() time.Duration {
	return c.cfg.Config().Timeout
}

func createTransport(cfg clients.ClientConfiguration) (*http.Transport, tls.Security, error) {
	transport := &http.Transport{
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	security := tls.WithoutTLS

	if agcfg, ok := clients.AsAttestedClientConfig(cfg); ok && agcfg == nil {
		return nil, security, clients.ErrNilAttestedClientConfig
	} else if ok && agcfg.AttestedTLS {
		if !agcfg.AttestationVerificationPolicy.RequiresAttestation() {
			return nil, security, clients.ErrMissingAttestationVerifier
		}
		result, err := tls.LoadASBConfig(
			agcfg.ServerCAFile,
			agcfg.ClientCert,
			agcfg.ClientKey,
		)
		if err != nil {
			return nil, security, err
		}
		result.Config.ServerName = agcfg.ServerName

		atlsConfig, err := buildATLSClientConfig(agcfg, result.Config)
		if err != nil {
			return nil, security, err
		}

		transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialNetwork, target := httpDialTarget(network, addr)
			return atls.DialContext(ctx, dialNetwork, target, atlsConfig)
		}
		transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
			return nil, clients.ErrAttestedTLSRequiresHTTPS
		}
		security = result.Security
	} else {
		conf := cfg.Config()

		result, err := tls.LoadBasicConfig(conf.ServerCAFile, conf.ClientCert, conf.ClientKey)
		if err != nil {
			return nil, security, err
		}

		if result.Security != tls.WithoutTLS {
			result.Config.ServerName = conf.ServerName
			transport.TLSClientConfig = result.Config
		}

		security = result.Security
	}

	return transport, security, nil
}

func buildATLSClientConfig(agcfg *clients.AttestedClientConfig, baseTLSConfig *stdtls.Config) (*atls.ClientConfig, error) {
	if !agcfg.AttestationVerificationPolicy.RequiresAttestation() {
		return nil, clients.ErrMissingAttestationVerifier
	}
	tlsConfig := baseTLSConfig.Clone()
	tlsConfig.MinVersion = stdtls.VersionTLS13
	atlsConfig := &atls.ClientConfig{
		TLSConfig:         tlsConfig,
		VerifyOptions:     atls.VerifyOptionsFromTLSConfig(tlsConfig),
		AttestationPolicy: agcfg.AttestationVerificationPolicy,
		IdentityPolicy:    agcfg.IdentityPolicy,
		IdentityGrant:     agcfg.IdentityGrant,
		IdentityBinding:   agcfg.IdentityBinding,
		IdentityReplay:    agcfg.IdentityReplay,
		IdentityLogger:    agcfg.IdentityLogger,
	}
	observedIdentity, err := agcfg.AGTPObservedIdentity()
	if err != nil {
		return nil, err
	}
	if observedIdentity != nil {
		atlsConfig.ObservedIdentity = observedIdentity
	}
	requestContext, err := agcfg.RequestContext()
	if err != nil {
		return nil, err
	}
	if len(requestContext) > 0 {
		req, err := atls.NewRequest(requestContext)
		if err != nil {
			return nil, err
		}
		atlsConfig.Request = req
	} else {
		atlsConfig.RequestBuilder = func() (*atls.AuthenticatorRequest, error) {
			return atls.NewRandomRequest(32)
		}
	}
	return atlsConfig, nil
}

func httpDialTarget(network, addr string) (string, string) {
	if strings.HasPrefix(addr, "unix://") {
		return "unix", strings.TrimPrefix(addr, "unix://")
	}
	if strings.HasPrefix(addr, "/") {
		return "unix", addr
	}
	return network, addr
}
