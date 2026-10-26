// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func TestHTTPSBackendRequiresVerifiedTLS(t *testing.T) {
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.ProtoMajor != 2 {
			t.Error("backend request did not use TLS HTTP/2")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	backend.EnableHTTP2 = true
	backend.Config.ErrorLog = log.New(io.Discard, "", 0)
	backend.StartTLS()
	defer backend.Close()
	target, err := url.Parse(backend.URL)
	require.NoError(t, err)
	transport, err := backendTransport(target)
	require.NoError(t, err)
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	_, err = client.Get(backend.URL)
	require.Error(t, err, "untrusted backend certificate must be rejected")
	roots := x509.NewCertPool()
	roots.AddCert(backend.Certificate())
	transport.TLSClientConfig = &tls.Config{RootCAs: roots}
	response, err := client.Get(backend.URL)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Equal(t, http.StatusNoContent, response.StatusCode)
	transport.CloseIdleConnections()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, ServerName: "wrong.example"}
	_, err = client.Get(backend.URL)
	require.Error(t, err, "wrong backend hostname must be rejected")
}

func TestHTTPSBackendCannotFallBackToH2C(t *testing.T) {
	backend := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), &http2.Server{}))
	defer backend.Close()
	target, err := url.Parse(backend.URL)
	require.NoError(t, err)
	transport, err := backendTransport(target)
	require.NoError(t, err)
	client := &http.Client{Transport: transport, Timeout: time.Second}
	response, err := client.Get(backend.URL)
	require.NoError(t, err, "explicit HTTP backend must retain h2c support")
	require.NoError(t, response.Body.Close())
	transport.CloseIdleConnections()
	target.Scheme = "https"
	secure, err := backendTransport(target)
	require.NoError(t, err)
	defer secure.CloseIdleConnections()
	client.Transport = secure
	_, err = client.Get(target.String())
	require.Error(t, err, "HTTPS backend sent plaintext to an h2c server")
}

func TestIngressExpiresIncompleteRequests(t *testing.T) {
	for _, attested := range []bool{false, true} {
		for _, protocol := range []string{"http/1.1", "h2"} {
			name := protocol
			if attested {
				name += "/attested"
			} else {
				name += "/plaintext"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				testIngressExpiresIncompleteRequest(t, attested, protocol)
			})
		}
	}
}

func testIngressExpiresIncompleteRequest(t *testing.T, attested bool, protocol string) {
	certificate, key := createTempCert(t)
	provider := mocks.NewCertificateProvider(t)
	if attested {
		provider.On("BuildLeafExtensions", mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)
	}
	backendServer := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), &http2.Server{}))
	defer backendServer.Close()
	backend, err := url.Parse(backendServer.URL)
	require.NoError(t, err)
	proxy := NewProxyServer(slog.New(slog.NewTextHandler(io.Discard, nil)), backend, provider).(*proxyServer)
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := reserved.Addr().String()
	_, port, err := net.SplitHostPort(address)
	require.NoError(t, err)
	require.NoError(t, reserved.Close())
	config := ProxyConfig{Port: port, AllowPlaintext: !attested, AttestedTLS: attested}
	if attested {
		config.CertFile, config.KeyFile = certificate, key
	}
	require.NoError(t, proxy.Start(config, ProxyContext{}))
	defer func() { _ = proxy.Stop() }()
	require.Positive(t, proxy.httpServer.ReadHeaderTimeout)
	require.Positive(t, proxy.httpServer.IdleTimeout)
	pem, err := os.ReadFile(certificate)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(pem))
	dial := func(ctx context.Context) (net.Conn, error) {
		if !attested {
			return (&net.Dialer{}).DialContext(ctx, "tcp", address)
		}
		return atls.DialContext(ctx, "tcp", address, &atls.ClientConfig{
			TLSConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13, NextProtos: []string{protocol}},
			VerifyOptions: &x509.VerifyOptions{Roots: roots},
		})
	}
	if protocol == "h2" {
		transport := &http2.Transport{
			AllowHTTP: !attested,
			DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
				return dial(ctx)
			},
		}
		defer transport.CloseIdleConnections()
		scheme := "http"
		if attested {
			scheme = "https"
		}
		response, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Get(scheme + "://" + address)
		require.NoError(t, err, "complete HTTP/2 requests must still be forwarded")
		require.NoError(t, response.Body.Close())
		require.Equal(t, http.StatusNoContent, response.StatusCode)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	connection, err := dial(ctx)
	require.NoError(t, err)
	defer connection.Close()
	partial := "GET / HTTP/1.1\r\nHost: localhost\r\n"
	if protocol == "h2" {
		partial = "PRI * HTTP/2.0\r\n\r\n"
	}
	_, err = io.WriteString(connection, partial)
	require.NoError(t, err)
	require.NoError(t, connection.SetReadDeadline(time.Now().Add(proxy.httpServer.ReadHeaderTimeout+2*time.Second)))
	_, err = io.ReadAll(connection)
	require.NoError(t, err, "connection did not close after incomplete headers or HTTP/2 preface")
}
