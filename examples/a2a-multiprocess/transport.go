// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

func loadServerTLS(stateDir, role string, clientAuth tls.ClientAuthType) (*tls.Config, error) {
	dir := roleDirectory(stateDir, role)
	certificate, err := tls.LoadX509KeyPair(filepath.Join(dir, tlsCertFile), filepath.Join(dir, tlsKeyFile))
	if err != nil {
		return nil, fmt.Errorf("load %s TLS certificate: %w", role, err)
	}
	pool, err := loadCAPool(filepath.Join(dir, caFile))
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   clientAuth,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{"http/1.1"},
	}, nil
}

func loadClientTLS(stateDir, role, rawURL string) (*tls.Config, error) {
	dir := roleDirectory(stateDir, role)
	certificate, err := tls.LoadX509KeyPair(filepath.Join(dir, tlsCertFile), filepath.Join(dir, tlsKeyFile))
	if err != nil {
		return nil, fmt.Errorf("load %s client certificate: %w", role, err)
	}
	pool, err := loadCAPool(filepath.Join(dir, caFile))
	if err != nil {
		return nil, err
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Hostname() == "" {
		return nil, fmt.Errorf("invalid TLS URL %q", rawURL)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		RootCAs:      pool,
		ServerName:   parsed.Hostname(),
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{"http/1.1"},
	}, nil
}

func loadCAPool(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("parse CA certificate")
	}
	return pool, nil
}

func newHTTPClient(tlsConfig *tls.Config) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:       tlsConfig,
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          4,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second,
		},
		Timeout: 10 * time.Second,
	}
}

func serverWriteTimeout(opts options, role string) time.Duration {
	if role == "agent-b" && effectiveWorkflow(opts.workflow) == workflowLLMConversation {
		// The selected Agent B runtime has a 20-second request limit. Keep the
		// authenticated A2A response open long enough for that bounded call.
		return 30 * time.Second
	}
	return 10 * time.Second
}

func serveTLS(ctx context.Context, opts options, role string, clientAuth tls.ClientAuthType, handler http.Handler, out outputWriter) error {
	config, err := loadServerTLS(opts.stateDir, role, clientAuth)
	if err != nil {
		return err
	}
	if role == "agent-b" && opts.bindingProfile == bindingProfileDraft06V2 {
		config.SessionTicketsDisabled = true
	}
	listener, err := net.Listen("tcp", opts.listen)
	if err != nil {
		return fmt.Errorf("listen for %s: %w", role, err)
	}
	address := listener.Addr().String()
	if opts.readyFile != "" {
		if err := os.WriteFile(opts.readyFile, []byte(address+"\n"), 0o600); err != nil {
			_ = listener.Close()
			return fmt.Errorf("write %s ready file: %w", role, err)
		}
	}
	fmt.Fprintf(out, "%s listening on %s\n", role, address)

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      serverWriteTimeout(opts, role),
		IdleTimeout:       30 * time.Second,
	}
	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- server.Serve(tls.NewListener(listener, config))
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown %s: %w", role, err)
		}
		err := <-serveErrors
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve %s: %w", role, err)
		}
		return nil
	case err := <-serveErrors:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve %s: %w", role, err)
		}
		return nil
	}
}

func requirePeer(r *http.Request, commonName string) error {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return fmt.Errorf("mutual TLS client certificate is required")
	}
	if r.TLS.PeerCertificates[0].Subject.CommonName != commonName {
		return fmt.Errorf("unexpected mutual TLS client identity")
	}
	return nil
}
