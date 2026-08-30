// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/runtime/server"
)

type runtimeServer struct {
	server.Base
	protocol string
	server   *http.Server
}

// NewServer returns an HTTP runtime server.
func NewServer(ctx context.Context, cancel context.CancelFunc, name string, config server.Config, handler http.Handler, logger *slog.Logger) server.Server {
	base := server.NewBase(ctx, cancel, name, config, logger)
	return &runtimeServer{
		Base:     base,
		protocol: "http",
		server: &http.Server{
			Addr:              base.Address,
			Handler:           handler,
			ReadTimeout:       config.ReadTimeout,
			WriteTimeout:      config.WriteTimeout,
			ReadHeaderTimeout: config.ReadHeaderTimeout,
			IdleTimeout:       config.IdleTimeout,
			MaxHeaderBytes:    config.MaxHeaderBytes,
		},
	}
}

func (s *runtimeServer) Start() error {
	errCh := make(chan error, 1)
	if s.Config.CertFile != "" || s.Config.KeyFile != "" {
		certificate, err := server.LoadX509KeyPair(s.Config.CertFile, s.Config.KeyFile)
		if err != nil {
			return err
		}
		if s.server.TLSConfig == nil {
			s.server.TLSConfig = &tls.Config{}
		}
		tlsConfig := s.server.TLSConfig.Clone()
		tlsConfig.Certificates = append(tlsConfig.Certificates, certificate)
		s.server.TLSConfig = tlsConfig
		s.protocol = "https"
		s.Logger.Info(fmt.Sprintf("%s HTTPS server listening at %s with TLS", s.Name, s.Address))
		go func() {
			errCh <- s.server.ListenAndServeTLS("", "")
		}()
	} else {
		s.Logger.Info(fmt.Sprintf("%s HTTP server listening at %s without TLS", s.Name, s.Address))
		go func() {
			errCh <- s.server.ListenAndServe()
		}()
	}

	select {
	case <-s.Ctx.Done():
		return s.Stop()
	case err := <-errCh:
		return err
	}
}

func (s *runtimeServer) Stop() error {
	defer s.Cancel()
	ctx, cancel := context.WithTimeout(context.Background(), server.StopWaitTime)
	defer cancel()
	if err := s.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("%s %s server shutdown at %s: %w", s.Name, s.protocol, s.Address, err)
	}
	s.Logger.Info(fmt.Sprintf("%s %s server shutdown at %s", s.Name, s.protocol, s.Address))
	return nil
}
