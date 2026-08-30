// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/runtime/netguard"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/runtime/server"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
)

type ServiceRegister func(srv *grpc.Server)

var ErrPlaintextPublicGRPC = fmt.Errorf("runtime grpc: plaintext listener requires localhost, loopback, or TLS")

type runtimeServer struct {
	server.Base
	server          *grpc.Server
	registerService ServiceRegister
	health          *health.Server
}

// NewServer returns a gRPC runtime server.
func NewServer(ctx context.Context, cancel context.CancelFunc, name string, config server.Config, registerService ServiceRegister, logger *slog.Logger) server.Server {
	return &runtimeServer{
		Base:            server.NewBase(ctx, cancel, name, config, logger),
		registerService: registerService,
	}
}

func (s *runtimeServer) Start() error {
	tlsConfigured := s.Config.CertFile != "" || s.Config.KeyFile != ""
	if !tlsConfigured && !netguard.PlaintextBindAllowed(s.Config.Host) {
		return fmt.Errorf("%w: %s", ErrPlaintextPublicGRPC, s.Address)
	}

	listener, err := net.Listen("tcp", s.Address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.Address, err)
	}

	creds := grpc.Creds(insecure.NewCredentials())
	if tlsConfigured {
		creds, err = s.tlsCredentials()
		if err != nil {
			_ = listener.Close()
			return err
		}
		s.Logger.Info(fmt.Sprintf("%s gRPC server listening at %s with TLS", s.Name, s.Address))
	} else {
		s.Logger.Info(fmt.Sprintf("%s gRPC server listening at %s without TLS", s.Name, s.Address))
	}

	s.server = grpc.NewServer(grpc.StatsHandler(otelgrpc.NewServerHandler()), creds)
	s.health = health.NewServer()
	grpchealth.RegisterHealthServer(s.server, s.health)
	s.registerService(s.server)
	s.health.SetServingStatus(s.Name, grpchealth.HealthCheckResponse_SERVING)

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.server.Serve(listener)
	}()

	select {
	case <-s.Ctx.Done():
		return s.Stop()
	case err := <-errCh:
		s.Cancel()
		return err
	}
}

func (s *runtimeServer) Stop() error {
	defer s.Cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		if s.health != nil {
			s.health.Shutdown()
		}
		if s.server != nil {
			s.server.GracefulStop()
		}
	}()
	select {
	case <-done:
	case <-time.After(server.StopWaitTime):
		if s.server != nil {
			s.server.Stop()
		}
	}
	s.Logger.Info(fmt.Sprintf("%s gRPC server shutdown at %s", s.Name, s.Address))
	return nil
}

func (s *runtimeServer) tlsCredentials() (grpc.ServerOption, error) {
	certificate, err := server.LoadX509KeyPair(s.Config.CertFile, s.Config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load gRPC server certificate: %w", err)
	}
	tlsConfig := &tls.Config{
		ClientAuth:   tls.NoClientCert,
		Certificates: []tls.Certificate{certificate},
	}
	rootCA, err := server.LoadRootCACerts(s.Config.ServerCAFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load root CA file: %w", err)
	}
	if rootCA != nil {
		tlsConfig.RootCAs = rootCA
	}
	clientCA, err := server.LoadRootCACerts(s.Config.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client CA file: %w", err)
	}
	if clientCA != nil {
		tlsConfig.ClientCAs = x509.NewCertPool()
		tlsConfig.ClientCAs = clientCA
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return grpc.Creds(credentials.NewTLS(tlsConfig)), nil
}
