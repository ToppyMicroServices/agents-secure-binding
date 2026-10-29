// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent"
	agentgrpc "github.com/ToppyMicroServices/agents-secure-binding/v2/agent/api/grpc"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent/auth"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/runtime/netguard"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

const (
	svcName          = "agent"
	defSvcGRPCSocket = "/run/agents-secure-binding/agent.sock"
)

var ErrPlaintextPublicAgentGRPC = fmt.Errorf("agent grpc: plaintext listener requires unix socket or loopback")
var ErrMissingRunIDStore = errors.New("agent grpc: missing persistent run ID store")
var ErrRunIDReused = errors.New("agent grpc: computation run ID already used by this VM")

type AgentServer interface {
	Start(cfg agent.AgentConfig, cmp agent.Computation) error
	Stop() error
}

type agentServer struct {
	mu         sync.Mutex
	gs         *grpc.Server
	logger     *slog.Logger
	svc        agent.Service
	host       string
	instanceID string
	storageDir string
}

func NewServer(logger *slog.Logger, svc agent.Service, host, instanceID, storageDir string) AgentServer {
	return &agentServer{
		logger:     logger,
		svc:        svc,
		host:       host,
		instanceID: instanceID,
		storageDir: storageDir,
	}
}

func (as *agentServer) Start(cfg agent.AgentConfig, cmp agent.Computation) error {
	authSvc, err := auth.New(cmp, as.instanceID)
	if err != nil {
		as.logger.WithGroup(cmp.ID).Error(fmt.Sprintf("failed to create auth service %s", err.Error()))
		return err
	}
	if strings.TrimSpace(as.storageDir) == "" {
		return ErrMissingRunIDStore
	}

	grpcServerOptions := []grpc.ServerOption{
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
	}

	// Add authentication interceptors
	unary, stream := agentgrpc.NewAuthInterceptor(authSvc)
	grpcServerOptions = append(grpcServerOptions, grpc.UnaryInterceptor(unary))
	grpcServerOptions = append(grpcServerOptions, grpc.StreamInterceptor(stream))

	// Internal Unix socket is pure plaintext HTTP/2; Ingress Proxy handles external aTLS termination
	grpcServerOptions = append(grpcServerOptions, grpc.Creds(insecure.NewCredentials()))

	gs := grpc.NewServer(grpcServerOptions...)

	reflection.Register(gs)
	agent.RegisterAgentServiceServer(gs, agentgrpc.NewServer(as.svc))

	healthServer := health.NewServer()
	healthServer.SetServingStatus("agent", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(gs, healthServer)

	socketPath := as.host
	if socketPath == "" || socketPath == "0.0.0.0" {
		socketPath = defSvcGRPCSocket
	}
	isUnix := socketPath[0] == '/' || socketPath[0] == '.'
	if !isUnix {
		host, _, splitErr := net.SplitHostPort(socketPath)
		if splitErr != nil || !netguard.PlaintextBindAllowed(host) {
			return fmt.Errorf("%w: %s", ErrPlaintextPublicAgentGRPC, socketPath)
		}
	}
	if err := as.markRunID(cmp.ID); err != nil {
		return err
	}

	var listener net.Listener
	if isUnix {
		// Remove existing socket file if it exists
		_ = os.Remove(socketPath)
		listener, err = net.Listen("unix", socketPath)
	} else {
		listener, err = net.Listen("tcp", socketPath)
	}

	if err != nil {
		if removeErr := as.clearReservedRunID(cmp.ID); removeErr != nil {
			as.logger.Error("failed to clear run ID after listener failure", "error", removeErr)
		}
		as.logger.Error(fmt.Sprintf("failed to listen on %s: %s", socketPath, err))
		return err
	}
	as.mu.Lock()
	as.gs = gs
	as.mu.Unlock()

	as.logger.Info(fmt.Sprintf("agent service gRPC server listening at %s without TLS", socketPath))

	go func() {
		err := gs.Serve(listener)
		if err != nil && err != grpc.ErrServerStopped {
			as.logger.Error(fmt.Sprintf("failed to start grpc server %s", err.Error()))
		}
	}()

	return nil
}

// markRunID persists the VM/run pair before accepting RPCs. A process restart
// cannot reset this replay boundary while the VM keeps its identity.
func (as *agentServer) markRunID(runID string) error {
	path := as.runIDPath(runID)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return ErrRunIDReused
	}
	if err != nil {
		return fmt.Errorf("agent grpc: record run ID: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("agent grpc: sync run ID: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("agent grpc: close run ID: %w", err)
	}
	return as.syncRunIDStore()
}

func (as *agentServer) runIDPath(runID string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d:%s%d:%s", len(as.instanceID), as.instanceID, len(runID), runID)))
	return filepath.Join(as.storageDir, "run-id-"+hex.EncodeToString(sum[:]))
}

func (as *agentServer) clearReservedRunID(runID string) error {
	if err := os.Remove(as.runIDPath(runID)); err != nil {
		return err
	}
	return as.syncRunIDStore()
}

func (as *agentServer) syncRunIDStore() error {
	dir, err := os.Open(as.storageDir)
	if err != nil {
		return fmt.Errorf("agent grpc: open run ID store: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("agent grpc: sync run ID store: %w", err)
	}
	return nil
}

func (as *agentServer) Stop() error {
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.gs != nil {
		as.gs.GracefulStop()
	}
	return nil
}
