// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/ToppyMicroServices/agents-secure-binding/integrations/cocos/evidencesource"
	agentlogger "github.com/ToppyMicroServices/agents-secure-binding/integrations/cocos/internal/logger"
	"github.com/ToppyMicroServices/agents-secure-binding/integrations/cocos/internal/platformselect"
	mglog "github.com/ToppyMicroServices/agents-secure-binding/integrations/cocos/internal/runtime/logging"
	"github.com/ToppyMicroServices/agents-secure-binding/integrations/cocos/internal/runtime/metrics"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent/api"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent/cvms"
	cvmsapi "github.com/ToppyMicroServices/agents-secure-binding/v2/agent/cvms/api/grpc"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent/cvms/server"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent/events"
	logpb "github.com/ToppyMicroServices/agents-secure-binding/v2/agent/log"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	pkggrpc "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients/grpc"
	attestation_client "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients/grpc/attestation"
	cvmsgrpc "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients/grpc/cvm"
	logclient "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients/grpc/log"
	runnerclient "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients/grpc/runner"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/ingress"
	"github.com/caarlos0/env/v11"
	"golang.org/x/sync/errgroup"
)

const (
	svcName          = "agent"
	envPrefixCVMGRPC = "AGENT_CVM_GRPC_"
	storageDir       = "/var/lib/agents-secure-binding/agent"
)

type config struct {
	LogLevel                 string `env:"AGENT_LOG_LEVEL"              envDefault:"debug"`
	Vmpl                     int    `env:"AGENT_VMPL"                   envDefault:"2"`
	AgentGrpcHost            string `env:"AGENT_GRPC_HOST"              envDefault:"0.0.0.0"`
	AttestationPlatform      string `env:"ASB_ATTESTATION_PLATFORM"     envDefault:"auto"`
	AttestationServiceSocket string `env:"ATTESTATION_SERVICE_SOCKET" envDefault:"/run/agents-secure-binding/attestation.sock"`
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	var cfg config
	if err := env.Parse(&cfg); err != nil {
		log.Fatalf("failed to load %s configuration : %s", svcName, err)
	}

	var exitCode int
	defer mglog.ExitWithError(&exitCode)

	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		log.Println(err)
		exitCode = 1
		return
	}

	logQueue := make(chan *cvms.ClientStreamMessage, 1000)
	cvmsQueue := make(chan *cvms.ClientStreamMessage, 1000)

	handler := agentlogger.NewProtoHandler(os.Stdout, &slog.HandlerOptions{Level: level}, logQueue)
	logger := slog.New(handler)

	eventSvc, err := events.New(svcName, logQueue)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create events service %s", err.Error()))
		exitCode = 1
		return
	}

	logClient, err := logclient.NewClient("/run/agents-secure-binding/log.sock")
	if err != nil {
		logger.Warn(fmt.Sprintf("failed to create log client: %s. Logging will be local only until service is available.", err))
	} else {
		defer logClient.Close()
	}

	g.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return nil
			case msg := <-logQueue:
				if logClient == nil {
					continue
				}
				switch m := msg.Message.(type) {
				case *cvms.ClientStreamMessage_AgentLog:
					err := logClient.SendLog(ctx, &logpb.LogEntry{
						Message:       m.AgentLog.Message,
						ComputationId: m.AgentLog.ComputationId,
						Level:         m.AgentLog.Level,
						Timestamp:     m.AgentLog.Timestamp,
					})
					if err != nil {
						logger.Error("failed to send log", "error", err)
					}
				case *cvms.ClientStreamMessage_AgentEvent:
					err := logClient.SendEvent(ctx, &logpb.EventEntry{
						EventType:     m.AgentEvent.EventType,
						Timestamp:     m.AgentEvent.Timestamp,
						ComputationId: m.AgentEvent.ComputationId,
						Details:       m.AgentEvent.Details,
						Originator:    m.AgentEvent.Originator,
						Status:        m.AgentEvent.Status,
					})
					if err != nil {
						logger.Error("failed to send event", "error", err)
					}
				}
			}
		}
	})

	ccPlatform, err := platformselect.Resolve(cfg.AttestationPlatform)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to select direct attestation platform: %s", err))
		exitCode = 1
		return
	}
	logger.Info(fmt.Sprintf("Detected confidential computing platform: %v", ccPlatform))

	cvmGrpcConfig := clients.StandardClientConfig{}
	if err := env.ParseWithOptions(&cvmGrpcConfig, env.Options{Prefix: envPrefixCVMGRPC}); err != nil {
		logger.Error(fmt.Sprintf("failed to load %s gRPC client configuration : %s", svcName, err))
		exitCode = 1
		return
	}

	cvmGRPCClient, cvmsClient, err := cvmsgrpc.NewCVMClient(cvmGrpcConfig)
	if err != nil {
		logger.Error(err.Error())
		exitCode = 1
		return
	}
	defer cvmGRPCClient.Close()

	reconnectFn := func(ctx context.Context) (pkggrpc.Client, cvms.Service_ProcessClient, error) {
		grpcClient, newClient, err := cvmsgrpc.NewCVMClient(cvmGrpcConfig)
		if err != nil {
			return nil, nil, err
		}
		// Don't defer close here as we want to keep the connection open

		pc, err := newClient.Process(ctx)
		if err != nil {
			grpcClient.Close()
			return nil, nil, err
		}
		return grpcClient, pc, nil
	}

	if cfg.Vmpl < 0 || cfg.Vmpl > 3 {
		logger.Error("vmpl level must be in a range [0, 3]")
		exitCode = 1
		return
	}

	attClient, err := attestation_client.NewClient(cfg.AttestationServiceSocket)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create attestation client: %s", err))
		exitCode = 1
		return
	}
	defer attClient.Close()

	runnerClient, err := runnerclient.NewClient("/run/agents-secure-binding/runner.sock")
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create runner client: %s", err))
		exitCode = 1
		return
	}
	defer runnerClient.Close()

	svc := newService(ctx, logger, eventSvc, attClient, runnerClient, cfg.Vmpl)

	if err := os.MkdirAll(storageDir, 0o755); err != nil {
		logger.Error(fmt.Sprintf("failed to create storage directory: %s", err))
		exitCode = 1
		return
	}

	var certProvider atls.CertificateProvider
	if ccPlatform != attestation.NoCC {
		logger.Info(fmt.Sprintf("Initializing aTLS for platform %v with attestation service at %s", ccPlatform, cfg.AttestationServiceSocket))
		evidenceSource, sourceErr := evidencesource.NewEvidenceSource(attClient, ccPlatform)
		if sourceErr != nil {
			logger.Error(fmt.Sprintf("failed to configure platform evidence source: %s", sourceErr))
			exitCode = 1
			return
		}
		certProvider, err = atls.NewProvider(evidenceSource)
		if err != nil {
			logger.Error(fmt.Sprintf("failed to create certificate provider for aTLS: %s", err))
			exitCode = 1
			return
		}
		logger.Info("Successfully created aTLS certificate provider")
	} else {
		logger.Warn("No Confidential Computing platform detected (NoCC). Certificate provider remains nil; aTLS will not be available for computations.")
	}

	// Create ingress proxy server
	backendURL, err := url.Parse("unix:///run/agents-secure-binding/agent.sock")
	if err != nil {
		logger.Error(fmt.Sprintf("failed to parse backend URL: %s", err))
		exitCode = 1
		return
	}
	ingressProxy := ingress.NewProxyServer(logger, backendURL, certProvider)

	pc, err := cvmsClient.Process(ctx)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to connect to cvm server: %s", err))
		exitCode = 1
		return
	}

	mc, err := cvmsapi.NewClient(pc, svc, cvmsQueue, logger, server.NewServer(logger, svc, cfg.AgentGrpcHost), ingressProxy, storageDir, reconnectFn, cvmGRPCClient)
	if err != nil {
		logger.Error(err.Error())
		exitCode = 1
		return
	}

	g.Go(func() error {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(ch)

		select {
		case <-ch:
			logger.Info("Received signal, shutting down...")
			cancel()
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})

	g.Go(func() error {
		return mc.Process(ctx, cancel)
	})

	if err := g.Wait(); err != nil {
		logger.Error(fmt.Sprintf("%s service terminated: %s", svcName, err))
	}
}

func newService(ctx context.Context, logger *slog.Logger, eventSvc events.Service, attClient attestation_client.Client, runnerClient runnerclient.Client, vmpl int) agent.Service {
	svc := agent.New(ctx, logger, eventSvc, attClient, runnerClient, vmpl)

	svc = api.LoggingMiddleware(svc, logger)
	counter, latency := metrics.MakeMetrics(svcName, "api")
	svc = api.MetricsMiddleware(svc, counter, latency)

	return svc
}
