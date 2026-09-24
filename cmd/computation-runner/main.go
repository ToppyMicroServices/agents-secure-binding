// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent/cvms"
	logpb "github.com/ToppyMicroServices/agents-secure-binding/v2/agent/log"
	pb "github.com/ToppyMicroServices/agents-secure-binding/v2/agent/runner"
	runnerevents "github.com/ToppyMicroServices/agents-secure-binding/v2/agent/runner/events"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent/runner/service"
	agentlogger "github.com/ToppyMicroServices/agents-secure-binding/v2/internal/logger"
	mglog "github.com/ToppyMicroServices/agents-secure-binding/v2/internal/runtime/logging"
	logclient "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients/grpc/log"
	"github.com/caarlos0/env/v11"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
)

const (
	svcName    = "computation-runner"
	socketPath = "/run/agents-secure-binding/runner.sock"
)

type config struct {
	LogLevel     string `env:"RUNNER_LOG_LEVEL" envAlternate:"AGENT_LOG_LEVEL" envDefault:"debug"`
	LogForwarder string `env:"LOG_FORWARDER_SOCKET" envDefault:"/run/agents-secure-binding/log.sock"`
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	var cfg config
	if err := env.Parse(&cfg); err != nil {
		fmt.Printf("failed to load %s configuration : %s\n", svcName, err)
		os.Exit(1)
	}

	var exitCode int
	defer mglog.ExitWithError(&exitCode)

	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		fmt.Println(err)
		exitCode = 1
		return
	}

	logQueue := make(chan *cvms.ClientStreamMessage, 1000)
	handler := agentlogger.NewProtoHandler(os.Stdout, &slog.HandlerOptions{Level: level}, logQueue)
	logger := slog.New(handler)

	// Connect to Log Forwarder
	logClient, err := logclient.NewClient(cfg.LogForwarder)
	if err != nil {
		logger.Warn(fmt.Sprintf("failed to connect to log-forwarder: %s. Logs and events will not be forwarded.", err))
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
				}
			}
		}
	})

	eventSvc := runnerevents.NewAdapter(logClient, svcName)

	lis, err := listenRunnerSocket(socketPath)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to listen on socket: %s", err))
		exitCode = 1
		return
	}
	defer lis.Close()

	grpcServer := grpc.NewServer()
	svc := service.New(logger, eventSvc)
	pb.RegisterComputationRunnerServer(grpcServer, svc)

	g.Go(func() error {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(ch)

		select {
		case <-ch:
			logger.Info("Received signal, shutting down...")
			cancel()
			grpcServer.GracefulStop()
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})

	g.Go(func() error {
		logger.Info(fmt.Sprintf("%s started on %s", svcName, socketPath))
		return grpcServer.Serve(lis)
	})

	if err := g.Wait(); err != nil {
		logger.Error(fmt.Sprintf("%s terminated: %s", svcName, err))
	}
}

func listenRunnerSocket(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create socket directory: %w", err)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refuse to replace non-socket path %q", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove existing socket: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect existing socket: %w", err)
	}
	lis, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = lis.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("restrict socket: %w", err)
	}
	return lis, nil
}
