// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/ToppyMicroServices/agents-secure-binding/v2/agent/runner"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestCanceledQueuedGRPCRunCannotStartAfterStop(t *testing.T) {
	t.Chdir(t.TempDir())
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	releaseQueued := sync.OnceFunc(func() { close(release) })
	defer releaseQueued()
	handled := make(chan error, 1)
	interceptor := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if info.FullMethod != pb.ComputationRunner_Run_FullMethodName {
			return handler(ctx, req)
		}
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-release
		resp, err := handler(ctx, req)
		handled <- err
		return resp, err
	}
	var preparations atomic.Int32
	originalCreate := createAlgorithmFile
	createAlgorithmFile = func(dir, pattern string) (*os.File, error) {
		preparations.Add(1)
		return originalCreate(dir, pattern)
	}
	t.Cleanup(func() { createAlgorithmFile = originalCreate })
	rs := New(slog.New(slog.NewTextHandler(io.Discard, nil)), &MockEventService{})
	client := cancellationTestClient(t, rs, interceptor)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runDone := make(chan error, 1)
	go func() {
		_, err := client.Run(ctx, &pb.RunRequest{ComputationId: "queued", AlgoType: "bin", Algorithm: []byte("#!/bin/sh\n: > executed\n")})
		runDone <- err
	}()
	waitCancellationTestSignal(t, entered)
	cancel()
	waitCancellationTestSignal(t, canceled)
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	_, err := client.Stop(stopCtx, &pb.StopRequest{ComputationId: "queued"})
	require.NoError(t, err)
	releaseQueued()
	var handledErr error
	select {
	case err := <-handled:
		handledErr = err
	case <-time.After(5 * time.Second):
		t.Fatal("queued Run handler did not return")
	}
	select {
	case err := <-runDone:
		require.Equal(t, codes.Canceled, status.Code(err))
	case <-time.After(5 * time.Second):
		t.Fatal("client Run did not observe cancellation")
	}
	require.Zero(t, preparations.Load(), "canceled queued Run prepared an algorithm after Stop")
	require.ErrorIs(t, handledErr, context.Canceled)
	_, err = os.Stat("executed")
	require.True(t, os.IsNotExist(err), "canceled queued Run executed code")
	rs.mu.Lock()
	running := rs.running
	rs.mu.Unlock()
	require.False(t, running)
}

func TestGRPCRunCancellationTearsDownBeforeReadmission(t *testing.T) {
	if runtime.GOOS != linuxTestOS {
		t.Skip("native PID-namespace runtime check requires Linux")
	}
	t.Chdir(t.TempDir())
	rs := New(slog.New(slog.NewTextHandler(io.Discard, nil)), &MockEventService{})
	client := cancellationTestClient(t, rs, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	runDone := make(chan error, 1)
	go func() {
		_, err := client.Run(ctx, &pb.RunRequest{
			ComputationId: "running", AlgoType: "bin",
			Algorithm: []byte("#!/bin/sh\nread -r host_pid rest < /proc/self/stat\nprintf '%s\\n' \"$host_pid\" > started\nsleep 30 &\nwait\n"),
		})
		runDone <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	var pid int
	for time.Now().Before(deadline) {
		data, err := os.ReadFile("started")
		if err == nil {
			pid, err = strconv.Atoi(strings.TrimSpace(string(data)))
			if err == nil {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	require.Greater(t, pid, 1, "contained native command did not start")
	cancel()
	select {
	case err := <-runDone:
		require.Equal(t, codes.Canceled, status.Code(err))
	case <-time.After(5 * time.Second):
		t.Fatal("client Run did not observe cancellation")
	}
	deadline = time.Now().Add(5 * time.Second)
	for {
		rs.mu.Lock()
		running := rs.running
		rs.mu.Unlock()
		if !running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("canceled RPC left the computation running")
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid)))
	require.True(t, errors.Is(err, os.ErrNotExist), "old process survived released admission: %v", err)
	nextCtx, nextCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer nextCancel()
	resp, err := client.Run(nextCtx, &pb.RunRequest{ComputationId: "next", AlgoType: "bin", Algorithm: []byte("#!/bin/sh\nexit 0\n")})
	require.NoError(t, err)
	require.Empty(t, resp.Error)
}

func cancellationTestClient(t *testing.T, rs *RunnerService, interceptor grpc.UnaryServerInterceptor) pb.ComputationRunnerClient {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	var options []grpc.ServerOption
	if interceptor != nil {
		options = append(options, grpc.UnaryInterceptor(interceptor))
	}
	server := grpc.NewServer(options...)
	pb.RegisterComputationRunnerServer(server, rs)
	go func() { _ = server.Serve(listener) }()
	conn, err := grpc.NewClient("passthrough:///runner-cancellation-test",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = conn.Close()
		server.Stop()
		_ = listener.Close()
	})
	return pb.NewComputationRunnerClient(conn)
}

func waitCancellationTestSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatal("gRPC cancellation synchronization timed out")
	}
}
