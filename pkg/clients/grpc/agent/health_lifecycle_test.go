// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/stats"
)

type stalledHealthServer struct {
	grpchealth.UnimplementedHealthServer
	stall bool
}

func (s stalledHealthServer) Check(ctx context.Context, _ *grpchealth.HealthCheckRequest) (*grpchealth.HealthCheckResponse, error) {
	if s.stall {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return &grpchealth.HealthCheckResponse{Status: grpchealth.HealthCheckResponse_NOT_SERVING}, nil
}

type connectionEndStats struct{ ended chan struct{} }

func (s connectionEndStats) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context {
	return ctx
}

func (s connectionEndStats) HandleRPC(context.Context, stats.RPCStats) {}

func (s connectionEndStats) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return ctx
}

func (s connectionEndStats) HandleConn(_ context.Context, event stats.ConnStats) {
	if _, ok := event.(*stats.ConnEnd); ok {
		select {
		case s.ended <- struct{}{}:
		default:
		}
	}
}

func TestFailedHealthCheckClosesClientConnection(t *testing.T) {
	for _, stall := range []bool{false, true} {
		name := "unhealthy"
		if stall {
			name = "health timeout"
		}
		t.Run(name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			ended := make(chan struct{}, 1)
			server := grpc.NewServer(grpc.StatsHandler(connectionEndStats{ended: ended}))
			grpchealth.RegisterHealthServer(server, stalledHealthServer{stall: stall})
			done := make(chan struct{})
			go func() {
				defer close(done)
				_ = server.Serve(listener)
			}()
			t.Cleanup(func() {
				server.Stop()
				<-done
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			started := time.Now()
			client, service, err := NewAgentClient(ctx, clients.AttestedClientConfig{
				StandardClientConfig: clients.StandardClientConfig{URL: listener.Addr().String(), Timeout: 200 * time.Millisecond},
			})
			require.Error(t, err)
			require.Nil(t, client)
			require.Nil(t, service)
			require.NoError(t, ctx.Err(), "the configured health timeout must bound the call")
			require.Less(t, time.Since(started), 3*time.Second)
			select {
			case <-ended:
			case <-time.After(3 * time.Second):
				t.Fatal("failed initialization left the gRPC connection open")
			}
		})
	}
}
