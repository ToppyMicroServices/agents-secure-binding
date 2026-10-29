// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package auth_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent"
	agentgrpc "github.com/ToppyMicroServices/agents-secure-binding/v2/agent/api/grpc"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type scopedResultService struct {
	agent.Service
	result []byte
}

func (s scopedResultService) Result(ctx context.Context) ([]byte, error) {
	if _, ok := agent.IndexFromContext(ctx); !ok {
		return nil, status.Error(codes.Unauthenticated, "consumer index missing")
	}
	return s.result, nil
}

func TestResultRPCRejectsProofOutsideVMAndComputation(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	clientFor := func(instanceID, id string, key ed25519.PublicKey) agent.AgentServiceClient {
		t.Helper()
		keyDER, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			t.Fatal(err)
		}
		verifier, err := auth.New(agent.Computation{
			ID:              id,
			Algorithm:       agent.Algorithm{UserKey: keyDER},
			ResultConsumers: []agent.ResultConsumer{{UserKey: keyDER}},
		}, instanceID)
		if err != nil {
			t.Fatal(err)
		}
		unary, stream := agentgrpc.NewAuthInterceptor(verifier)
		server := grpc.NewServer(grpc.UnaryInterceptor(unary), grpc.StreamInterceptor(stream))
		agent.RegisterAgentServiceServer(server, agentgrpc.NewServer(scopedResultService{result: []byte("result-" + instanceID + "-" + id)}))
		listener := bufconn.Listen(1 << 20)
		go func() { _ = server.Serve(listener) }()
		t.Cleanup(func() { server.Stop(); _ = listener.Close() })

		conn, err := grpc.NewClient("passthrough:///scoped-result",
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return agent.NewAgentServiceClient(conn)
	}

	a := clientFor("vm-A", "run-1", publicKey)
	b := clientFor("vm-B", "run-1", publicKey)
	c := clientFor("vm-A", "run-2", publicKey)
	d := clientFor("vm-D", "run-1", otherPublicKey)
	issuedAt := time.Now().UTC().Format(time.RFC3339Nano)
	nonce := "one-request"
	signed := func(instanceID, id, method string) metadata.MD {
		proof := auth.SignaturePayload(instanceID, id, auth.ConsumerRole, method, issuedAt, nonce)
		return metadata.Pairs(
			auth.SignatureMetadataKey, base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, proof)),
			auth.SignatureTimestampMetadataKey, issuedAt,
			auth.SignatureNonceMetadataKey, nonce,
		)
	}
	fetch := func(client agent.AgentServiceClient, proof metadata.MD) ([]byte, error) {
		ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), proof.Copy()), 5*time.Second)
		defer cancel()
		stream, err := client.Result(ctx, &agent.ResultRequest{})
		if err != nil {
			return nil, err
		}
		var result []byte
		for {
			part, err := stream.Recv()
			if err == io.EOF {
				return result, nil
			}
			if err != nil {
				return nil, err
			}
			result = append(result, part.File...)
		}
	}
	checkDenied := func(client agent.AgentServiceClient, proof metadata.MD) {
		t.Helper()
		result, err := fetch(client, proof)
		if status.Code(err) != codes.Unauthenticated || len(result) != 0 {
			t.Fatalf("got result %q and error %v, want unauthenticated without result", result, err)
		}
	}

	proofA := signed("vm-A", "run-1", agent.AgentService_Result_FullMethodName)
	result, err := fetch(a, proofA)
	if err != nil || string(result) != "result-vm-A-run-1" {
		t.Fatalf("A-scoped result = %q, %v", result, err)
	}
	checkDenied(a, proofA)
	checkDenied(b, proofA)
	checkDenied(c, proofA)
	checkDenied(d, proofA)
	checkDenied(b, signed("vm-B", "run-1", agent.AgentService_IMAMeasurements_FullMethodName))

	proofB := signed("vm-B", "run-1", agent.AgentService_Result_FullMethodName)
	result, err = fetch(b, proofB)
	if err != nil || string(result) != "result-vm-B-run-1" {
		t.Fatalf("B-scoped result = %q, %v", result, err)
	}
	checkDenied(b, proofB)

	proofC := signed("vm-A", "run-2", agent.AgentService_Result_FullMethodName)
	result, err = fetch(c, proofC)
	if err != nil || string(result) != "result-vm-A-run-2" {
		t.Fatalf("C-scoped result = %q, %v", result, err)
	}
	checkDenied(c, proofC)
}
