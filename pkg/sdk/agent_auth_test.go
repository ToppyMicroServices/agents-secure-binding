// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent/auth"
	"google.golang.org/grpc/metadata"
)

func TestGeneratedAgentProofBindsVMAndComputation(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	method := agent.AgentService_Result_FullMethodName
	proof, err := generateMetadata("vm-A", "run-1", auth.ConsumerRole, method, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, instanceID, id string
		wantErr              error
	}{
		{"same VM and run", "vm-A", "run-1", nil},
		{"different VM with reused run ID", "vm-B", "run-1", auth.ErrSignatureVerificationFailed},
		{"different run in same VM", "vm-A", "run-2", auth.ErrSignatureVerificationFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			verifier, err := auth.New(agent.Computation{
				ID:              test.id,
				Algorithm:       agent.Algorithm{UserKey: keyDER},
				ResultConsumers: []agent.ResultConsumer{{UserKey: keyDER}},
			}, test.instanceID)
			if err != nil {
				t.Fatal(err)
			}
			ctx := metadata.NewIncomingContext(context.Background(), proof.Copy())
			_, err = verifier.AuthenticateUser(ctx, auth.ConsumerRole, method)
			if !errors.Is(err, test.wantErr) || (test.wantErr == nil && err != nil) {
				t.Fatalf("AuthenticateUser() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}
