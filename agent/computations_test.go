// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"golang.org/x/crypto/sha3"
	"google.golang.org/grpc/metadata"
)

func TestDatasetsString(t *testing.T) {
	datasets := Datasets{
		{
			Hash:     [32]byte{1, 2, 3},
			UserKey:  []byte("user_key"),
			Filename: "test.dat",
		},
	}

	expected := `[{"hash":[1,2,3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"user_key":"dXNlcl9rZXk=","filename":"test.dat"}]`
	result := datasets.String()

	if result != expected {
		t.Errorf("Datasets.String() = %v, want %v", result, expected)
	}
}

func TestAlgorithmCommitmentPreservesOnlySafeLegacyCase(t *testing.T) {
	program := []byte("program")
	if got, want := AlgorithmCommitment("", nil, program, nil), sha3.Sum256(program); got != want {
		t.Fatalf("legacy binary commitment = %x, want %x", got, want)
	}
	if got, want := AlgorithmCommitment("python", nil, program, nil), ExecutionBundleHash("python", nil, program, nil); got != want {
		t.Fatalf("python commitment = %x, want %x", got, want)
	}
}

func TestExecutionBundleHashBindsEveryRuntimeInput(t *testing.T) {
	base := ExecutionBundleHash("python", []string{"--mode=strict"}, []byte("print('ok')"), []byte("pkg==1.0\n"))
	variants := [][32]byte{
		ExecutionBundleHash("bin", []string{"--mode=strict"}, []byte("print('ok')"), []byte("pkg==1.0\n")),
		ExecutionBundleHash("python", []string{"--mode=other"}, []byte("print('ok')"), []byte("pkg==1.0\n")),
		ExecutionBundleHash("python", []string{"--mode=strict"}, []byte("print('changed')"), []byte("pkg==1.0\n")),
		ExecutionBundleHash("python", []string{"--mode=strict"}, []byte("print('ok')"), []byte("pkg==2.0\n")),
	}
	for i, variant := range variants {
		if variant == base {
			t.Fatalf("runtime input mutation %d did not change bundle hash", i)
		}
	}
}

func TestIndexToContext(t *testing.T) {
	ctx := context.Background()
	index := 5

	newCtx := IndexToContext(ctx, index)
	result, ok := IndexFromContext(newCtx)

	if !ok {
		t.Errorf("IndexFromContext() ok = false, want true")
	}

	if result != index {
		t.Errorf("IndexFromContext() = %v, want %v", result, index)
	}
}

func TestDecompressFromContext(t *testing.T) {
	tests := []struct {
		name     string
		ctx      context.Context
		expected bool
	}{
		{
			name:     "No decompress metadata",
			ctx:      context.Background(),
			expected: false,
		},
		{
			name: "Decompress true",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs(DecompressKey, "true"),
			),
			expected: true,
		},
		{
			name: "Decompress false",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs(DecompressKey, "false"),
			),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DecompressFromContext(tt.ctx)
			if result != tt.expected {
				t.Errorf("DecompressFromContext() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDecompressToContext(t *testing.T) {
	ctx := context.Background()
	decompress := true

	newCtx := DecompressToContext(ctx, decompress)
	md, ok := metadata.FromOutgoingContext(newCtx)

	if !ok {
		t.Errorf("metadata.FromOutgoingContext() ok = false, want true")
	}

	vals := md.Get(DecompressKey)
	if len(vals) != 1 {
		t.Errorf("len(md.Get(DecompressKey)) = %v, want 1", len(vals))
	}

	if vals[0] != "true" {
		t.Errorf("md.Get(DecompressKey)[0] = %v, want 'true'", vals[0])
	}
}

func TestAgentConfigJSON(t *testing.T) {
	cfg := AgentConfig{
		CertFile:     "cert.pem",
		KeyFile:      "key.pem",
		ServerCAFile: "server-ca.pem",
		ClientCAFile: "client-ca.pem",
		AttestedTls:  true,
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Failed to marshal AgentConfig: %v", err)
	}

	var unmarshaledConfig AgentConfig
	err = json.Unmarshal(data, &unmarshaledConfig)
	if err != nil {
		t.Fatalf("Failed to unmarshal AgentConfig: %v", err)
	}

	if !reflect.DeepEqual(cfg, unmarshaledConfig) {
		t.Errorf("Unmarshaled config does not match original. Got %+v, want %+v", unmarshaledConfig, cfg)
	}
}
