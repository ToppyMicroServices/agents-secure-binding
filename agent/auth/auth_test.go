// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

const (
	testInstanceID    = "test-vm"
	testComputationID = "test-computation"
)

func TestAuthenticateUser(t *testing.T) {
	resultConsumerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	dataProviderKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubEd25519Key, algorithmProviderKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	resultConsumerPubKey, err := x509.MarshalPKIXPublicKey(&resultConsumerKey.PublicKey)
	require.NoError(t, err)

	dataProviderPubKey, err := x509.MarshalPKIXPublicKey(&dataProviderKey.PublicKey)
	require.NoError(t, err)

	algorithmProviderPubKey, err := x509.MarshalPKIXPublicKey(pubEd25519Key)
	require.NoError(t, err)

	manifest := agent.Computation{
		ID:              testComputationID,
		ResultConsumers: []agent.ResultConsumer{{UserKey: resultConsumerPubKey}},
		Datasets:        []agent.Dataset{{UserKey: dataProviderPubKey}},
		Algorithm:       agent.Algorithm{UserKey: algorithmProviderPubKey},
	}

	auth, err := New(manifest, testInstanceID)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	testCases := []struct {
		name        string
		role        UserRole
		method      string
		key         any
		expectedErr error
	}{
		{
			name:        "valid result consumer",
			role:        ConsumerRole,
			method:      agent.AgentService_Result_FullMethodName,
			key:         resultConsumerKey,
			expectedErr: nil,
		},
		{
			name:        "valid data provider",
			role:        DataProviderRole,
			method:      agent.AgentService_Data_FullMethodName,
			key:         dataProviderKey,
			expectedErr: nil,
		},
		{
			name:        "valid algorithm provider",
			role:        AlgorithmProviderRole,
			method:      agent.AgentService_Algo_FullMethodName,
			key:         algorithmProviderKey,
			expectedErr: nil,
		},
		{
			name:        "invalid role",
			role:        "invalid-role",
			method:      "invalid-method",
			key:         resultConsumerKey,
			expectedErr: ErrSignatureVerificationFailed,
		},
		{
			name:        "invalid key",
			role:        ConsumerRole,
			method:      agent.AgentService_Result_FullMethodName,
			key:         dataProviderKey,
			expectedErr: ErrSignatureVerificationFailed,
		},
		{
			name:        "missing signature",
			role:        ConsumerRole,
			method:      agent.AgentService_Result_FullMethodName,
			key:         resultConsumerKey,
			expectedErr: ErrInvalidMetadata,
		},
		{
			name:        "missing metadata",
			role:        ConsumerRole,
			method:      agent.AgentService_Result_FullMethodName,
			key:         resultConsumerKey,
			expectedErr: ErrMissingMetadata,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			issuedAt := time.Now().UTC().Format(time.RFC3339Nano)
			nonce := tc.name
			signature, err := signRole(manifest.ID, tc.role, tc.method, issuedAt, nonce, tc.key)
			if err != nil {
				t.Fatalf("failed to sign role: %v", err)
			}

			ctx := context.Background()

			switch tc.name {
			case "missing signature":
				ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(
					SignatureTimestampMetadataKey, issuedAt,
					SignatureNonceMetadataKey, nonce,
				))
			case "missing metadata":
			default:
				ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(
					SignatureMetadataKey, signature,
					SignatureTimestampMetadataKey, issuedAt,
					SignatureNonceMetadataKey, nonce,
				))
			}

			ctx, err = auth.AuthenticateUser(ctx, tc.role, tc.method)
			assert.True(t, errors.Contains(err, tc.expectedErr), "expected error %v, got %v", tc.expectedErr, err)

			if err == nil {
				switch id, ok := agent.IndexFromContext(ctx); {
				case tc.role == ConsumerRole:
					assert.True(t, ok, "expected index in context")
					assert.Equal(t, 0, id, "expected index 0 in context")
				default:
					assert.False(t, ok, "expected no index in context")
				}
			}
		})
	}
}

func TestAuthenticateUserRejectsReplay(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	require.NoError(t, err)

	authSvc, err := New(agent.Computation{
		ID:        testComputationID,
		Algorithm: agent.Algorithm{UserKey: pubKeyBytes},
	}, testInstanceID)
	require.NoError(t, err)

	issuedAt := time.Now().UTC().Format(time.RFC3339Nano)
	nonce := "replayed-nonce"
	signature, err := signRole(testComputationID, AlgorithmProviderRole, agent.AgentService_Algo_FullMethodName, issuedAt, nonce, privKey)
	require.NoError(t, err)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		SignatureMetadataKey, signature,
		SignatureTimestampMetadataKey, issuedAt,
		SignatureNonceMetadataKey, nonce,
	))

	_, err = authSvc.AuthenticateUser(ctx, AlgorithmProviderRole, agent.AgentService_Algo_FullMethodName)
	require.NoError(t, err)

	_, err = authSvc.AuthenticateUser(ctx, AlgorithmProviderRole, agent.AgentService_Algo_FullMethodName)
	assert.ErrorIs(t, err, ErrReplayDetected)
}

func TestAuthenticateUserBindsSignatureToMethod(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	require.NoError(t, err)

	authSvc, err := New(agent.Computation{
		ID:        testComputationID,
		Algorithm: agent.Algorithm{UserKey: pubKeyBytes},
	}, testInstanceID)
	require.NoError(t, err)

	issuedAt := time.Now().UTC().Format(time.RFC3339Nano)
	nonce := "method-bound-nonce"
	signature, err := signRole(testComputationID, AlgorithmProviderRole, agent.AgentService_Data_FullMethodName, issuedAt, nonce, privKey)
	require.NoError(t, err)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		SignatureMetadataKey, signature,
		SignatureTimestampMetadataKey, issuedAt,
		SignatureNonceMetadataKey, nonce,
	))

	_, err = authSvc.AuthenticateUser(ctx, AlgorithmProviderRole, agent.AgentService_Algo_FullMethodName)
	assert.ErrorIs(t, err, ErrSignatureVerificationFailed)
}

func TestAuthenticateUserRejectsExpiredSignature(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	require.NoError(t, err)

	authSvc, err := New(agent.Computation{
		ID:        testComputationID,
		Algorithm: agent.Algorithm{UserKey: pubKeyBytes},
	}, testInstanceID)
	require.NoError(t, err)

	issuedAt := time.Now().Add(-maxSignatureAge - time.Minute).UTC().Format(time.RFC3339Nano)
	nonce := "expired-nonce"
	signature, err := signRole(testComputationID, AlgorithmProviderRole, agent.AgentService_Algo_FullMethodName, issuedAt, nonce, privKey)
	require.NoError(t, err)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		SignatureMetadataKey, signature,
		SignatureTimestampMetadataKey, issuedAt,
		SignatureNonceMetadataKey, nonce,
	))

	_, err = authSvc.AuthenticateUser(ctx, AlgorithmProviderRole, agent.AgentService_Algo_FullMethodName)
	assert.ErrorIs(t, err, ErrSignatureExpired)
}

func TestNewRequiresComputationID(t *testing.T) {
	for _, id := range []string{"", " \t"} {
		_, err := New(agent.Computation{ID: id}, testInstanceID)
		assert.ErrorIs(t, err, ErrMissingComputationID)
	}
}

func TestNewRequiresInstanceID(t *testing.T) {
	for _, id := range []string{"", " \t"} {
		_, err := New(agent.Computation{ID: testComputationID}, id)
		assert.ErrorIs(t, err, ErrMissingInstanceID)
	}
}

func TestAuthenticateUserRejectsLegacyUnscopedSignatures(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	require.NoError(t, err)
	authSvc, err := New(agent.Computation{ID: testComputationID, Algorithm: agent.Algorithm{UserKey: pubKeyBytes}}, testInstanceID)
	require.NoError(t, err)

	issuedAt := time.Now().UTC().Format(time.RFC3339Nano)
	for _, test := range []struct {
		name, payload string
	}{
		{"v1 without scope", fmt.Sprintf("agents-secure-binding-agent-auth-v1\nrole=%s\nmethod=%s\nissued_at=%s\nnonce=%s", AlgorithmProviderRole, agent.AgentService_Algo_FullMethodName, issuedAt, "legacy-unscoped")},
		{"v2 without VM", fmt.Sprintf("agents-secure-binding-agent-auth-v2\ncomputation_id=%d:%s\nrole=%s\nmethod=%s\nissued_at=%s\nnonce=%s", len(testComputationID), testComputationID, AlgorithmProviderRole, agent.AgentService_Algo_FullMethodName, issuedAt, "legacy-unscoped")},
	} {
		t.Run(test.name, func(t *testing.T) {
			nonce := "legacy-unscoped"
			signature := base64.StdEncoding.EncodeToString(ed25519.Sign(privKey, []byte(test.payload)))
			ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
				SignatureMetadataKey, signature,
				SignatureTimestampMetadataKey, issuedAt,
				SignatureNonceMetadataKey, nonce,
			))
			_, err := authSvc.AuthenticateUser(ctx, AlgorithmProviderRole, agent.AgentService_Algo_FullMethodName)
			assert.ErrorIs(t, err, ErrSignatureVerificationFailed)
		})
	}
}

func TestSignaturePayloadSeparatesComputationIDs(t *testing.T) {
	role := ConsumerRole
	method := agent.AgentService_Result_FullMethodName
	issuedAt := "2026-10-29T00:00:00Z"
	nonce := "same-nonce"
	first := SignaturePayload(testInstanceID, "computation-A", role, method, issuedAt, nonce)
	for _, id := range []string{"computation-B", "computation-A\nrole=consumer", "computation-A\nmethod=" + method} {
		assert.NotEqual(t, first, SignaturePayload(testInstanceID, id, role, method, issuedAt, nonce))
	}
	for _, id := range []string{"other-vm", "test-vm\ncomputation_id=computation-A"} {
		assert.NotEqual(t, first, SignaturePayload(id, "computation-A", role, method, issuedAt, nonce))
	}
}

func signRole(computationID string, role UserRole, method, issuedAt, nonce string, key crypto.PrivateKey) (string, error) {
	var signature []byte
	var err error
	payload := SignaturePayload(testInstanceID, computationID, role, method, issuedAt, nonce)

	switch k := key.(type) {
	case ed25519.PrivateKey:
		signature, err = k.Sign(rand.Reader, payload, crypto.Hash(0))
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
		hash := sha256.Sum256(payload)
		signer := key.(crypto.Signer)
		signature, err = signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	default:
		return "", errors.New("unsupported key type")
	}

	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}
