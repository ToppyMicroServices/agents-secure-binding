// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type UserRole string

const (
	UserMetadataKey               = "user-id"
	SignatureMetadataKey          = "signature"
	SignatureTimestampMetadataKey = "signature-timestamp"
	SignatureNonceMetadataKey     = "signature-nonce"

	signaturePayloadVersion = "agents-secure-binding-agent-auth-v1"
	maxSignatureAge         = 5 * time.Minute
	maxSignatureFutureSkew  = time.Minute

	ConsumerRole          UserRole = "consumer"
	DataProviderRole      UserRole = "data-provider"
	AlgorithmProviderRole UserRole = "algorithm-provider"
)

var (
	ErrMissingMetadata             = errors.New("missing metadata")
	ErrInvalidMetadata             = errors.New("invalid metadata")
	ErrSignatureVerificationFailed = errors.New("signature verification failed")
	ErrSignatureExpired            = errors.New("signature timestamp outside allowed window")
	ErrReplayDetected              = errors.New("signature nonce has already been used")
)

type Authenticator interface {
	AuthenticateUser(ctx context.Context, role UserRole, method string) (context.Context, error)
}

type service struct {
	mu                sync.Mutex
	resultConsumers   []any
	datasetProviders  []any
	algorithmProvider any
	seenNonces        map[string]time.Time
}

func New(manifest agent.Computation) (Authenticator, error) {
	s := &service{
		seenNonces: make(map[string]time.Time),
	}
	for _, rc := range manifest.ResultConsumers {
		pubKey, err := x509.ParsePKIXPublicKey(rc.UserKey)
		if err != nil {
			return nil, err
		}

		pKey, err := decodePublicKey(pubKey)
		if err != nil {
			return nil, err
		}

		s.resultConsumers = append(s.resultConsumers, pKey)
	}

	for _, dp := range manifest.Datasets {
		pubKey, err := x509.ParsePKIXPublicKey(dp.UserKey)
		if err != nil {
			return nil, err
		}

		pKey, err := decodePublicKey(pubKey)
		if err != nil {
			return nil, err
		}

		s.datasetProviders = append(s.datasetProviders, pKey)
	}

	pubKey, err := x509.ParsePKIXPublicKey(manifest.Algorithm.UserKey)
	if err != nil {
		return nil, err
	}

	pKey, err := decodePublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	s.algorithmProvider = pKey
	return s, nil
}

func extractMetadataValue(md metadata.MD, key string) (string, error) {
	values := md.Get(key)
	if len(values) != 1 || values[0] == "" {
		return "", status.Errorf(codes.Unauthenticated, "invalid metadata")
	}

	return values[0], nil
}

func extractSignature(md metadata.MD) (string, error) {
	return extractMetadataValue(md, SignatureMetadataKey)
}

func verifySignature(role UserRole, method, issuedAt, nonce, signature string, publicKey any) error {
	payload := signaturePayload(role, method, issuedAt, nonce)
	hash := sha256.Sum256(payload)
	sigByte, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	var ok bool

	switch publicKey := publicKey.(type) {
	case *rsa.PublicKey:
		if err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], sigByte); err != nil {
			return err
		}
		return nil
	case *ecdsa.PublicKey:
		ok = ecdsa.VerifyASN1(publicKey, hash[:], sigByte)
	case ed25519.PublicKey:
		ok = ed25519.Verify(publicKey, payload, sigByte)
	}

	if !ok {
		return ErrSignatureVerificationFailed
	}

	return nil
}

func (s *service) AuthenticateUser(ctx context.Context, role UserRole, method string) (context.Context, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, ErrMissingMetadata
	}
	signature, err := extractSignature(md)
	if err != nil {
		return nil, errors.Wrap(err, ErrInvalidMetadata)
	}
	issuedAt, err := extractMetadataValue(md, SignatureTimestampMetadataKey)
	if err != nil {
		return nil, errors.Wrap(err, ErrInvalidMetadata)
	}
	nonce, err := extractMetadataValue(md, SignatureNonceMetadataKey)
	if err != nil {
		return nil, errors.Wrap(err, ErrInvalidMetadata)
	}
	issuedAtTime, err := time.Parse(time.RFC3339Nano, issuedAt)
	if err != nil {
		return nil, errors.Wrap(err, ErrInvalidMetadata)
	}
	if err := validateIssuedAt(issuedAtTime, time.Now()); err != nil {
		return nil, err
	}

	switch role {
	case ConsumerRole:
		for i, rc := range s.resultConsumers {
			if err := verifySignature(role, method, issuedAt, nonce, signature, rc); err == nil {
				if err := s.markNonce(role, method, nonce, issuedAtTime.Add(maxSignatureAge)); err != nil {
					return nil, err
				}
				return agent.IndexToContext(ctx, i), nil
			}
		}
	case DataProviderRole:
		for _, dp := range s.datasetProviders {
			if err := verifySignature(role, method, issuedAt, nonce, signature, dp); err == nil {
				if err := s.markNonce(role, method, nonce, issuedAtTime.Add(maxSignatureAge)); err != nil {
					return nil, err
				}
				return ctx, nil
			}
		}
	case AlgorithmProviderRole:
		if err := verifySignature(role, method, issuedAt, nonce, signature, s.algorithmProvider); err == nil {
			if err := s.markNonce(role, method, nonce, issuedAtTime.Add(maxSignatureAge)); err != nil {
				return nil, err
			}
			return ctx, nil
		}
	}

	return ctx, ErrSignatureVerificationFailed
}

func signaturePayload(role UserRole, method, issuedAt, nonce string) []byte {
	return []byte(fmt.Sprintf("%s\nrole=%s\nmethod=%s\nissued_at=%s\nnonce=%s", signaturePayloadVersion, role, method, issuedAt, nonce))
}

func SignaturePayload(role UserRole, method, issuedAt, nonce string) []byte {
	return signaturePayload(role, method, issuedAt, nonce)
}

func validateIssuedAt(issuedAt, now time.Time) error {
	if issuedAt.Before(now.Add(-maxSignatureAge)) || issuedAt.After(now.Add(maxSignatureFutureSkew)) {
		return ErrSignatureExpired
	}
	return nil
}

func (s *service) markNonce(role UserRole, method, nonce string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for key, expires := range s.seenNonces {
		if !expires.After(now) {
			delete(s.seenNonces, key)
		}
	}

	key := fmt.Sprintf("%s\x00%s\x00%s", role, method, nonce)
	if expires, ok := s.seenNonces[key]; ok && expires.After(now) {
		return ErrReplayDetected
	}
	s.seenNonces[key] = expiresAt
	return nil
}

func decodePublicKey(key any) (pubKey any, err error) {
	switch key := key.(type) {
	case *rsa.PublicKey:
		return key, nil
	case *ecdsa.PublicKey:
		return key, nil
	case ed25519.PublicKey:
		return key, nil
	default:
		return nil, errors.New("unsupported public key type")
	}
}
