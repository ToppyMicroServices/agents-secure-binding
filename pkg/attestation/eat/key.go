// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package eat

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

var (
	ErrInvalidSigningKey      = errors.New("invalid EAT signing key")
	ErrInvalidVerificationKey = errors.New("invalid EAT verification key")
)

// LoadSigningKey loads an ES256 private key from a PEM-encoded SEC 1 or PKCS#8
// file. Private key files with group or other permission bits are rejected.
func LoadSigningKey(path string) (*ecdsa.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSigningKey, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: not a regular file", ErrInvalidSigningKey)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: private key file permissions must not grant group or other access", ErrInvalidSigningKey)
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSigningKey, err)
	}
	block, _ := pem.Decode(encoded)
	if block == nil {
		return nil, fmt.Errorf("%w: PEM block not found", ErrInvalidSigningKey)
	}

	if key, parseErr := x509.ParseECPrivateKey(block.Bytes); parseErr == nil {
		return validateSigningKey(key)
	}
	parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
	if parseErr != nil {
		return nil, fmt.Errorf("%w: unsupported private key encoding", ErrInvalidSigningKey)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: expected ECDSA private key", ErrInvalidSigningKey)
	}
	return validateSigningKey(key)
}

// LoadVerificationKey loads an ES256 public key from a PEM-encoded PKIX public
// key or X.509 certificate.
func LoadVerificationKey(path string) (*ecdsa.PublicKey, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidVerificationKey, err)
	}
	block, _ := pem.Decode(encoded)
	if block == nil {
		return nil, fmt.Errorf("%w: PEM block not found", ErrInvalidVerificationKey)
	}

	if parsed, parseErr := x509.ParsePKIXPublicKey(block.Bytes); parseErr == nil {
		key, ok := parsed.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: expected ECDSA public key", ErrInvalidVerificationKey)
		}
		return validateVerificationKey(key)
	}
	certificate, parseErr := x509.ParseCertificate(block.Bytes)
	if parseErr != nil {
		return nil, fmt.Errorf("%w: unsupported public key encoding", ErrInvalidVerificationKey)
	}
	key, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: certificate does not contain an ECDSA public key", ErrInvalidVerificationKey)
	}
	return validateVerificationKey(key)
}

// VerificationKeyFingerprint returns the SHA-256 fingerprint of a public key's
// PKIX encoding.
func VerificationKeyFingerprint(key *ecdsa.PublicKey) (string, error) {
	key, err := validateVerificationKey(key)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", fmt.Errorf("marshal EAT verification key: %w", err)
	}
	digest := sha256.Sum256(der)
	return hex.EncodeToString(digest[:]), nil
}

func validateSigningKey(key *ecdsa.PrivateKey) (*ecdsa.PrivateKey, error) {
	if key == nil || key.Curve != elliptic.P256() || key.D == nil {
		return nil, fmt.Errorf("%w: ES256 requires a P-256 private key", ErrInvalidSigningKey)
	}
	return key, nil
}

func validateVerificationKey(key *ecdsa.PublicKey) (*ecdsa.PublicKey, error) {
	if key == nil || key.Curve != elliptic.P256() || key.X == nil || key.Y == nil || !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, fmt.Errorf("%w: ES256 requires a valid P-256 public key", ErrInvalidVerificationKey)
	}
	return key, nil
}
