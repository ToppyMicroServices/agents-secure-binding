// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package production

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrAzureMAAToken   = errors.New("production: invalid Azure Attestation token")
	ErrAzureMAAKey     = errors.New("production: invalid Azure Attestation signing key")
	ErrAzureSNPClaims  = errors.New("production: invalid Azure SEV-SNP claims")
	ErrAzureSNPPolicy  = errors.New("production: Azure SEV-SNP policy mismatch")
	ErrAzureSNPBinding = errors.New("production: Azure SEV-SNP binding mismatch")
	ErrAzureSNPBridge  = errors.New("production: invalid Azure SEV-SNP bridge configuration")
)

const (
	AzureSNPChallengeVersion = "asb.azure-sevsnp.challenge/v1"
	AzureSNPAttestationType  = "sevsnpvm"
)

// AzureSNPTokenClaims is the normalized, signature-verified subset of an Azure
// Attestation token used by the production bridge.
type AzureSNPTokenClaims struct {
	TokenID          string
	Nonce            string
	PolicyHash       string
	Measurement      string
	AttestationType  string
	GuestSVN         uint64
	Debuggable       bool
	MigrationAllowed bool
	IssuedAt         time.Time
	ExpiresAt        time.Time
}

// AzureSNPTokenVerifier authenticates an Azure Attestation token and returns
// normalized SEV-SNP claims. Implementations must verify the token signature,
// issuer, lifetime, and key ID before returning claims.
type AzureSNPTokenVerifier interface {
	Verify(context.Context, string, time.Time) (AzureSNPTokenClaims, error)
}

// AzureMAATokenVerifier verifies RS256 Azure Attestation JWTs against a pinned
// issuer and a deployment-managed signing-key snapshot. It deliberately does
// not follow token-provided jku URLs or fetch keys during request acceptance.
type AzureMAATokenVerifier struct {
	Issuer         string
	TrustedKeys    map[string]*rsa.PublicKey
	DisabledKeyIDs []string
	MaxAge         time.Duration
	ClockSkew      time.Duration
}

// Verify authenticates one Azure Attestation JWT and extracts its SEV-SNP
// appraisal claims. Both the current nested guest-attestation claim layout and
// direct top-level SEV-SNP claims are accepted.
func (v AzureMAATokenVerifier) Verify(ctx context.Context, token string, now time.Time) (AzureSNPTokenClaims, error) {
	if ctx == nil {
		return AzureSNPTokenClaims{}, ErrMissingContext
	}
	if err := ctx.Err(); err != nil {
		return AzureSNPTokenClaims{}, err
	}
	if strings.TrimSpace(v.Issuer) == "" || len(v.TrustedKeys) == 0 || v.MaxAge <= 0 || v.ClockSkew < 0 {
		return AzureSNPTokenClaims{}, ErrAzureMAAToken
	}
	if strings.TrimSpace(token) == "" {
		return AzureSNPTokenClaims{}, ErrAzureMAAToken
	}
	if now.IsZero() {
		now = time.Now()
	}

	claims := jwt.MapClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(v.Issuer),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(v.ClockSkew),
		jwt.WithTimeFunc(func() time.Time { return now }),
	)
	parsed, err := parser.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		keyID, ok := token.Header["kid"].(string)
		if !ok || strings.TrimSpace(keyID) == "" {
			return nil, ErrAzureMAAKey
		}
		if contains(v.DisabledKeyIDs, keyID) {
			return nil, ErrAzureMAAKey
		}
		key, ok := v.TrustedKeys[keyID]
		if !ok || key == nil || key.N == nil || key.E < 3 {
			return nil, ErrAzureMAAKey
		}
		return key, nil
	})
	if err != nil || !parsed.Valid {
		return AzureSNPTokenClaims{}, fmt.Errorf("%w: signature, issuer, lifetime, or key validation failed", ErrAzureMAAToken)
	}

	normalized, err := normalizeAzureSNPClaims(claims)
	if err != nil {
		return AzureSNPTokenClaims{}, err
	}
	if normalized.IssuedAt.After(now.Add(v.ClockSkew)) || now.Sub(normalized.IssuedAt) > v.MaxAge+v.ClockSkew {
		return AzureSNPTokenClaims{}, ErrAzureMAAToken
	}
	return normalized, nil
}

// AzureSNPAttestationBridge converts a verified Azure SEV-SNP appraisal into
// the role-separated ASB attestation-result format.
type AzureSNPAttestationBridge struct {
	TokenVerifier       AzureSNPTokenVerifier
	VerifierKeyID       string
	Signer              crypto.Signer
	PolicyID            string
	AllowedPolicyHashes []string
	AllowedMeasurements []string
	MinimumGuestSVN     uint64
	AllowDebug          bool
	AllowMigration      bool
	ResultTTL           time.Duration
}

// Issue authenticates an Azure token, enforces the deployment appraisal, and
// signs a short-lived ASB result bound to the exact expected ASB binder.
func (b AzureSNPAttestationBridge) Issue(
	ctx context.Context,
	token string,
	expectedBinder string,
	now time.Time,
) (AttestationResult, error) {
	if ctx == nil {
		return AttestationResult{}, ErrMissingContext
	}
	if b.TokenVerifier == nil || b.Signer == nil ||
		strings.TrimSpace(b.VerifierKeyID) == "" ||
		strings.TrimSpace(b.PolicyID) == "" ||
		len(b.AllowedPolicyHashes) == 0 ||
		len(b.AllowedMeasurements) == 0 ||
		b.ResultTTL <= 0 {
		return AttestationResult{}, ErrAzureSNPBridge
	}
	publicKey, ok := b.Signer.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return AttestationResult{}, ErrAzureSNPBridge
	}
	if strings.TrimSpace(expectedBinder) == "" || strings.TrimSpace(expectedBinder) != expectedBinder {
		return AttestationResult{}, ErrAzureSNPBinding
	}
	if now.IsZero() {
		now = time.Now()
	}

	claims, err := b.TokenVerifier.Verify(ctx, token, now)
	if err != nil {
		return AttestationResult{}, err
	}
	if claims.AttestationType != AzureSNPAttestationType ||
		!contains(b.AllowedPolicyHashes, claims.PolicyHash) ||
		!contains(b.AllowedMeasurements, claims.Measurement) ||
		claims.GuestSVN < b.MinimumGuestSVN ||
		(claims.Debuggable && !b.AllowDebug) ||
		(claims.MigrationAllowed && !b.AllowMigration) {
		return AttestationResult{}, ErrAzureSNPPolicy
	}
	expectedChallenge := AzureSNPChallenge(expectedBinder)
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(expectedChallenge)) != 1 {
		return AttestationResult{}, ErrAzureSNPBinding
	}
	if claims.IssuedAt.IsZero() || claims.ExpiresAt.IsZero() || !claims.ExpiresAt.After(now) {
		return AttestationResult{}, ErrAzureMAAToken
	}

	expiresAt := now.Add(b.ResultTTL)
	if claims.ExpiresAt.Before(expiresAt) {
		expiresAt = claims.ExpiresAt
	}
	result := AttestationResult{
		Version:                 AttestationResultVersion,
		ResultID:                claims.TokenID,
		VerifierKeyID:           b.VerifierKeyID,
		PolicyID:                b.PolicyID,
		Measurement:             claims.Measurement,
		AttestationBinderSHA256: expectedBinder,
		IssuedAt:                now.UTC(),
		ExpiresAt:               expiresAt.UTC(),
	}
	payload, err := result.SigningBytes()
	if err != nil {
		return AttestationResult{}, err
	}
	result.Signature, err = b.Signer.Sign(rand.Reader, payload, crypto.Hash(0))
	if err != nil || len(result.Signature) != ed25519.SignatureSize {
		return AttestationResult{}, ErrAzureSNPBridge
	}
	if !ed25519.Verify(publicKey, payload, result.Signature) {
		return AttestationResult{}, ErrAzureSNPBridge
	}
	return result, nil
}

// AzureSNPChallenge returns the nonce supplied to Azure guest attestation for
// one ASB binder. The returned ASCII value is safe for the MAA nonce claim.
func AzureSNPChallenge(expectedBinder string) string {
	digest := sha256.Sum256([]byte(AzureSNPChallengeVersion + "\x00" + expectedBinder))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func normalizeAzureSNPClaims(claims jwt.MapClaims) (AzureSNPTokenClaims, error) {
	schemaVersion, _ := claims["x-ms-ver"].(string)
	if schemaVersion != "1.0" {
		return AzureSNPTokenClaims{}, ErrAzureSNPClaims
	}
	teeClaims := map[string]any(claims)
	if nested, ok := claims["x-ms-isolation-tee"].(map[string]any); ok {
		teeClaims = nested
	}

	issuedAt, err := claims.GetIssuedAt()
	if err != nil || issuedAt == nil {
		return AzureSNPTokenClaims{}, ErrAzureSNPClaims
	}
	expiresAt, err := claims.GetExpirationTime()
	if err != nil || expiresAt == nil {
		return AzureSNPTokenClaims{}, ErrAzureSNPClaims
	}
	tokenID, _ := claims["jti"].(string)
	nonce, _ := claims["nonce"].(string)
	policyHash, _ := claims["x-ms-policy-hash"].(string)
	measurement, _ := teeClaims["x-ms-sevsnpvm-launchmeasurement"].(string)
	attestationType, _ := teeClaims["x-ms-attestation-type"].(string)
	if attestationType == "" {
		attestationType, _ = claims["x-ms-attestation-type"].(string)
	}
	guestSVN, ok := exactUint64(teeClaims["x-ms-sevsnpvm-guestsvn"])
	if !ok {
		return AzureSNPTokenClaims{}, ErrAzureSNPClaims
	}
	debuggable, ok := teeClaims["x-ms-sevsnpvm-is-debuggable"].(bool)
	if !ok {
		return AzureSNPTokenClaims{}, ErrAzureSNPClaims
	}
	migrationAllowed, ok := teeClaims["x-ms-sevsnpvm-migration-allowed"].(bool)
	if !ok {
		return AzureSNPTokenClaims{}, ErrAzureSNPClaims
	}

	for _, value := range []string{tokenID, nonce, policyHash, measurement, attestationType} {
		if strings.TrimSpace(value) == "" || strings.TrimSpace(value) != value || len(value) > 4096 {
			return AzureSNPTokenClaims{}, ErrAzureSNPClaims
		}
	}
	return AzureSNPTokenClaims{
		TokenID:          tokenID,
		Nonce:            nonce,
		PolicyHash:       policyHash,
		Measurement:      measurement,
		AttestationType:  attestationType,
		GuestSVN:         guestSVN,
		Debuggable:       debuggable,
		MigrationAllowed: migrationAllowed,
		IssuedAt:         issuedAt.Time,
		ExpiresAt:        expiresAt.Time,
	}, nil
}

func exactUint64(value any) (uint64, bool) {
	switch typed := value.(type) {
	case float64:
		if typed < 0 || typed > math.MaxUint64 || math.Trunc(typed) != typed {
			return 0, false
		}
		return uint64(typed), true
	case uint64:
		return typed, true
	case int:
		if typed < 0 {
			return 0, false
		}
		return uint64(typed), true
	default:
		return 0, false
	}
}
