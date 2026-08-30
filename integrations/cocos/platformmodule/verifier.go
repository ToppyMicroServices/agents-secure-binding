// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

// Package platformmodule contains the experimental compatibility adapter that
// connects platform evidence appraisal to ASB's platform-neutral evidence
// verifier interface. A verifier is pinned to one locally configured platform;
// peer-provided EAT claims are checked for consistency and never select an
// appraiser.
//
// This package is not production qualification. It preserves the repository's
// legacy platform appraisers. Deployments remain responsible for qualifying
// each selected appraiser's quote-signature, endorsement-chain, collateral,
// revocation, TCB, debug-policy, measurement-policy, and freshness behavior.
package platformmodule

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	snpmodule "github.com/ToppyMicroServices/agents-secure-binding/modules/attestation/snp"
	tdxmodule "github.com/ToppyMicroServices/agents-secure-binding/modules/attestation/tdx"
	eaattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/eaattestation"
	asbattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/eat"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/tdx"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/vtpm"
	"github.com/google/go-sev-guest/proto/sevsnp"
	sevvalidate "github.com/google/go-sev-guest/validate"
	sevverify "github.com/google/go-sev-guest/verify"
	tdxcheckconfig "github.com/google/go-tdx-guest/proto/checkconfig"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/veraison/corim/corim"
	"google.golang.org/protobuf/proto"
)

var (
	ErrUnsupportedPlatform = errors.New("attestation platform module: unsupported locally configured platform")
	ErrPlatformMismatch    = errors.New("attestation platform module: evidence platform does not match locally configured platform")
	ErrPolicyUnavailable   = errors.New("attestation platform module: policy file is unavailable")
	ErrInvalidSNPEvidence  = errors.New("attestation platform module: invalid direct SNP evidence")
	ErrEATTrustUnavailable = errors.New("attestation platform module: EAT trust configuration is unavailable")
	ErrSNPPolicyRequired   = errors.New("attestation platform module: direct SNP verification policy is required")
	ErrSNPVerification     = errors.New("attestation platform module: direct SNP cryptographic verification failed")
	ErrSNPValidation       = errors.New("attestation platform module: direct SNP policy validation failed")
	ErrTDXPolicyRequired   = errors.New("attestation platform module: TDX verification policy is required")
	ErrTDXVerification     = errors.New("attestation platform module: TDX quote verification failed")
	ErrCoRIMTrustRequired  = errors.New("attestation platform module: signed CoRIM verification key is required")
	ErrCoRIMVerification   = errors.New("attestation platform module: signed CoRIM verification failed")
)

const (
	maxEATLifetime              = 5 * time.Minute
	maxEATClockSkew             = 30 * time.Second
	platformVerificationTimeout = 2 * time.Minute
)

// Platform identifies the appraiser selected by trusted local configuration.
// Its zero value is invalid. It is not a wire value and must not be populated
// from peer-provided evidence.
type Platform string

const (
	PlatformSNP Platform = "snp"
	PlatformTDX Platform = "tdx"
)

type policyEvidenceVerifier struct {
	platform               Platform
	policyPath             string
	eatVerificationKey     *ecdsa.PublicKey
	corimVerificationKey   *ecdsa.PublicKey
	expectedIssuer         string
	snpVerificationOptions *sevverify.Options
	snpValidationOptions   *sevvalidate.Options
	tdxPolicy              *tdxcheckconfig.Config
	tdxRuntime             *tdxmodule.RuntimeOptions
}

var _ eaattestation.EvidenceVerifier = (*policyEvidenceVerifier)(nil)

// VerifierConfig contains trust configuration selected by the local ASB
// deployment. None of these values may be derived from peer evidence.
type VerifierConfig struct {
	Platform               Platform
	PolicyPath             string
	EATVerificationKey     *ecdsa.PublicKey
	CoRIMVerificationKey   *ecdsa.PublicKey
	ExpectedIssuer         string
	SNPVerificationOptions *sevverify.Options
	SNPValidationOptions   *sevvalidate.Options
	TDXPolicy              *tdxcheckconfig.Config
	// TDXRuntimeOptions permits a reviewed collateral getter and fixed clock
	// for deterministic qualification. Nil uses the module's bounded HTTPS
	// getter and current time.
	TDXRuntimeOptions *tdxmodule.RuntimeOptions
}

// NewEvidenceVerifier constructs a compatibility verifier for exactly one
// locally selected platform. Evidence claiming a different platform is
// rejected; the claim never causes dispatch to another appraiser.
func NewEvidenceVerifier(config VerifierConfig) (eaattestation.EvidenceVerifier, error) {
	if !config.Platform.valid() {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedPlatform, config.Platform)
	}
	if err := validateEATTrustConfig(config.EATVerificationKey, config.ExpectedIssuer); err != nil {
		return nil, err
	}
	if config.Platform == PlatformSNP {
		if err := validateDirectSNPConfig(config.SNPVerificationOptions, config.SNPValidationOptions); err != nil {
			return nil, err
		}
	}
	if config.Platform == PlatformTDX {
		if err := validateTDXConfig(config.TDXPolicy); err != nil {
			return nil, err
		}
	}
	info, err := os.Stat(config.PolicyPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPolicyUnavailable, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: not a regular file", ErrPolicyUnavailable)
	}
	return &policyEvidenceVerifier{
		platform:               config.Platform,
		policyPath:             config.PolicyPath,
		eatVerificationKey:     cloneECDSAPublicKey(config.EATVerificationKey),
		corimVerificationKey:   cloneOptionalECDSAPublicKey(config.CoRIMVerificationKey),
		expectedIssuer:         config.ExpectedIssuer,
		snpVerificationOptions: cloneSNPVerificationOptions(config.SNPVerificationOptions),
		snpValidationOptions:   cloneSNPValidationOptions(config.SNPValidationOptions),
		tdxPolicy:              cloneTDXPolicy(config.TDXPolicy),
		tdxRuntime:             cloneTDXRuntimeOptions(config.TDXRuntimeOptions),
	}, nil
}

func (v *policyEvidenceVerifier) VerifyEvidence(evidence []byte, expected eaattestation.EvidenceBinding) error {
	if v == nil || !v.platform.valid() {
		return ErrUnsupportedPlatform
	}
	if v.policyPath == "" {
		return fmt.Errorf("attestation platform module: attestation policy path is not set")
	}
	claims, err := eat.DecodeVerifiedCBOR(evidence, v.eatVerificationKey)
	if err != nil {
		return fmt.Errorf("attestation platform module: failed to verify EAT evidence: %w", err)
	}
	if err := verifyEATProfile(claims, v.expectedIssuer, time.Now()); err != nil {
		return err
	}
	if !constantTimeEqual(claims.Nonce, expected.Nonce[:]) {
		return fmt.Errorf("attestation platform module: evidence nonce does not match TLS exporter binding")
	}
	claimedPlatform, err := platformFromEATClaim(claims.PlatformType)
	if err != nil {
		return err
	}
	if claimedPlatform != v.platform {
		return fmt.Errorf("%w: configured=%q evidence=%q", ErrPlatformMismatch, v.platform, claimedPlatform)
	}
	appraisalEvidence, err := v.prepareEvidenceForAppraisal(claims.RawReport, expected)
	if err != nil {
		return err
	}
	manifest, err := loadCoRIM(v.policyPath, v.corimVerificationKey, time.Now())
	if err != nil {
		return err
	}
	verifier, err := platformVerifier(v.platform)
	if err != nil {
		return err
	}
	return verifier.VerifyWithCoRIM(appraisalEvidence, manifest)
}

func validateEATTrustConfig(key *ecdsa.PublicKey, expectedIssuer string) error {
	if key == nil || key.Curve != elliptic.P256() || key.X == nil || key.Y == nil || !key.Curve.IsOnCurve(key.X, key.Y) {
		return fmt.Errorf("%w: a valid P-256 verification key is required", ErrEATTrustUnavailable)
	}
	if expectedIssuer == "" {
		return fmt.Errorf("%w: expected issuer is required", ErrEATTrustUnavailable)
	}
	return nil
}

func validateDirectSNPConfig(verification *sevverify.Options, validation *sevvalidate.Options) error {
	if err := snpmodule.ValidateConfig(verification, validation); err != nil {
		return fmt.Errorf("%w: %v", ErrSNPPolicyRequired, err)
	}
	return nil
}

func validateTDXConfig(policy *tdxcheckconfig.Config) error {
	if err := tdxmodule.ValidateConfig(policy); err != nil {
		return fmt.Errorf("%w: %v", ErrTDXPolicyRequired, err)
	}
	return nil
}

func cloneECDSAPublicKey(key *ecdsa.PublicKey) *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: key.Curve,
		X:     new(big.Int).Set(key.X),
		Y:     new(big.Int).Set(key.Y),
	}
}

func cloneOptionalECDSAPublicKey(key *ecdsa.PublicKey) *ecdsa.PublicKey {
	if key == nil {
		return nil
	}
	return cloneECDSAPublicKey(key)
}

func cloneSNPVerificationOptions(options *sevverify.Options) *sevverify.Options {
	if options == nil {
		return nil
	}
	clone := *options
	if options.Product != nil {
		clone.Product = proto.Clone(options.Product).(*sevsnp.SevProduct)
	}
	return &clone
}

func cloneSNPValidationOptions(options *sevvalidate.Options) *sevvalidate.Options {
	if options == nil {
		return nil
	}
	clone := *options
	return &clone
}

func cloneTDXPolicy(policy *tdxcheckconfig.Config) *tdxcheckconfig.Config {
	if policy == nil {
		return nil
	}
	return proto.Clone(policy).(*tdxcheckconfig.Config)
}

func cloneTDXRuntimeOptions(runtime *tdxmodule.RuntimeOptions) *tdxmodule.RuntimeOptions {
	if runtime == nil {
		return nil
	}
	clone := *runtime
	return &clone
}

func verifyEATProfile(claims *eat.EATClaims, expectedIssuer string, now time.Time) error {
	if claims == nil {
		return fmt.Errorf("attestation platform module: EAT claims are missing")
	}
	if claims.Issuer != expectedIssuer {
		return fmt.Errorf("attestation platform module: EAT issuer mismatch")
	}
	if claims.IssuedAt <= 0 || claims.ExpiresAt <= claims.IssuedAt {
		return fmt.Errorf("attestation platform module: invalid EAT validity interval")
	}
	if claims.ExpiresAt-claims.IssuedAt > int64(maxEATLifetime/time.Second) {
		return fmt.Errorf("attestation platform module: EAT validity interval exceeds %s", maxEATLifetime)
	}
	nowUnix := now.Unix()
	if claims.IssuedAt > nowUnix+int64(maxEATClockSkew/time.Second) {
		return fmt.Errorf("attestation platform module: EAT is not yet valid")
	}
	if claims.ExpiresAt < nowUnix-int64(maxEATClockSkew/time.Second) {
		return fmt.Errorf("attestation platform module: EAT has expired")
	}
	return nil
}

// prepareEvidenceForAppraisal validates the ASB binding and converts only the
// direct SNP wire representations into the legacy wrapper expected by the
// existing CoRIM appraiser. The peer-controlled platform claim never selects
// this conversion; the caller supplies the locally configured platform.
func (v *policyEvidenceVerifier) prepareEvidenceForAppraisal(report []byte, expected eaattestation.EvidenceBinding) ([]byte, error) {
	if v.platform == PlatformTDX {
		ctx, cancel := context.WithTimeout(context.Background(), platformVerificationTimeout)
		defer cancel()
		if err := tdxmodule.Verify(ctx, report, expected.ReportData[:], cloneTDXPolicy(v.tdxPolicy), cloneTDXRuntimeOptions(v.tdxRuntime)); err != nil {
			return nil, translateTDXModuleError(err)
		}
		return report, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), platformVerificationTimeout)
	defer cancel()
	snpAttestation, err := snpmodule.Verify(
		ctx,
		report,
		expected.ReportData[:],
		cloneSNPVerificationOptions(v.snpVerificationOptions),
		cloneSNPValidationOptions(v.snpValidationOptions),
	)
	if err != nil {
		return nil, translateSNPModuleError(err)
	}

	wrapped, err := proto.Marshal(&attest.Attestation{
		TeeAttestation: &attest.Attestation_SevSnpAttestation{
			SevSnpAttestation: snpAttestation,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("%w: failed to wrap evidence for appraisal: %v", ErrInvalidSNPEvidence, err)
	}
	return wrapped, nil
}

func translateSNPModuleError(err error) error {
	switch {
	case errors.Is(err, snpmodule.ErrInvalidConfig):
		return fmt.Errorf("%w: %v", ErrSNPPolicyRequired, err)
	case errors.Is(err, snpmodule.ErrInvalidEvidence):
		return fmt.Errorf("%w: %v", ErrInvalidSNPEvidence, err)
	case errors.Is(err, snpmodule.ErrVerification):
		return fmt.Errorf("%w: %v", ErrSNPVerification, err)
	case errors.Is(err, snpmodule.ErrValidation):
		return fmt.Errorf("%w: %v", ErrSNPValidation, err)
	default:
		return err
	}
}

func translateTDXModuleError(err error) error {
	if errors.Is(err, tdxmodule.ErrPolicyRequired) {
		return fmt.Errorf("%w: %v", ErrTDXPolicyRequired, err)
	}
	return fmt.Errorf("%w: %v", ErrTDXVerification, err)
}

func constantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func loadCoRIM(path string, verificationKey *ecdsa.PublicKey, now time.Time) (*corim.UnsignedCorim, error) {
	corimBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("attestation platform module: failed to read CoRIM file: %w", err)
	}

	var uc corim.UnsignedCorim
	if err := uc.FromCBOR(corimBytes); err == nil {
		if verificationKey != nil {
			return nil, fmt.Errorf("%w: unsigned CoRIM supplied while a verification key is configured", ErrCoRIMVerification)
		}
		if err := validateCoRIMValidity(uc.RimValidity, now); err != nil {
			return nil, err
		}
		return &uc, nil
	}

	var sc corim.SignedCorim
	if err := sc.FromCOSE(corimBytes); err != nil {
		return nil, fmt.Errorf("attestation platform module: failed to parse CoRIM: %w", err)
	}
	if verificationKey == nil {
		return nil, ErrCoRIMTrustRequired
	}
	if err := sc.Meta.Valid(); err != nil {
		return nil, fmt.Errorf("%w: invalid signed CoRIM metadata: %v", ErrCoRIMVerification, err)
	}
	if err := sc.Verify(verificationKey); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCoRIMVerification, err)
	}
	if err := validateCoRIMValidity(sc.Meta.Validity, now); err != nil {
		return nil, err
	}
	if err := validateCoRIMValidity(sc.UnsignedCorim.RimValidity, now); err != nil {
		return nil, err
	}
	return &sc.UnsignedCorim, nil
}

func validateCoRIMValidity(validity *corim.Validity, now time.Time) error {
	if validity == nil {
		return nil
	}
	if validity.NotBefore != nil && now.Before(*validity.NotBefore) {
		return fmt.Errorf("%w: CoRIM is not yet valid", ErrCoRIMVerification)
	}
	if now.After(validity.NotAfter) {
		return fmt.Errorf("%w: CoRIM has expired", ErrCoRIMVerification)
	}
	return nil
}

func platformFromEATClaim(name string) (Platform, error) {
	switch name {
	case "SNP":
		return PlatformSNP, nil
	case "TDX":
		return PlatformTDX, nil
	default:
		return "", fmt.Errorf("%w: EAT claim %q", ErrUnsupportedPlatform, name)
	}
}

func platformVerifier(platform Platform) (asbattestation.Verifier, error) {
	switch platform {
	case PlatformSNP:
		return vtpm.NewVerifier(nil), nil
	case PlatformTDX:
		return tdx.NewVerifier(), nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedPlatform, platform)
	}
}

func (p Platform) valid() bool {
	switch p {
	case PlatformSNP, PlatformTDX:
		return true
	default:
		return false
	}
}
