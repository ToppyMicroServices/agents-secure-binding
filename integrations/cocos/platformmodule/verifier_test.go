// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package platformmodule

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	tdxmodule "github.com/ToppyMicroServices/agents-secure-binding/modules/attestation/tdx"
	eaattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/eaattestation"
	asbattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/corimgen"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/eat"
	sevabi "github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/sevsnp"
	sevtesting "github.com/google/go-sev-guest/testing"
	sevvalidate "github.com/google/go-sev-guest/validate"
	sevverify "github.com/google/go-sev-guest/verify"
	sevtrust "github.com/google/go-sev-guest/verify/trust"
	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxcheckconfig "github.com/google/go-tdx-guest/proto/checkconfig"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	tdxtestdata "github.com/google/go-tdx-guest/testing/testdata"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/veraison/corim/corim"
	"google.golang.org/protobuf/proto"
)

const testEATIssuer = "test-issuer"

type rejectingHTTPSGetter struct{}

func (rejectingHTTPSGetter) Get(url string) ([]byte, error) {
	return nil, fmt.Errorf("unexpected collateral request: %s", url)
}

type rejectingTDXGetter struct{}

func (rejectingTDXGetter) Get(url string) (map[string][]string, []byte, error) {
	return nil, nil, fmt.Errorf("offline TDX collateral: %s", url)
}

func testEATSigningKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testVerifierConfig(platform Platform, policyPath string, key *ecdsa.PublicKey) VerifierConfig {
	config := VerifierConfig{
		Platform:           platform,
		PolicyPath:         policyPath,
		EATVerificationKey: key,
		ExpectedIssuer:     testEATIssuer,
	}
	if platform == PlatformSNP {
		vmpl := 0
		config.SNPVerificationOptions = &sevverify.Options{
			CheckRevocations: true,
			Getter:           rejectingHTTPSGetter{},
			Product:          sevabi.DefaultSevProduct(),
		}
		config.SNPValidationOptions = &sevvalidate.Options{VMPL: &vmpl}
	}
	if platform == PlatformTDX {
		config.TDXPolicy = &tdxcheckconfig.Config{
			RootOfTrust: &tdxcheckconfig.RootOfTrust{CheckCrl: true, GetCollateral: true},
			Policy: &tdxcheckconfig.Policy{
				HeaderPolicy: &tdxcheckconfig.HeaderPolicy{},
				TdQuoteBodyPolicy: &tdxcheckconfig.TDQuoteBodyPolicy{
					TdAttributes: make([]byte, tdxabi.TdAttributesSize),
				},
			},
		}
	}
	return config
}

func testEvidenceBinding() eaattestation.EvidenceBinding {
	var binding eaattestation.EvidenceBinding
	for i := range binding.ReportData {
		binding.ReportData[i] = byte(i + 1)
	}
	for i := range binding.Nonce {
		binding.Nonce[i] = byte(0xa0 + i)
	}
	return binding
}

func TestNewEvidenceVerifierRequiresLocalPlatform(t *testing.T) {
	policyPath := testPolicyPath(t)
	key := testEATSigningKey(t)
	for _, platform := range []Platform{
		PlatformSNP,
		PlatformTDX,
	} {
		t.Run(string(platform), func(t *testing.T) {
			verifier, err := NewEvidenceVerifier(testVerifierConfig(platform, policyPath, &key.PublicKey))
			if err != nil {
				t.Fatalf("NewEvidenceVerifier() error = %v", err)
			}
			if verifier == nil {
				t.Fatal("NewEvidenceVerifier() returned nil")
			}
		})
	}

	for _, platform := range []Platform{"", "SNP", "snp-vtpm", "vtpm", "azure", "no-cc", "unknown"} {
		t.Run("reject-"+string(platform), func(t *testing.T) {
			config := testVerifierConfig(platform, policyPath, &key.PublicKey)
			if _, err := NewEvidenceVerifier(config); !errors.Is(err, ErrUnsupportedPlatform) {
				t.Fatalf("NewEvidenceVerifier() error = %v, want ErrUnsupportedPlatform", err)
			}
		})
	}
}

func TestNewEvidenceVerifierRequiresPolicyFile(t *testing.T) {
	key := testEATSigningKey(t)
	if _, err := NewEvidenceVerifier(testVerifierConfig(PlatformSNP, "", &key.PublicKey)); !errors.Is(err, ErrPolicyUnavailable) {
		t.Fatalf("NewEvidenceVerifier() error = %v, want ErrPolicyUnavailable", err)
	}
	if _, err := NewEvidenceVerifier(testVerifierConfig(PlatformSNP, t.TempDir(), &key.PublicKey)); !errors.Is(err, ErrPolicyUnavailable) {
		t.Fatalf("NewEvidenceVerifier() error = %v, want ErrPolicyUnavailable", err)
	}
}

func TestNewEvidenceVerifierRequiresTrustConfiguration(t *testing.T) {
	key := testEATSigningKey(t)
	policyPath := testPolicyPath(t)

	tests := []struct {
		name   string
		mutate func(*VerifierConfig)
		want   error
	}{
		{name: "missing EAT key", mutate: func(c *VerifierConfig) { c.EATVerificationKey = nil }, want: ErrEATTrustUnavailable},
		{name: "missing issuer", mutate: func(c *VerifierConfig) { c.ExpectedIssuer = "" }, want: ErrEATTrustUnavailable},
		{name: "missing SNP verification options", mutate: func(c *VerifierConfig) { c.SNPVerificationOptions = nil }, want: ErrSNPPolicyRequired},
		{name: "missing SNP validation options", mutate: func(c *VerifierConfig) { c.SNPValidationOptions = nil }, want: ErrSNPPolicyRequired},
		{name: "revocation disabled", mutate: func(c *VerifierConfig) { c.SNPVerificationOptions.CheckRevocations = false }, want: ErrSNPPolicyRequired},
		{name: "missing collateral getter", mutate: func(c *VerifierConfig) { c.SNPVerificationOptions.Getter = nil }, want: ErrSNPPolicyRequired},
		{name: "missing expected product", mutate: func(c *VerifierConfig) { c.SNPVerificationOptions.Product = nil }, want: ErrSNPPolicyRequired},
		{name: "debug permitted", mutate: func(c *VerifierConfig) { c.SNPValidationOptions.GuestPolicy.Debug = true }, want: ErrSNPPolicyRequired},
		{name: "missing VMPL", mutate: func(c *VerifierConfig) { c.SNPValidationOptions.VMPL = nil }, want: ErrSNPPolicyRequired},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := testVerifierConfig(PlatformSNP, policyPath, &key.PublicKey)
			tc.mutate(&config)
			if _, err := NewEvidenceVerifier(config); !errors.Is(err, tc.want) {
				t.Fatalf("NewEvidenceVerifier() error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestNewEvidenceVerifierRequiresTDXTrustConfiguration(t *testing.T) {
	key := testEATSigningKey(t)
	policyPath := testPolicyPath(t)
	tests := []struct {
		name   string
		mutate func(*VerifierConfig)
	}{
		{name: "missing policy", mutate: func(c *VerifierConfig) { c.TDXPolicy = nil }},
		{name: "revocation disabled", mutate: func(c *VerifierConfig) { c.TDXPolicy.RootOfTrust.CheckCrl = false }},
		{name: "collateral disabled", mutate: func(c *VerifierConfig) { c.TDXPolicy.RootOfTrust.GetCollateral = false }},
		{name: "TD attributes omitted", mutate: func(c *VerifierConfig) { c.TDXPolicy.Policy.TdQuoteBodyPolicy.TdAttributes = nil }},
		{name: "debug enabled", mutate: func(c *VerifierConfig) { c.TDXPolicy.Policy.TdQuoteBodyPolicy.TdAttributes[0] = 1 }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := testVerifierConfig(PlatformTDX, policyPath, &key.PublicKey)
			tc.mutate(&config)
			if _, err := NewEvidenceVerifier(config); !errors.Is(err, ErrTDXPolicyRequired) {
				t.Fatalf("NewEvidenceVerifier() error = %v, want ErrTDXPolicyRequired", err)
			}
		})
	}
}

func TestVerifyEATProfile(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	valid := eat.EATClaims{
		Issuer:    testEATIssuer,
		IssuedAt:  now.Add(-time.Minute).Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
	}
	if err := verifyEATProfile(&valid, testEATIssuer, now); err != nil {
		t.Fatalf("verifyEATProfile() error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*eat.EATClaims)
	}{
		{name: "wrong issuer", mutate: func(c *eat.EATClaims) { c.Issuer = "other-issuer" }},
		{name: "missing issued at", mutate: func(c *eat.EATClaims) { c.IssuedAt = 0 }},
		{name: "expires before issuance", mutate: func(c *eat.EATClaims) { c.ExpiresAt = c.IssuedAt }},
		{name: "lifetime too long", mutate: func(c *eat.EATClaims) { c.ExpiresAt = c.IssuedAt + 301 }},
		{name: "issued beyond skew", mutate: func(c *eat.EATClaims) {
			c.IssuedAt = now.Add(31 * time.Second).Unix()
			c.ExpiresAt = now.Add(time.Minute).Unix()
		}},
		{name: "expired beyond skew", mutate: func(c *eat.EATClaims) {
			c.IssuedAt = now.Add(-time.Minute).Unix()
			c.ExpiresAt = now.Add(-31 * time.Second).Unix()
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := valid
			tc.mutate(&claims)
			if err := verifyEATProfile(&claims, testEATIssuer, now); err == nil {
				t.Fatal("verifyEATProfile() unexpectedly succeeded")
			}
		})
	}
}

func TestVerifyEvidenceRejectsClaimForDifferentPlatform(t *testing.T) {
	expected := testEvidenceBinding()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		configured Platform
		claim      string
	}{
		{configured: PlatformSNP, claim: "TDX"},
		{configured: PlatformTDX, claim: "SNP"},
	}

	for _, tc := range tests {
		t.Run(string(tc.configured)+"-rejects-"+tc.claim, func(t *testing.T) {
			token, err := eat.EncodeToCBOR(&eat.EATClaims{
				Nonce:        append([]byte(nil), expected.Nonce[:]...),
				PlatformType: tc.claim,
				RawReport:    []byte("peer-controlled-report"),
			}, key, "test-issuer")
			if err != nil {
				t.Fatal(err)
			}
			verifier, err := NewEvidenceVerifier(testVerifierConfig(tc.configured, testPolicyPath(t), &key.PublicKey))
			if err != nil {
				t.Fatal(err)
			}
			if err := verifier.VerifyEvidence(token, expected); !errors.Is(err, ErrPlatformMismatch) {
				t.Fatalf("VerifyEvidence() error = %v, want ErrPlatformMismatch", err)
			}
		})
	}
}

func TestVerifyEvidenceRejectsUnsupportedPlatformClaim(t *testing.T) {
	expected := testEvidenceBinding()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewEvidenceVerifier(testVerifierConfig(PlatformSNP, testPolicyPath(t), &key.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	for _, claim := range []string{"SNP-vTPM", "vTPM", "Azure", "Unknown"} {
		t.Run(claim, func(t *testing.T) {
			token, err := eat.EncodeToCBOR(&eat.EATClaims{
				Nonce:        append([]byte(nil), expected.Nonce[:]...),
				PlatformType: claim,
				RawReport:    []byte("peer-controlled-report"),
			}, key, "test-issuer")
			if err != nil {
				t.Fatal(err)
			}
			if err := verifier.VerifyEvidence(token, expected); !errors.Is(err, ErrUnsupportedPlatform) {
				t.Fatalf("VerifyEvidence() error = %v, want ErrUnsupportedPlatform", err)
			}
		})
	}
}

func testPolicyPath(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.corim")
	if err := os.WriteFile(path, []byte("test policy placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVerifyEvidenceTDXDelegatesToIndependentModule(t *testing.T) {
	quoteAny, err := tdxabi.QuoteToProto(tdxtestdata.RawQuote)
	if err != nil {
		t.Fatal(err)
	}
	quote, ok := quoteAny.(*tdxpb.QuoteV4)
	if !ok {
		t.Fatalf("unexpected TDX quote type %T", quoteAny)
	}
	expected := testEvidenceBinding()
	copy(expected.ReportData[:], quote.GetTdQuoteBody().GetReportData())
	key := testEATSigningKey(t)
	claims, err := eat.NewEATClaims(tdxtestdata.RawQuote, expected.Nonce[:], asbattestation.TDX)
	if err != nil {
		t.Fatal(err)
	}
	token, err := eat.EncodeToCBOR(claims, key, testEATIssuer)
	if err != nil {
		t.Fatal(err)
	}
	config := testVerifierConfig(PlatformTDX, testPolicyPath(t), &key.PublicKey)
	config.TDXRuntimeOptions = &tdxmodule.RuntimeOptions{Getter: rejectingTDXGetter{}}
	verifier, err := NewEvidenceVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyEvidence(token, expected); !errors.Is(err, ErrTDXVerification) {
		t.Fatalf("VerifyEvidence() error = %v, want ErrTDXVerification", err)
	}
}

func TestVerifyEvidenceDirectSNPProviderEndToEnd(t *testing.T) {
	expected := testEvidenceBinding()
	fixture := testDirectSNPEvidence(t, expected)
	policyPath := testSNPPolicyPath(t, fixture.measurement)

	key := testEATSigningKey(t)
	config := testVerifierConfig(PlatformSNP, policyPath, &key.PublicKey)
	config.SNPVerificationOptions = fixture.verificationOptions
	config.SNPValidationOptions = fixture.validationOptions
	verifier, err := NewEvidenceVerifier(config)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name     string
		evidence []byte
	}{
		{name: "direct provider protobuf", evidence: fixture.providerEvidence},
		{name: "AMD ABI report and certificate table", evidence: fixture.rawEvidence},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := testSignedEnvelopeClaims(tc.evidence, expected.Nonce[:], "SNP")
			token, err := eat.EncodeToCBOR(claims, key, "test-issuer")
			if err != nil {
				t.Fatalf("EncodeToCBOR() error = %v", err)
			}
			if err := verifier.VerifyEvidence(token, expected); err != nil {
				t.Fatalf("VerifyEvidence() error = %v", err)
			}
		})
	}
}

func TestVerifyEvidenceDirectSNPRejectsBindingAndPolicyMismatch(t *testing.T) {
	expected := testEvidenceBinding()
	fixture := testDirectSNPEvidence(t, expected)
	key := testEATSigningKey(t)
	claims := testSignedEnvelopeClaims(fixture.providerEvidence, expected.Nonce[:], "SNP")
	token, err := eat.EncodeToCBOR(claims, key, "test-issuer")
	if err != nil {
		t.Fatal(err)
	}

	config := testVerifierConfig(PlatformSNP, testSNPPolicyPath(t, fixture.measurement), &key.PublicKey)
	config.SNPVerificationOptions = fixture.verificationOptions
	config.SNPValidationOptions = fixture.validationOptions
	verifier, err := NewEvidenceVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	wrong := expected
	wrong.ReportData[0] ^= 0xff
	if err := verifier.VerifyEvidence(token, wrong); err == nil {
		t.Fatal("expected mismatched SNP report data to fail")
	}

	wrongMeasurement := append([]byte(nil), fixture.measurement...)
	wrongMeasurement[0] ^= 0xff
	config.PolicyPath = testSNPPolicyPath(t, wrongMeasurement)
	verifier, err = NewEvidenceVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyEvidence(token, expected); err == nil {
		t.Fatal("expected mismatched SNP measurement policy to fail")
	}
}

func TestVerifyEvidenceDirectSNPRejectsTamperedSignatureAndDebugPolicy(t *testing.T) {
	expected := testEvidenceBinding()
	fixture := testDirectSNPEvidence(t, expected)
	key := testEATSigningKey(t)
	config := testVerifierConfig(PlatformSNP, testSNPPolicyPath(t, fixture.measurement), &key.PublicKey)
	config.SNPVerificationOptions = fixture.verificationOptions
	config.SNPValidationOptions = fixture.validationOptions

	var tampered sevsnp.Attestation
	if err := proto.Unmarshal(fixture.providerEvidence, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.Report.Signature[0] ^= 0xff
	tamperedEvidence, err := proto.Marshal(&tampered)
	if err != nil {
		t.Fatal(err)
	}
	claims := testSignedEnvelopeClaims(tamperedEvidence, expected.Nonce[:], "SNP")
	tamperedToken, err := eat.EncodeToCBOR(claims, key, testEATIssuer)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewEvidenceVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyEvidence(tamperedToken, expected); !errors.Is(err, ErrSNPVerification) {
		t.Fatalf("VerifyEvidence() error = %v, want ErrSNPVerification", err)
	}

	config.SNPValidationOptions.GuestPolicy.Debug = true
	if _, err := NewEvidenceVerifier(config); !errors.Is(err, ErrSNPPolicyRequired) {
		t.Fatalf("NewEvidenceVerifier() error = %v, want ErrSNPPolicyRequired", err)
	}
}

// testSignedEnvelopeClaims constructs only the fields consumed by the Cocos
// compatibility verifier. This keeps verifier tests independent of the legacy
// Cocos evidence producer's platform-specific claim extraction.
func testSignedEnvelopeClaims(report, nonce []byte, platform string) *eat.EATClaims {
	return &eat.EATClaims{
		Nonce:        append([]byte(nil), nonce...),
		PlatformType: platform,
		RawReport:    append([]byte(nil), report...),
	}
}

func TestVerifyEvidenceDirectSNPRejectsSNPvTPMWrapper(t *testing.T) {
	expected := testEvidenceBinding()
	fixture := testDirectSNPEvidence(t, expected)
	var snpAttestation sevsnp.Attestation
	if err := proto.Unmarshal(fixture.providerEvidence, &snpAttestation); err != nil {
		t.Fatal(err)
	}
	wrapper, err := proto.Marshal(&attest.Attestation{
		TeeAttestation: &attest.Attestation_SevSnpAttestation{
			SevSnpAttestation: &snpAttestation,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	key := testEATSigningKey(t)
	token, err := eat.EncodeToCBOR(&eat.EATClaims{
		Nonce:        append([]byte(nil), expected.Nonce[:]...),
		PlatformType: "SNP",
		RawReport:    wrapper,
	}, key, "test-issuer")
	if err != nil {
		t.Fatal(err)
	}
	config := testVerifierConfig(PlatformSNP, testSNPPolicyPath(t, fixture.measurement), &key.PublicKey)
	config.SNPVerificationOptions = fixture.verificationOptions
	config.SNPValidationOptions = fixture.validationOptions
	verifier, err := NewEvidenceVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyEvidence(token, expected); !errors.Is(err, ErrInvalidSNPEvidence) {
		t.Fatalf("VerifyEvidence() error = %v, want ErrInvalidSNPEvidence", err)
	}
}

type directSNPTestEvidence struct {
	rawEvidence         []byte
	providerEvidence    []byte
	measurement         []byte
	verificationOptions *sevverify.Options
	validationOptions   *sevvalidate.Options
}

func testDirectSNPEvidence(t *testing.T, expected eaattestation.EvidenceBinding) directSNPTestEvidence {
	t.Helper()
	now := time.Now()
	signer, err := sevtesting.DefaultTestOnlyCertChain(sevtesting.GetProductName(), now)
	if err != nil {
		t.Fatal(err)
	}
	rawBuffer := sevtesting.TestRawReport(expected.ReportData)
	rawReport := append([]byte(nil), rawBuffer[:sevabi.ReportSize]...)
	binary.LittleEndian.PutUint64(rawReport[0x08:0x10], sevabi.SnpPolicyToBytes(sevabi.SnpPolicy{}))
	measurement := make([]byte, sevabi.MeasurementSize)
	for i := range measurement {
		measurement[i] = byte(0x40 + i)
	}
	copy(rawReport[0x90:0xc0], measurement)
	r, s, err := signer.Sign(sevabi.SignedComponent(rawReport))
	if err != nil {
		t.Fatal(err)
	}
	if err := sevabi.SetSignature(r, s, rawReport); err != nil {
		t.Fatal(err)
	}
	certificateTable, err := signer.CertTableBytes()
	if err != nil {
		t.Fatal(err)
	}
	rawEvidence := append(append([]byte(nil), rawReport...), certificateTable...)

	snpAttestation, err := sevabi.ReportCertsToProto(rawEvidence)
	if err != nil {
		t.Fatal(err)
	}
	product := sevabi.DefaultSevProduct()
	snpAttestation.Product = proto.Clone(product).(*sevsnp.SevProduct)
	providerEvidence, err := proto.Marshal(snpAttestation)
	if err != nil {
		t.Fatal(err)
	}

	root := sevtrust.AMDRootCertsProduct(sevtesting.GetProductLine())
	root.ProductCerts = &sevtrust.ProductCerts{Ark: signer.Ark, Ask: signer.Ask}
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(-time.Minute),
		NextUpdate: now.Add(time.Hour),
	}, signer.Ark, signer.Keys.Ark)
	if err != nil {
		t.Fatal(err)
	}
	root.CRL, err = x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatal(err)
	}
	vmpl := 0
	return directSNPTestEvidence{
		rawEvidence:      rawEvidence,
		providerEvidence: providerEvidence,
		measurement:      measurement,
		verificationOptions: &sevverify.Options{
			CheckRevocations:    true,
			DisableCertFetching: true,
			Getter:              rejectingHTTPSGetter{},
			TrustedRoots: map[string][]*sevtrust.AMDRootCerts{
				sevtesting.GetProductLine(): {root},
			},
			Product: proto.Clone(product).(*sevsnp.SevProduct),
		},
		validationOptions: &sevvalidate.Options{
			GuestPolicy: sevabi.SnpPolicy{},
			VMPL:        &vmpl,
		},
	}
}

func testSNPPolicyPath(t *testing.T, measurement []byte) string {
	t.Helper()
	policy, err := corimgen.GenerateCoRIM(corimgen.Options{
		Platform:    "snp",
		Measurement: hex.EncodeToString(measurement),
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "snp-policy.corim")
	if err := os.WriteFile(path, policy, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadCoRIMVerifiesConfiguredSignature(t *testing.T) {
	key := testEATSigningKey(t)
	payload, err := corimgen.GenerateCoRIM(corimgen.Options{
		Platform:   "snp",
		SigningKey: key,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "signed-policy.corim")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := loadCoRIM(path, &key.PublicKey, time.Now()); err != nil {
		t.Fatalf("loadCoRIM() error = %v", err)
	}
	if _, err := loadCoRIM(path, nil, time.Now()); !errors.Is(err, ErrCoRIMTrustRequired) {
		t.Fatalf("loadCoRIM() error = %v, want ErrCoRIMTrustRequired", err)
	}
	wrongKey := testEATSigningKey(t)
	if _, err := loadCoRIM(path, &wrongKey.PublicKey, time.Now()); !errors.Is(err, ErrCoRIMVerification) {
		t.Fatalf("loadCoRIM() error = %v, want ErrCoRIMVerification", err)
	}
}

func TestLoadCoRIMRejectsUnsignedPolicyWhenKeyConfigured(t *testing.T) {
	path := testSNPPolicyPath(t, make([]byte, sevabi.MeasurementSize))
	key := testEATSigningKey(t)
	if _, err := loadCoRIM(path, &key.PublicKey, time.Now()); !errors.Is(err, ErrCoRIMVerification) {
		t.Fatalf("loadCoRIM() error = %v, want ErrCoRIMVerification", err)
	}
}

func TestValidateCoRIMValidity(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	notBefore := now.Add(-time.Minute)
	if err := validateCoRIMValidity(&corim.Validity{NotBefore: &notBefore, NotAfter: now.Add(time.Minute)}, now); err != nil {
		t.Fatal(err)
	}
	future := now.Add(time.Second)
	if err := validateCoRIMValidity(&corim.Validity{NotBefore: &future, NotAfter: now.Add(time.Minute)}, now); !errors.Is(err, ErrCoRIMVerification) {
		t.Fatalf("future validity error = %v", err)
	}
	if err := validateCoRIMValidity(&corim.Validity{NotAfter: now.Add(-time.Second)}, now); !errors.Is(err, ErrCoRIMVerification) {
		t.Fatalf("expired validity error = %v", err)
	}
}
