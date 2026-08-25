// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/thinksyncs/agents-secure-binding/pkg/atls/identitypolicy"
	"github.com/thinksyncs/agents-secure-binding/pkg/atls/sbaipv2"
	"github.com/thinksyncs/agents-secure-binding/pkg/clients"
)

type draft06V2WireFixture struct {
	FixtureVersion string    `json:"fixture_version"`
	Profile        string    `json:"profile"`
	ClaimScope     string    `json:"claim_scope"`
	Now            time.Time `json:"now"`
	HTTPRequest    struct {
		Method              string            `json:"method"`
		Path                string            `json:"path"`
		Headers             map[string]string `json:"headers"`
		MustBeAbsentHeaders []string          `json:"must_be_absent_headers"`
		BodyBase64URL       string            `json:"body_base64url"`
		BodySHA256          string            `json:"body_sha256"`
	} `json:"http_request"`
	PublicKeys struct {
		Manager             wireFixtureJWK `json:"manager"`
		Agent               wireFixtureJWK `json:"agent"`
		AttestationVerifier wireFixtureJWK `json:"attestation_verifier"`
	} `json:"public_keys"`
	BindingInputs struct {
		EndpointSPKIDERBase64URL string `json:"endpoint_spki_der_base64url"`
		TLSExporterBase64URL     string `json:"tls_exporter_base64url"`
		VerifierNonce            string `json:"verifier_nonce"`
		AttemptID                string `json:"attempt_id"`
	} `json:"binding_inputs"`
	VerifierInputs struct {
		AcceptedProfile             identitypolicy.ProfileSelectionV2 `json:"accepted_profile"`
		EndpointCredentialExpiresAt time.Time                         `json:"endpoint_credential_expires_at"`
		EvidenceChallengeExpiresAt  time.Time                         `json:"evidence_challenge_expires_at"`
		LocalPolicyExpiresAt        time.Time                         `json:"local_policy_expires_at"`
		Policy                      string                            `json:"policy"`
	} `json:"verifier_inputs"`
	Expected struct {
		TaskContextBase64URL                 string                             `json:"task_context_base64url"`
		TaskContextSHA256                    string                             `json:"task_context_sha256"`
		TargetContextBase64URL               string                             `json:"target_context_base64url"`
		TargetContextSHA256                  string                             `json:"target_context_sha256"`
		BindingContextBase64URL              string                             `json:"binding_context_base64url"`
		IdentityGrantSHA256                  string                             `json:"identity_grant_sha256"`
		GrantHash                            string                             `json:"grant_hash"`
		SessionBindingSHA256                 string                             `json:"session_binding_sha256"`
		AcceptedEndpointSPKISHA256           string                             `json:"accepted_endpoint_spki_sha256"`
		TLSExporterSHA256                    string                             `json:"tls_exporter_sha256"`
		BindingContextSHA256                 string                             `json:"binding_context_sha256"`
		AttestationBinderSHA256              string                             `json:"attestation_binder_sha256"`
		AttestationReportDataSHA512Base64URL string                             `json:"attestation_report_data_sha512_base64url"`
		AcceptedAssertion                    identitypolicy.AcceptedAssertionV2 `json:"accepted_assertion"`
	} `json:"expected"`
}

type wireFixtureJWK struct {
	KTY string `json:"kty"`
	CRV string `json:"crv"`
	KID string `json:"kid"`
	Use string `json:"use"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func TestDraft06V2FullWireEvidenceFixture(t *testing.T) {
	fixture := loadDraft06V2WireFixture(t)
	if fixture.FixtureVersion != "1" || fixture.Profile != bindingProfileDraft06V2 || fixture.ClaimScope != "repository-profile-evidence" {
		t.Fatalf("fixture identity = version %q, profile %q, scope %q", fixture.FixtureVersion, fixture.Profile, fixture.ClaimScope)
	}
	if fixture.VerifierInputs.Policy != "receiverPolicyV2" {
		t.Fatalf("verifier policy = %q", fixture.VerifierInputs.Policy)
	}
	assertWireFixtureRequestContract(t, fixture)

	body := decodeCanonicalBase64URLFixture(t, "HTTP body", fixture.HTTPRequest.BodyBase64URL)
	if got := sha256String(body); got != fixture.HTTPRequest.BodySHA256 {
		t.Fatalf("HTTP body hash = %q, want %q", got, fixture.HTTPRequest.BodySHA256)
	}
	assertWireFixtureHTTPRequest(t, fixture, body)
	request, err := decodeStrictA2ARequestV2(body)
	if err != nil {
		t.Fatalf("decode fixture request through strict v2 wire parser: %v", err)
	}
	sbo, err := decodeSBOV2(request.Message.Metadata[securityBindingExtensionV2])
	if err != nil {
		t.Fatalf("decode fixture Security Binding Object: %v", err)
	}
	var attestationToken string
	if err := json.Unmarshal(request.Message.Metadata[attestationResultExtensionV2], &attestationToken); err != nil || attestationToken == "" {
		t.Fatalf("decode fixture attestation result: %v", err)
	}

	managerKey := publicKeyFromWireFixtureJWK(t, fixture.PublicKeys.Manager, demoManagerKeyID)
	agentKey := publicKeyFromWireFixtureJWK(t, fixture.PublicKeys.Agent, demoAgentKeyID)
	verifierKey := publicKeyFromWireFixtureJWK(t, fixture.PublicKeys.AttestationVerifier, demoVerifierKeyID)
	grant, err := clients.VerifyIdentityGrantJWTV2(sbo.Grant, clients.JWTVerifyOptions{
		ExpectedIssuer: demoManagerIssuer, ExpectedAudience: demoAudience,
		ValidMethods: []string{jwt.SigningMethodES256.Alg()},
		LocalKeys:    []clients.LocalKey{{KeyID: demoManagerKeyID, Key: managerKey}}, Now: fixture.Now,
	})
	if err != nil {
		t.Fatalf("verify fixture authority grant: %v", err)
	}
	statement, err := clients.VerifySessionBindingJWTV2(sbo.Binding, clients.JWTVerifyOptions{
		ExpectedIssuer: demoAgentIssuer, ExpectedAudience: demoAudience,
		ValidMethods: []string{jwt.SigningMethodES256.Alg()},
		LocalKeys:    []clients.LocalKey{{KeyID: demoAgentKeyID, Key: agentKey}}, Now: fixture.Now,
	})
	if err != nil {
		t.Fatalf("verify fixture session proof: %v", err)
	}
	attestation, err := parseAttestationResultV2(attestationToken, verifierKey, fixture.Now)
	if err != nil {
		t.Fatalf("verify fixture attestation result: %v", err)
	}

	if got := sha256String([]byte(sbo.Grant)); got != fixture.Expected.IdentityGrantSHA256 || got != sbo.GrantSHA256 {
		t.Fatalf("exact compact grant hash = %q, expected %q, wrapper %q", got, fixture.Expected.IdentityGrantSHA256, sbo.GrantSHA256)
	}
	if got := clients.IdentityGrantHash(sbo.Grant); got != fixture.Expected.GrantHash || got != statement.GrantHash || got != grant.GrantHash {
		t.Fatalf("domain-separated grant hash = %q, fixture %q, proof %q, grant %q", got, fixture.Expected.GrantHash, statement.GrantHash, grant.GrantHash)
	}
	if got := sha256String([]byte(sbo.Binding)); got != fixture.Expected.SessionBindingSHA256 || got != sbo.BindingSHA256 {
		t.Fatalf("exact compact proof hash = %q, expected %q, wrapper %q", got, fixture.Expected.SessionBindingSHA256, sbo.BindingSHA256)
	}

	contexts, err := canonicalRequestContextsV2(request)
	if err != nil {
		t.Fatalf("build fixture task and target contexts: %v", err)
	}
	assertWireFixtureContext(t, "task", contexts.Task, fixture.Expected.TaskContextBase64URL, fixture.Expected.TaskContextSHA256)
	assertWireFixtureContext(t, "target", contexts.Target, fixture.Expected.TargetContextBase64URL, fixture.Expected.TargetContextSHA256)
	if contexts.Resource != demoResource || contexts.Operation != demoOperation {
		t.Fatalf("target = %q/%q", contexts.Resource, contexts.Operation)
	}

	endpointSPKI := decodeCanonicalBase64URLFixture(t, "endpoint SPKI", fixture.BindingInputs.EndpointSPKIDERBase64URL)
	if _, err := x509.ParsePKIXPublicKey(endpointSPKI); err != nil {
		t.Fatalf("fixture endpoint SPKI is not DER SubjectPublicKeyInfo: %v", err)
	}
	exporter := decodeCanonicalBase64URLFixture(t, "TLS exporter", fixture.BindingInputs.TLSExporterBase64URL)
	if len(exporter) != sbaipv2.ExporterLength {
		t.Fatalf("TLS exporter length = %d, want %d", len(exporter), sbaipv2.ExporterLength)
	}
	nonce := decodeCanonicalBase64URLFixture(t, "verifier nonce", fixture.BindingInputs.VerifierNonce)
	attempt := decodeCanonicalBase64URLFixture(t, "attempt ID", fixture.BindingInputs.AttemptID)
	contextValue, err := sbaipv2.EncodeContext(sbaipv2.ContextInputs{
		EndpointRole: v2EndpointRole, InteractionType: v2InteractionType,
		ProtocolID: v2ProtocolID, Audience: demoAudience, GrantHash: clients.IdentityGrantDigest(sbo.Grant),
		TaskContext: contexts.Task, TargetContext: contexts.Target,
		VerifierNonce: nonce, AttemptID: attempt,
	})
	if err != nil {
		t.Fatalf("encode fixture binding context: %v", err)
	}
	wantContext := decodeCanonicalBase64URLFixture(t, "binding context", fixture.Expected.BindingContextBase64URL)
	if !bytes.Equal(contextValue, wantContext) {
		t.Fatal("encoded binding context differs from the fixture")
	}
	hashes, err := sbaipv2.DeriveHashes(contextValue, endpointSPKI, exporter)
	if err != nil {
		t.Fatalf("derive fixture binding hashes: %v", err)
	}
	assertDerivedWireFixtureHashes(t, hashes, fixture, statement.Binding, sbo)
	binder, err := sbaipv2.AttestationBindingInput(endpointSPKI, exporter)
	if err != nil {
		t.Fatalf("encode fixture attestation binder: %v", err)
	}
	reportData := sha512.Sum512(binder)
	if got := base64.RawURLEncoding.EncodeToString(reportData[:]); got != fixture.Expected.AttestationReportDataSHA512Base64URL {
		t.Fatalf("attestation report data = %q, want %q", got, fixture.Expected.AttestationReportDataSHA512Base64URL)
	}
	if attestation.BinderSHA256 != fixture.Expected.AttestationBinderSHA256 {
		t.Fatalf("attestation binder = %q, want %q", attestation.BinderSHA256, fixture.Expected.AttestationBinderSHA256)
	}
	if err := validateSBOV2(sbo, statement.Binding, fixture.VerifierInputs.EvidenceChallengeExpiresAt, fixture.Now); err != nil {
		t.Fatalf("validate fixture Security Binding Object: %v", err)
	}

	acceptedAttestation := identitypolicy.VerifiedAttestationResultV2{
		ProfileType: attestation.ProfileType, ProfileVersion: attestation.ProfileVersion,
		ResultID: attestation.ID, Issuer: attestation.Issuer, Subject: attestation.Subject,
		SignerKeyID: demoVerifierKeyID, Audience: attestation.Audience[0],
		AppraisalPolicyID: attestation.AppraisalPolicyID, BinderSHA256: attestation.BinderSHA256,
		IssuedAt: attestation.IssuedAt.Time.UTC(), ExpiresAt: attestation.ExpiresAt.Time.UTC(),
	}
	replay := identitypolicy.NewMemoryReplayCacheWithClock(func() time.Time { return fixture.Now })
	verifyOptions := clients.SessionIdentityJWTOptionsV2{
		Grant: clients.JWTVerifyOptions{
			ExpectedIssuer: demoManagerIssuer, ExpectedAudience: demoAudience,
			ValidMethods: []string{jwt.SigningMethodES256.Alg()},
			LocalKeys:    []clients.LocalKey{{KeyID: demoManagerKeyID, Key: managerKey}},
		},
		SessionBinding: clients.JWTVerifyOptions{
			ExpectedIssuer: demoAgentIssuer, ExpectedAudience: demoAudience,
			ValidMethods: []string{jwt.SigningMethodES256.Alg()},
			LocalKeys:    []clients.LocalKey{{KeyID: demoAgentKeyID, Key: agentKey}},
		},
		Policy: receiverPolicyV2(), ExpectedBinding: statement.Binding,
		AcceptedProfile: fixture.VerifierInputs.AcceptedProfile,
		Freshness: identitypolicy.FreshnessInputsV2{
			EndpointCredentialExpiresAt: fixture.VerifierInputs.EndpointCredentialExpiresAt,
			EvidenceChallengeExpiresAt:  fixture.VerifierInputs.EvidenceChallengeExpiresAt,
			LocalPolicyExpiresAt:        fixture.VerifierInputs.LocalPolicyExpiresAt,
		},
		ReplayCache: replay,
		Clock:       func() time.Time { return fixture.Now },
		AttestationVerifier: func(identitypolicy.VerifiedGrantV2, identitypolicy.VerifiedSessionBindingStatementV2, identitypolicy.BindingV2) (identitypolicy.VerifiedAttestationResultV2, error) {
			return acceptedAttestation, nil
		},
		Now: fixture.Now,
	}
	result, err := clients.VerifySessionIdentityJWTV2(sbo.Grant, sbo.Binding, verifyOptions)
	if err != nil {
		t.Fatalf("verify complete fixture: %v", err)
	}
	if !reflect.DeepEqual(result.Accepted, fixture.Expected.AcceptedAssertion) {
		got, _ := json.MarshalIndent(result.Accepted, "", "  ")
		want, _ := json.MarshalIndent(fixture.Expected.AcceptedAssertion, "", "  ")
		t.Fatalf("accepted assertion differs\n got: %s\nwant: %s", got, want)
	}
	if _, err := clients.VerifySessionIdentityJWTV2(sbo.Grant, sbo.Binding, verifyOptions); !errors.Is(err, identitypolicy.ErrReplayDetected) {
		t.Fatalf("second fixture verification error = %v, want replay detected", err)
	}
}

func loadDraft06V2WireFixture(t *testing.T) draft06V2WireFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/draft06-v2-wire.json")
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var fixture draft06V2WireFixture
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("fixture has trailing JSON: %v", err)
	}
	return fixture
}

func assertWireFixtureRequestContract(t *testing.T, fixture draft06V2WireFixture) {
	t.Helper()
	wantHeaders := map[string]string{
		"Host": "agent-b.example.test", "Content-Type": a2aMediaType,
		"A2A-Version":    a2aVersion,
		"A2A-Extensions": securityBindingExtensionV2 + "," + attestationResultExtensionV2,
	}
	if fixture.HTTPRequest.Method != http.MethodPost || fixture.HTTPRequest.Path != "/message:send" || !reflect.DeepEqual(fixture.HTTPRequest.Headers, wantHeaders) {
		t.Fatalf("HTTP request contract = %s %s %#v", fixture.HTTPRequest.Method, fixture.HTTPRequest.Path, fixture.HTTPRequest.Headers)
	}
	wantAbsent := []string{"Early-Data", "Forwarded", "Via", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"}
	if !reflect.DeepEqual(fixture.HTTPRequest.MustBeAbsentHeaders, wantAbsent) {
		t.Fatalf("absent header list = %#v", fixture.HTTPRequest.MustBeAbsentHeaders)
	}
}

func assertWireFixtureHTTPRequest(t *testing.T, fixture draft06V2WireFixture, body []byte) {
	t.Helper()
	request, err := http.NewRequest(fixture.HTTPRequest.Method, "https://"+fixture.HTTPRequest.Headers["Host"]+fixture.HTTPRequest.Path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Host = fixture.HTTPRequest.Headers["Host"]
	for name, value := range fixture.HTTPRequest.Headers {
		if name != "Host" {
			request.Header.Set(name, value)
		}
	}
	if err := rejectTransportIndirectionV2(request); err != nil {
		t.Fatalf("fixture contains rejected transport metadata: %v", err)
	}
	for _, name := range fixture.HTTPRequest.MustBeAbsentHeaders {
		mutated := request.Clone(request.Context())
		mutated.Header.Set(name, "fixture-must-reject")
		if err := rejectTransportIndirectionV2(mutated); err == nil {
			t.Fatalf("header %q was not rejected", name)
		}
	}
}

func assertWireFixtureContext(t *testing.T, name string, got []byte, encoded, expectedHash string) {
	t.Helper()
	want := decodeCanonicalBase64URLFixture(t, name+" context", encoded)
	if !bytes.Equal(got, want) {
		t.Fatalf("%s context differs from fixture", name)
	}
	digest := sha256.Sum256(got)
	if gotHash := hashStringV2(digest); gotHash != expectedHash {
		t.Fatalf("%s context hash = %q, want %q", name, gotHash, expectedHash)
	}
}

func assertDerivedWireFixtureHashes(t *testing.T, hashes sbaipv2.DerivedHashes, fixture draft06V2WireFixture, binding identitypolicy.BindingV2, sbo securityBindingObjectV2) {
	t.Helper()
	for _, item := range []struct {
		name    string
		got     string
		want    string
		proof   string
		wrapper string
	}{
		{"accepted endpoint SPKI", hashStringV2(hashes.AcceptedEndpointSPKISHA256), fixture.Expected.AcceptedEndpointSPKISHA256, binding.AcceptedEndpointSPKISHA256, sbo.AcceptedEndpointSPKISHA256},
		{"TLS exporter", hashStringV2(hashes.TLSExporterSHA256), fixture.Expected.TLSExporterSHA256, binding.TLSExporterSHA256, sbo.TLSExporterSHA256},
		{"binding context", hashStringV2(hashes.BindingContextSHA256), fixture.Expected.BindingContextSHA256, binding.BindingContextSHA256, sbo.BindingContextSHA256},
		{"attestation binder", hashStringV2(hashes.AttestationBinderSHA256), fixture.Expected.AttestationBinderSHA256, binding.AttestationBinderSHA256, sbo.AttestationBinderSHA256},
	} {
		if item.got != item.want || item.got != item.proof || item.got != item.wrapper {
			t.Fatalf("%s hash = %q, fixture %q, proof %q, wrapper %q", item.name, item.got, item.want, item.proof, item.wrapper)
		}
	}
	if binding.VerifierNonce != fixture.BindingInputs.VerifierNonce || binding.AttemptID != fixture.BindingInputs.AttemptID {
		t.Fatalf("proof nonce/attempt = %q/%q", binding.VerifierNonce, binding.AttemptID)
	}
}

func publicKeyFromWireFixtureJWK(t *testing.T, value wireFixtureJWK, expectedKID string) *ecdsa.PublicKey {
	t.Helper()
	if value.KTY != "EC" || value.CRV != "P-256" || value.Use != "sig" || value.KID != expectedKID {
		t.Fatalf("unexpected public JWK for %q: %#v", expectedKID, value)
	}
	xRaw := decodeCanonicalBase64URLFixture(t, expectedKID+" x", value.X)
	yRaw := decodeCanonicalBase64URLFixture(t, expectedKID+" y", value.Y)
	if len(xRaw) != 32 || len(yRaw) != 32 {
		t.Fatalf("public JWK %q coordinates are not 32 bytes", expectedKID)
	}
	key := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xRaw), Y: new(big.Int).SetBytes(yRaw)}
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		t.Fatalf("public JWK %q is not on P-256", expectedKID)
	}
	return key
}

func decodeCanonicalBase64URLFixture(t *testing.T, name, value string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != value {
		t.Fatalf("%s is not canonical base64url: %v", name, err)
	}
	return raw
}
