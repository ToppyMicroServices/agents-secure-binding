// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package production

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/thinksyncs/agents-secure-binding/pkg/atls/identitypolicy"
	"github.com/thinksyncs/agents-secure-binding/pkg/clients"
)

const (
	testAudience            = "https://change.example.test/v1/changes"
	testManagerIssuer       = "https://manager.example.test"
	testAgentIssuer         = "https://agent.example.test"
	testManagerKeyID        = "manager-ed25519-2026-01"
	testAgentKeyID          = "agent-ed25519-2026-01"
	testAttesterKeyID       = "attester-ed25519-2026-01"
	testAttestationID       = "attestation-0001"
	testAttestationPolicyID = "protected-change-attestation/v1"
	testMeasurement         = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

type profileFixture struct {
	profile         Profile
	request         VerifyRequest
	managerPrivate  ed25519.PrivateKey
	agentPrivate    ed25519.PrivateKey
	attesterPrivate ed25519.PrivateKey
	replay          *recordingReplayCache
	now             time.Time
}

type trustSourceFunc func(context.Context) (TrustSnapshot, error)

func (f trustSourceFunc) Snapshot(ctx context.Context) (TrustSnapshot, error) {
	return f(ctx)
}

type recordingReplayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
	err  error
}

func (c *recordingReplayCache) MarkUsed(key string, expiresAt time.Time) error {
	if c.err != nil {
		return c.err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.seen[key]; ok {
		return identitypolicy.ErrReplayDetected
	}
	c.seen[key] = expiresAt
	return nil
}

func (c *recordingReplayCache) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}

func TestProfileVerifyAcceptsProductionComposition(t *testing.T) {
	t.Parallel()
	fixture := newProfileFixture(t)

	accepted, err := fixture.profile.Verify(context.Background(), fixture.request)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if accepted.Agent != "change-agent-01" || accepted.TaskID != "change-0001" {
		t.Fatalf("Verify() accepted = %+v", accepted)
	}
	if fixture.replay.count() != 1 {
		t.Fatalf("replay commits = %d, want 1", fixture.replay.count())
	}
}

func TestProfileVerifyRejectsReplay(t *testing.T) {
	t.Parallel()
	fixture := newProfileFixture(t)

	if _, err := fixture.profile.Verify(context.Background(), fixture.request); err != nil {
		t.Fatalf("first Verify() error = %v", err)
	}
	_, err := fixture.profile.Verify(context.Background(), fixture.request)
	if !errors.Is(err, identitypolicy.ErrReplayDetected) {
		t.Fatalf("second Verify() error = %v, want %v", err, identitypolicy.ErrReplayDetected)
	}
}

func TestProfileRejectsTypedNilReplayCache(t *testing.T) {
	t.Parallel()
	fixture := newProfileFixture(t)
	var replay *identitypolicy.SetNXReplayCache
	fixture.profile.ReplayCache = replay

	if err := fixture.profile.Validate(context.Background()); !errors.Is(err, ErrMissingReplayCache) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMissingReplayCache)
	}
	if _, err := fixture.profile.Verify(context.Background(), fixture.request); !errors.Is(err, ErrMissingReplayCache) {
		t.Fatalf("Verify() error = %v, want %v", err, ErrMissingReplayCache)
	}
}

func TestProfileVerifyNegativeGatesDoNotCommitReplay(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*testing.T, *profileFixture)
		want   error
	}{
		{
			name: "trust source outage",
			mutate: func(_ *testing.T, f *profileFixture) {
				f.profile.GrantAuthority.TrustSource = trustSourceFunc(func(context.Context) (TrustSnapshot, error) {
					return TrustSnapshot{}, errors.New("registry unavailable")
				})
			},
			want: ErrTrustSourceUnavailable,
		},
		{
			name: "disabled manager key",
			mutate: func(_ *testing.T, f *profileFixture) {
				f.profile.GrantAuthority.TrustSource = StaticTrustSource{Trust: TrustSnapshot{
					Keys:           []clients.LocalKey{{KeyID: testManagerKeyID, Key: f.managerPrivate.Public()}},
					DisabledKeyIDs: []string{testManagerKeyID},
				}}
			},
			want: clients.ErrDisabledKeyID,
		},
		{
			name: "unknown agent key",
			mutate: func(_ *testing.T, f *profileFixture) {
				f.profile.BindingAuthority.TrustSource = StaticTrustSource{Trust: TrustSnapshot{
					Keys: []clients.LocalKey{{KeyID: "different-agent-key", Key: f.agentPrivate.Public()}},
				}}
			},
			want: clients.ErrUnknownKeyID,
		},
		{
			name: "revoked grant",
			mutate: func(_ *testing.T, f *profileFixture) {
				f.profile.GrantAuthority.TrustSource = StaticTrustSource{Trust: TrustSnapshot{
					Keys:            []clients.LocalKey{{KeyID: testManagerKeyID, Key: f.managerPrivate.Public()}},
					RevokedTokenIDs: []string{"grant-0001"},
				}}
			},
			want: clients.ErrRevokedJWTID,
		},
		{
			name: "wrong action binding",
			mutate: func(_ *testing.T, f *profileFixture) {
				f.request.ExpectedBinding.RequestContextSHA256 = testHash("different-action")
			},
			want: identitypolicy.ErrMismatch,
		},
		{
			name: "wrong local task",
			mutate: func(_ *testing.T, f *profileFixture) {
				f.profile.IdentityPolicy.Expected.TaskID = "change-9999"
			},
			want: identitypolicy.ErrMismatch,
		},
		{
			name: "attestation binder mismatch",
			mutate: func(t *testing.T, f *profileFixture) {
				f.request.Attestation.AttestationBinderSHA256 = testHash("other-attestation-binding")
				signAttestation(t, &f.request.Attestation, f.attesterPrivate)
			},
			want: ErrAttestationBinding,
		},
		{
			name: "stale attestation",
			mutate: func(t *testing.T, f *profileFixture) {
				f.request.Attestation.IssuedAt = f.now.Add(-10 * time.Minute)
				f.request.Attestation.ExpiresAt = f.now.Add(time.Minute)
				signAttestation(t, &f.request.Attestation, f.attesterPrivate)
			},
			want: ErrAttestationStale,
		},
		{
			name: "unknown measurement",
			mutate: func(t *testing.T, f *profileFixture) {
				f.request.Attestation.Measurement = testHash("unapproved-workload")
				signAttestation(t, &f.request.Attestation, f.attesterPrivate)
			},
			want: ErrAttestationPolicy,
		},
		{
			name: "replay store outage",
			mutate: func(_ *testing.T, f *profileFixture) {
				f.replay.err = errors.New("shared store unavailable")
			},
			want: errors.New("shared store unavailable"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fixture := newProfileFixture(t)
			tt.mutate(t, fixture)
			_, err := fixture.profile.Verify(context.Background(), fixture.request)
			if tt.name == "replay store outage" {
				if err == nil || !errors.Is(err, fixture.replay.err) {
					t.Fatalf("Verify() error = %v, want replay store error", err)
				}
			} else if !errors.Is(err, tt.want) {
				t.Fatalf("Verify() error = %v, want %v", err, tt.want)
			}
			if fixture.replay.count() != 0 {
				t.Fatalf("replay commits = %d, want 0", fixture.replay.count())
			}
		})
	}
}

func TestProfileValidateRejectsIncompleteDeployment(t *testing.T) {
	t.Parallel()
	fixture := newProfileFixture(t)
	if err := fixture.profile.Validate(nil); !errors.Is(err, ErrMissingContext) {
		t.Fatalf("Validate(nil) error = %v, want %v", err, ErrMissingContext)
	}
	if _, err := fixture.profile.Verify(nil, fixture.request); !errors.Is(err, ErrMissingContext) {
		t.Fatalf("Verify(nil) error = %v, want %v", err, ErrMissingContext)
	}

	tests := []struct {
		name   string
		mutate func(*Profile)
		want   error
	}{
		{"missing trust", func(p *Profile) { p.GrantAuthority.TrustSource = nil }, ErrMissingTrustSource},
		{"missing attestation", func(p *Profile) { p.Attestation = nil }, ErrMissingAttestationPolicy},
		{"missing replay", func(p *Profile) { p.ReplayCache = nil }, ErrMissingReplayCache},
		{"missing policy", func(p *Profile) { p.IdentityPolicy = identitypolicy.Policy{} }, ErrMissingPolicy},
		{"missing grant lifetime bound", func(p *Profile) { p.GrantAuthority.MaxTokenLifetime = 0 }, ErrInvalidAuthority},
		{"negative clock skew", func(p *Profile) { p.BindingAuthority.ClockSkew = -time.Second }, ErrInvalidAuthority},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := fixture.profile
			tt.mutate(&profile)
			if err := profile.Validate(context.Background()); !errors.Is(err, tt.want) {
				t.Fatalf("Validate() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func newProfileFixture(t *testing.T) *profileFixture {
	t.Helper()
	now := time.Date(2026, time.August, 3, 2, 0, 0, 0, time.UTC)
	managerPublic, managerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agentPublic, agentPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attesterPublic, attesterPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	expectedBinding := identitypolicy.Binding{
		LeafPublicKeySHA256:     testHash("agent-leaf-key"),
		TLSExporterSHA256:       testHash("accepted-tls-exporter"),
		RequestContextSHA256:    testHash("protected-change-action"),
		AttestationBinderSHA256: testHash("accepted-attestation-binding"),
		Nonce:                   "binding-nonce-0001",
	}
	values := identitypolicy.Values{
		Service:              "protected-change",
		Agent:                "change-agent-01",
		TaskID:               "change-0001",
		IntentRef:            "change:intent:apply",
		CapabilityRef:        "change:capability:write",
		Scopes:               []string{"change.write"},
		Resources:            []string{"config://tenant-01/feature-x"},
		AuthorizationDetails: []string{"change:set-enabled"},
	}
	grant := signJWT(t, managerPrivate, testManagerKeyID, jwt.MapClaims{
		"iss":                   testManagerIssuer,
		"sub":                   values.Agent,
		"aud":                   testAudience,
		"jti":                   "grant-0001",
		"iat":                   now.Add(-time.Minute).Unix(),
		"exp":                   now.Add(5 * time.Minute).Unix(),
		"profile_type":          clients.TokenTypeIdentityGrant,
		"profile_version":       clients.ProfileVersion,
		"cnf":                   map[string]string{"kid": testAgentKeyID},
		"service":               values.Service,
		"agent":                 values.Agent,
		"task_id":               values.TaskID,
		"intent_ref":            values.IntentRef,
		"capability_ref":        values.CapabilityRef,
		"scopes":                values.Scopes,
		"resources":             values.Resources,
		"authorization_details": values.AuthorizationDetails,
	})
	binding := signJWT(t, agentPrivate, testAgentKeyID, jwt.MapClaims{
		"iss":                       testAgentIssuer,
		"aud":                       testAudience,
		"jti":                       "binding-0001",
		"iat":                       now.Add(-30 * time.Second).Unix(),
		"exp":                       now.Add(2 * time.Minute).Unix(),
		"profile_type":              clients.TokenTypeSessionBinding,
		"profile_version":           clients.ProfileVersion,
		"grant_hash":                clients.IdentityGrantHash(grant),
		"leaf_public_key_sha256":    expectedBinding.LeafPublicKeySHA256,
		"tls_exporter_sha256":       expectedBinding.TLSExporterSHA256,
		"request_context_sha256":    expectedBinding.RequestContextSHA256,
		"attestation_binder_sha256": expectedBinding.AttestationBinderSHA256,
		"nonce":                     expectedBinding.Nonce,
	})
	attestation := AttestationResult{
		Version:                 AttestationResultVersion,
		ResultID:                testAttestationID,
		VerifierKeyID:           testAttesterKeyID,
		PolicyID:                testAttestationPolicyID,
		Measurement:             testMeasurement,
		AttestationBinderSHA256: expectedBinding.AttestationBinderSHA256,
		IssuedAt:                now.Add(-30 * time.Second),
		ExpiresAt:               now.Add(90 * time.Second),
	}
	signAttestation(t, &attestation, attesterPrivate)

	replay := &recordingReplayCache{seen: make(map[string]time.Time)}
	profile := Profile{
		GrantAuthority: AuthorityPolicy{
			ExpectedIssuer:   testManagerIssuer,
			ExpectedAudience: testAudience,
			ValidMethods:     []string{jwt.SigningMethodEdDSA.Alg()},
			TrustSource: StaticTrustSource{Trust: TrustSnapshot{Keys: []clients.LocalKey{
				{KeyID: testManagerKeyID, Key: managerPublic},
			}}},
			MaxTokenLifetime: 10 * time.Minute,
			ClockSkew:        5 * time.Second,
		},
		BindingAuthority: AuthorityPolicy{
			ExpectedIssuer:   testAgentIssuer,
			ExpectedAudience: testAudience,
			ValidMethods:     []string{jwt.SigningMethodEdDSA.Alg()},
			TrustSource: StaticTrustSource{Trust: TrustSnapshot{Keys: []clients.LocalKey{
				{KeyID: testAgentKeyID, Key: agentPublic},
			}}},
			MaxTokenLifetime: 5 * time.Minute,
			ClockSkew:        5 * time.Second,
		},
		IdentityPolicy: identitypolicy.Policy{
			Mode:     identitypolicy.ModeRequired,
			SetMode:  identitypolicy.SetModeExact,
			Require:  identitypolicy.Requirements{L3: true, L4: true, L5: true, L6: true},
			Expected: values,
		},
		Attestation: SignedAttestationPolicy{
			TrustedKeys:         map[string]ed25519.PublicKey{testAttesterKeyID: attesterPublic},
			PolicyID:            testAttestationPolicyID,
			AllowedMeasurements: []string{testMeasurement},
			MaxAge:              2 * time.Minute,
			ClockSkew:           5 * time.Second,
		},
		ReplayCache: replay,
		Now:         func() time.Time { return now },
	}
	return &profileFixture{
		profile:         profile,
		request:         VerifyRequest{GrantJWT: grant, SessionBindingJWT: binding, ExpectedBinding: expectedBinding, Attestation: attestation},
		managerPrivate:  managerPrivate,
		agentPrivate:    agentPrivate,
		attesterPrivate: attesterPrivate,
		replay:          replay,
		now:             now,
	}
}

func signJWT(t *testing.T, key ed25519.PrivateKey, keyID string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = keyID
	value, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return value
}

func resignJWT(t *testing.T, tokenString string, key ed25519.PrivateKey, keyID string, mutate func(jwt.MapClaims)) string {
	t.Helper()
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse JWT without verification: %v", err)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("JWT claims type = %T, want jwt.MapClaims", token.Claims)
	}
	mutate(claims)
	return signJWT(t, key, keyID, claims)
}

func signAttestation(t *testing.T, result *AttestationResult, key ed25519.PrivateKey) {
	t.Helper()
	result.Signature = nil
	payload, err := result.SigningBytes()
	if err != nil {
		t.Fatalf("attestation signing bytes: %v", err)
	}
	result.Signature = ed25519.Sign(key, payload)
}

func testHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}
