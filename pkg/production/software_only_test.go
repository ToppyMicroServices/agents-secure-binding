// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package production

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/thinksyncs/agents-secure-binding/pkg/atls/identitypolicy"
	"github.com/thinksyncs/agents-secure-binding/pkg/clients"
)

type softwareOnlyFixture struct {
	profile SoftwareOnlyProfile
	request SoftwareOnlyVerifyRequest
	base    *profileFixture
}

func TestSoftwareOnlyProfileVerifyAcceptsWithoutAttestation(t *testing.T) {
	t.Parallel()
	fixture := newSoftwareOnlyFixture(t)

	accepted, err := fixture.profile.Verify(context.Background(), fixture.request)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if accepted.Agent != "change-agent-01" || accepted.TaskID != "change-0001" {
		t.Fatalf("Verify() accepted = %+v", accepted)
	}
	if !accepted.AttestationExpiresAt.IsZero() {
		t.Fatalf("AttestationExpiresAt = %v, want zero", accepted.AttestationExpiresAt)
	}
	if fixture.base.replay.count() != 1 {
		t.Fatalf("replay commits = %d, want 1", fixture.base.replay.count())
	}
}

func TestSoftwareOnlyProfileRejectsReplay(t *testing.T) {
	t.Parallel()
	fixture := newSoftwareOnlyFixture(t)

	if _, err := fixture.profile.Verify(context.Background(), fixture.request); err != nil {
		t.Fatalf("first Verify() error = %v", err)
	}
	_, err := fixture.profile.Verify(context.Background(), fixture.request)
	if !errors.Is(err, identitypolicy.ErrReplayDetected) {
		t.Fatalf("second Verify() error = %v, want %v", err, identitypolicy.ErrReplayDetected)
	}
}

func TestSoftwareOnlyProfileRejectsAttestationBinding(t *testing.T) {
	t.Parallel()
	fixture := newSoftwareOnlyFixture(t)
	fixture.request.ExpectedBinding.AttestationBinderSHA256 = testHash("unexpected-attestation")

	_, err := fixture.profile.Verify(context.Background(), fixture.request)
	if !errors.Is(err, ErrUnexpectedAttestationBinding) {
		t.Fatalf("Verify() error = %v, want %v", err, ErrUnexpectedAttestationBinding)
	}
	if fixture.base.replay.count() != 0 {
		t.Fatalf("replay commits = %d, want 0", fixture.base.replay.count())
	}
}

func TestSoftwareOnlyProfileRejectsSessionProofWithAttestationBinder(t *testing.T) {
	t.Parallel()
	fixture := newSoftwareOnlyFixture(t)
	expected := fixture.request.ExpectedBinding
	fixture.request.SessionBindingJWT = signJWT(t, fixture.base.agentPrivate, testAgentKeyID, jwt.MapClaims{
		"iss":                       testAgentIssuer,
		"aud":                       testAudience,
		"jti":                       "binding-software-with-attestation-0001",
		"iat":                       fixture.base.now.Add(-30 * time.Second).Unix(),
		"exp":                       fixture.base.now.Add(2 * time.Minute).Unix(),
		"profile_type":              clients.TokenTypeSessionBinding,
		"profile_version":           clients.ProfileVersion,
		"grant_hash":                clients.IdentityGrantHash(fixture.base.request.GrantJWT),
		"leaf_public_key_sha256":    expected.LeafPublicKeySHA256,
		"tls_exporter_sha256":       expected.TLSExporterSHA256,
		"request_context_sha256":    expected.RequestContextSHA256,
		"attestation_binder_sha256": testHash("unexpected-attestation"),
		"nonce":                     expected.Nonce,
	})

	_, err := fixture.profile.Verify(context.Background(), fixture.request)
	if !errors.Is(err, ErrUnexpectedAttestationBinding) {
		t.Fatalf("Verify() error = %v, want %v", err, ErrUnexpectedAttestationBinding)
	}
	if fixture.base.replay.count() != 0 {
		t.Fatalf("replay commits = %d, want 0", fixture.base.replay.count())
	}
}

func TestSoftwareOnlyProfileNegativeGatesDoNotCommitReplay(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*softwareOnlyFixture)
		want   error
	}{
		{
			name: "trust source outage",
			mutate: func(f *softwareOnlyFixture) {
				f.profile.GrantAuthority.TrustSource = trustSourceFunc(func(context.Context) (TrustSnapshot, error) {
					return TrustSnapshot{}, errors.New("registry unavailable")
				})
			},
			want: ErrTrustSourceUnavailable,
		},
		{
			name: "revoked grant",
			mutate: func(f *softwareOnlyFixture) {
				f.profile.GrantAuthority.TrustSource = StaticTrustSource{Trust: TrustSnapshot{
					Keys:            []clients.LocalKey{{KeyID: testManagerKeyID, Key: f.base.managerPrivate.Public()}},
					RevokedTokenIDs: []string{"grant-0001"},
				}}
			},
			want: clients.ErrRevokedJWTID,
		},
		{
			name: "wrong action binding",
			mutate: func(f *softwareOnlyFixture) {
				f.request.ExpectedBinding.RequestContextSHA256 = testHash("different-action")
			},
			want: identitypolicy.ErrMismatch,
		},
		{
			name: "wrong local task",
			mutate: func(f *softwareOnlyFixture) {
				f.profile.IdentityPolicy.Expected.TaskID = "change-9999"
			},
			want: identitypolicy.ErrMismatch,
		},
		{
			name: "replay store outage",
			mutate: func(f *softwareOnlyFixture) {
				f.base.replay.err = errors.New("shared store unavailable")
			},
			want: errors.New("shared store unavailable"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fixture := newSoftwareOnlyFixture(t)
			tt.mutate(fixture)
			_, err := fixture.profile.Verify(context.Background(), fixture.request)
			if tt.name == "replay store outage" {
				if err == nil || !errors.Is(err, fixture.base.replay.err) {
					t.Fatalf("Verify() error = %v, want replay store error", err)
				}
			} else if !errors.Is(err, tt.want) {
				t.Fatalf("Verify() error = %v, want %v", err, tt.want)
			}
			if fixture.base.replay.count() != 0 {
				t.Fatalf("replay commits = %d, want 0", fixture.base.replay.count())
			}
		})
	}
}

func TestSoftwareOnlyProfileValidateRejectsIncompleteDeployment(t *testing.T) {
	t.Parallel()
	fixture := newSoftwareOnlyFixture(t)
	if err := fixture.profile.Validate(nil); !errors.Is(err, ErrMissingContext) {
		t.Fatalf("Validate(nil) error = %v, want %v", err, ErrMissingContext)
	}
	if _, err := fixture.profile.Verify(nil, fixture.request); !errors.Is(err, ErrMissingContext) {
		t.Fatalf("Verify(nil) error = %v, want %v", err, ErrMissingContext)
	}

	tests := []struct {
		name   string
		mutate func(*SoftwareOnlyProfile)
		want   error
	}{
		{"missing trust", func(p *SoftwareOnlyProfile) { p.GrantAuthority.TrustSource = nil }, ErrMissingTrustSource},
		{"missing replay", func(p *SoftwareOnlyProfile) { p.ReplayCache = nil }, ErrMissingReplayCache},
		{"missing policy", func(p *SoftwareOnlyProfile) { p.IdentityPolicy = identitypolicy.Policy{} }, ErrMissingPolicy},
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

func newSoftwareOnlyFixture(t *testing.T) *softwareOnlyFixture {
	t.Helper()
	base := newProfileFixture(t)
	expectedBinding := base.request.ExpectedBinding
	expectedBinding.AttestationBinderSHA256 = ""
	binding := signJWT(t, base.agentPrivate, testAgentKeyID, jwt.MapClaims{
		"iss":                    testAgentIssuer,
		"aud":                    testAudience,
		"jti":                    "binding-software-0001",
		"iat":                    base.now.Add(-30 * time.Second).Unix(),
		"exp":                    base.now.Add(2 * time.Minute).Unix(),
		"profile_type":           clients.TokenTypeSessionBinding,
		"profile_version":        clients.ProfileVersion,
		"grant_hash":             clients.IdentityGrantHash(base.request.GrantJWT),
		"leaf_public_key_sha256": expectedBinding.LeafPublicKeySHA256,
		"tls_exporter_sha256":    expectedBinding.TLSExporterSHA256,
		"request_context_sha256": expectedBinding.RequestContextSHA256,
		"nonce":                  expectedBinding.Nonce,
	})
	profile := SoftwareOnlyProfile{
		GrantAuthority:   base.profile.GrantAuthority,
		BindingAuthority: base.profile.BindingAuthority,
		IdentityPolicy:   base.profile.IdentityPolicy,
		ReplayCache:      base.replay,
		Now:              base.profile.Now,
	}
	return &softwareOnlyFixture{
		profile: profile,
		request: SoftwareOnlyVerifyRequest{
			GrantJWT:          base.request.GrantJWT,
			SessionBindingJWT: binding,
			ExpectedBinding:   expectedBinding,
		},
		base: base,
	}
}
