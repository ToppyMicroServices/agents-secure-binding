// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package production

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
)

type replayCacheFunc func(string, time.Time) error

func (f replayCacheFunc) MarkUsed(key string, expiry time.Time) error {
	return f(key, expiry)
}

func TestProductionProfilesRecheckAcceptanceDeadline(t *testing.T) {
	for _, softwareOnly := range []bool{false, true} {
		name := "attested"
		if softwareOnly {
			name = "software-only"
		}
		t.Run(name, func(t *testing.T) {
			for _, stage := range []string{"trust lookup", "replay commit"} {
				for _, failure := range []string{"binding expires", "request cancelled", "clock unavailable", "attestation expires"} {
					if softwareOnly && failure == "attestation expires" {
						continue
					}
					t.Run(stage+"/"+failure, func(t *testing.T) {
						fixture := newProfileFixture(t)
						software := newSoftwareOnlyFixture(t)
						if softwareOnly {
							fixture = software.base
						}
						ctx, cancel := context.WithCancel(context.Background())
						defer cancel()
						now := fixture.now
						clock := func() time.Time { return now }
						want := identitypolicy.ErrExpiredAssertion
						advance := func() {
							switch failure {
							case "binding expires":
								now = fixture.now.Add(2*time.Minute + fixture.profile.BindingAuthority.ClockSkew)
							case "request cancelled":
								cancel()
							case "clock unavailable":
								now = time.Time{}
							case "attestation expires":
								now = fixture.request.Attestation.ExpiresAt.Add(6 * time.Second)
							}
						}
						switch failure {
						case "request cancelled":
							want = context.Canceled
						case "clock unavailable":
							want = ErrInvalidCurrentTime
						case "attestation expires":
							want = ErrAttestationExpired
						}
						grantAuthority := fixture.profile.GrantAuthority
						replay := identitypolicy.ReplayCache(fixture.replay)
						if stage == "trust lookup" {
							trust := grantAuthority.TrustSource
							grantAuthority.TrustSource = trustSourceFunc(func(ctx context.Context) (TrustSnapshot, error) {
								snapshot, err := trust.Snapshot(ctx)
								advance()
								return snapshot, err
							})
						} else {
							replay = replayCacheFunc(func(key string, expiry time.Time) error {
								err := fixture.replay.MarkUsed(key, expiry)
								advance()
								return err
							})
						}
						var accepted AcceptedIdentity
						var err error
						if softwareOnly {
							software.profile.Now = clock
							software.profile.GrantAuthority = grantAuthority
							software.profile.ReplayCache = replay
							accepted, err = software.profile.Verify(ctx, software.request)
						} else {
							fixture.profile.Now = clock
							fixture.profile.GrantAuthority = grantAuthority
							fixture.profile.ReplayCache = replay
							accepted, err = fixture.profile.Verify(ctx, fixture.request)
						}
						if !errors.Is(err, want) || !reflect.DeepEqual(accepted, AcceptedIdentity{}) {
							t.Fatalf("Verify() = (%+v, %v), want empty identity and %v", accepted, err, want)
						}
						wantCommits := 0
						if stage == "replay commit" {
							wantCommits = 1
						}
						if got := fixture.replay.count(); got != wantCommits {
							t.Fatalf("replay entries = %d, want %d", got, wantCommits)
						}
					})
				}
			}
		})
	}
}

func TestProductionProfilesRejectMissingClock(t *testing.T) {
	fixture := newProfileFixture(t)
	fixture.profile.Now = func() time.Time { return time.Time{} }
	if _, err := fixture.profile.Verify(context.Background(), fixture.request); !errors.Is(err, ErrInvalidCurrentTime) {
		t.Fatalf("attested Verify() = %v, want invalid clock", err)
	}
	software := newSoftwareOnlyFixture(t)
	software.profile.Now = fixture.profile.Now
	if _, err := software.profile.Verify(context.Background(), software.request); !errors.Is(err, ErrInvalidCurrentTime) {
		t.Fatalf("software-only Verify() = %v, want invalid clock", err)
	}
}

func TestProductionAcceptanceRecheckPreservesConfiguredSkew(t *testing.T) {
	software := newSoftwareOnlyFixture(t)
	now := software.base.now
	software.profile.Now = func() time.Time { return now }
	software.profile.ReplayCache = replayCacheFunc(func(key string, expiry time.Time) error {
		err := software.base.replay.MarkUsed(key, expiry)
		now = now.Add(2*time.Minute + 4*time.Second)
		return err
	})
	if _, err := software.profile.Verify(context.Background(), software.request); err != nil {
		t.Fatalf("configured binding skew was lost: %v", err)
	}

	attested := newProfileFixture(t)
	now = attested.now
	attested.profile.Now = func() time.Time { return now }
	attested.profile.ReplayCache = replayCacheFunc(func(key string, expiry time.Time) error {
		err := attested.replay.MarkUsed(key, expiry)
		now = attested.request.Attestation.ExpiresAt.Add(4 * time.Second)
		return err
	})
	if _, err := attested.profile.Verify(context.Background(), attested.request); err != nil {
		t.Fatalf("configured attestation skew was lost: %v", err)
	}
}

type attestationPolicyFunc func(context.Context, AttestationResult, string, time.Time) error

func (f attestationPolicyFunc) Verify(ctx context.Context, result AttestationResult, binder string, now time.Time) error {
	return f(ctx, result, binder, now)
}

func TestProfileRechecksAfterFinalAttestationCallback(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		name := "expiry"
		if cancelled {
			name = "cancellation"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newProfileFixture(t)
			now := fixture.now
			fixture.profile.Now = func() time.Time { return now }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			original := fixture.profile.Attestation
			calls := 0
			fixture.profile.Attestation = attestationPolicyFunc(func(ctx context.Context, result AttestationResult, binder string, checkedAt time.Time) error {
				if err := original.Verify(ctx, result, binder, checkedAt); err != nil {
					return err
				}
				calls++
				if calls == 3 {
					if cancelled {
						cancel()
					} else {
						now = fixture.now.Add(2*time.Minute + fixture.profile.BindingAuthority.ClockSkew)
					}
				}
				return nil
			})
			accepted, err := fixture.profile.Verify(ctx, fixture.request)
			want := identitypolicy.ErrExpiredAssertion
			if cancelled {
				want = context.Canceled
			}
			if !errors.Is(err, want) || !reflect.DeepEqual(accepted, AcceptedIdentity{}) || fixture.replay.count() != 1 {
				t.Fatalf("Verify() = (%+v, %v), commits=%d", accepted, err, fixture.replay.count())
			}
		})
	}
}
