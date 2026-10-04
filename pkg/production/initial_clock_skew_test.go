// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package production

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	"github.com/golang-jwt/jwt/v5"
)

const (
	initialExpiryClaim    = "exp"
	initialIssuedAtClaim  = "iat"
	initialNotBeforeClaim = "nbf"
)

func TestProductionInitialFreshnessUsesEachAuthoritySkew(t *testing.T) {
	for _, softwareOnly := range []bool{false, true} {
		profileName := "attested"
		if softwareOnly {
			profileName = "software-only"
		}
		for _, grantRole := range []bool{false, true} {
			roleName := "binding"
			if grantRole {
				roleName = "grant"
			}
			for _, test := range []struct {
				name   string
				claim  string
				offset time.Duration
				skew   time.Duration
				want   error
			}{
				{"expiry within skew", initialExpiryClaim, -time.Second, 2 * time.Second, nil},
				{"expiry at skew boundary", initialExpiryClaim, -2 * time.Second, 2 * time.Second, jwt.ErrTokenExpired},
				{"expiry beyond own skew", initialExpiryClaim, -3 * time.Second, 2 * time.Second, jwt.ErrTokenExpired},
				{"future issue within skew", initialIssuedAtClaim, time.Second, 2 * time.Second, nil},
				{"future issue beyond own skew", initialIssuedAtClaim, 3 * time.Second, 2 * time.Second, jwt.ErrTokenUsedBeforeIssued},
				{"not before within skew", initialNotBeforeClaim, time.Second, 2 * time.Second, nil},
				{"not before beyond own skew", initialNotBeforeClaim, 3 * time.Second, 2 * time.Second, jwt.ErrTokenNotValidYet},
				{"expiry with zero skew", initialExpiryClaim, 0, 0, jwt.ErrTokenExpired},
				{"future issue with zero skew", initialIssuedAtClaim, time.Second, 0, jwt.ErrTokenUsedBeforeIssued},
			} {
				t.Run(profileName+"/"+roleName+"/"+test.name, func(t *testing.T) {
					fixture := newProfileFixture(t)
					var software *softwareOnlyFixture
					if softwareOnly {
						software = newSoftwareOnlyFixture(t)
						fixture = software.base
						fixture.request.GrantJWT = software.request.GrantJWT
						fixture.request.SessionBindingJWT = software.request.SessionBindingJWT
					}
					grantAuthority := fixture.profile.GrantAuthority
					bindingAuthority := fixture.profile.BindingAuthority
					// A more permissive other role must not supply this token's skew.
					grantAuthority.ClockSkew = 10 * time.Second
					bindingAuthority.ClockSkew = 10 * time.Second
					grantExpiry := fixture.now.Add(5 * time.Minute)
					bindingExpiry := fixture.now.Add(2 * time.Minute)
					changedTime := fixture.now.Add(test.offset)
					mutate := func(claims jwt.MapClaims) { claims[test.claim] = changedTime.Unix() }
					if grantRole {
						grantAuthority.ClockSkew = test.skew
						fixture.request.GrantJWT = resignJWT(t, fixture.request.GrantJWT, fixture.managerPrivate, testManagerKeyID, mutate)
						fixture.request.SessionBindingJWT = resignJWT(t, fixture.request.SessionBindingJWT, fixture.agentPrivate, testAgentKeyID, func(claims jwt.MapClaims) {
							claims["grant_hash"] = clients.IdentityGrantHash(fixture.request.GrantJWT)
						})
						if test.claim == initialExpiryClaim {
							grantExpiry = changedTime
						}
					} else {
						bindingAuthority.ClockSkew = test.skew
						fixture.request.SessionBindingJWT = resignJWT(t, fixture.request.SessionBindingJWT, fixture.agentPrivate, testAgentKeyID, mutate)
						if test.claim == initialExpiryClaim {
							bindingExpiry = changedTime
						}
					}
					var accepted AcceptedIdentity
					var err error
					if softwareOnly {
						software.profile.GrantAuthority = grantAuthority
						software.profile.BindingAuthority = bindingAuthority
						software.request.GrantJWT = fixture.request.GrantJWT
						software.request.SessionBindingJWT = fixture.request.SessionBindingJWT
						accepted, err = software.profile.Verify(context.Background(), software.request)
					} else {
						fixture.profile.GrantAuthority = grantAuthority
						fixture.profile.BindingAuthority = bindingAuthority
						accepted, err = fixture.profile.Verify(context.Background(), fixture.request)
					}
					if test.want != nil {
						if !errors.Is(err, test.want) || fixture.replay.count() != 0 || !reflect.DeepEqual(accepted, AcceptedIdentity{}) {
							t.Fatalf("Verify() = (%+v, %v), commits=%d, want %v", accepted, err, fixture.replay.count(), test.want)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					if !accepted.GrantExpiresAt.Equal(grantExpiry) || !accepted.SessionBindingExpiresAt.Equal(bindingExpiry) {
						t.Fatalf("authenticated expiries were rewritten: %+v", accepted)
					}
					wantValues := fixture.profile.IdentityPolicy.Expected
					if !reflect.DeepEqual(accepted.Scopes, wantValues.Scopes) || !reflect.DeepEqual(accepted.Resources, wantValues.Resources) || !reflect.DeepEqual(accepted.AuthorizationDetails, wantValues.AuthorizationDetails) {
						t.Fatalf("authorization changed: %+v", accepted)
					}
					wantRetention := earliestTime(grantExpiry.Add(grantAuthority.ClockSkew), bindingExpiry.Add(bindingAuthority.ClockSkew))
					if fixture.replay.count() != 1 {
						t.Fatalf("replay commits=%d, want 1", fixture.replay.count())
					}
					for _, expiresAt := range fixture.replay.seen {
						if !expiresAt.Equal(wantRetention) {
							t.Fatalf("replay expiry=%v, want %v", expiresAt, wantRetention)
						}
					}
				})
			}
		}
	}
}

func TestProductionAcceptanceRejectsClockRollbackBeforeNotBefore(t *testing.T) {
	fixture := newSoftwareOnlyFixture(t)
	now := fixture.base.now
	fixture.profile.Now = func() time.Time { return now }
	fixture.profile.BindingAuthority.ClockSkew = 0
	fixture.request.SessionBindingJWT = resignJWT(t, fixture.request.SessionBindingJWT, fixture.base.agentPrivate, testAgentKeyID, func(claims jwt.MapClaims) {
		claims[initialNotBeforeClaim] = now.Unix()
	})
	fixture.profile.ReplayCache = replayCacheFunc(func(key string, expiry time.Time) error {
		err := fixture.base.replay.MarkUsed(key, expiry)
		// Still after iat, but no longer after the authenticated nbf.
		now = now.Add(-time.Second)
		return err
	})
	accepted, err := fixture.profile.Verify(context.Background(), fixture.request)
	if !errors.Is(err, ErrInvalidCurrentTime) || fixture.base.replay.count() != 1 || !reflect.DeepEqual(accepted, AcceptedIdentity{}) {
		t.Fatalf("rollback Verify() = (%+v, %v), commits=%d", accepted, err, fixture.base.replay.count())
	}
}
