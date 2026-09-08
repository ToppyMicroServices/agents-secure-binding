// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/humanrelay"
	relaybinding "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/humanrelay/asbbinding"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

func TestHumanProtocolRedTeamRejectsCrossProfileAndAudienceConfusion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	store := seededIngressStore(t, now)
	current, err := store.LoadAssignment(ctx, "assignment:human:1")
	if err != nil {
		t.Fatal(err)
	}
	request := TransitionRequest{
		ParticipantID: current.ParticipantID,
		EventID:       "event:redteam:domain-confusion",
		TaskID:        current.TaskID, AssignmentID: current.AssignmentID,
		Operation: taskcoord.OperationAccept, ExpectedRevision: current.Revision,
	}
	digest, err := TransitionDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	profile := Profile{Participants: store, Now: func() time.Time { return now }}

	t.Run("relay profile proof", func(t *testing.T) {
		replay := identitypolicy.NewMemoryReplayCacheWithClock(func() time.Time { return now })
		evidence := crossProfileEvidence(t, now, digest, replay)
		if _, err := profile.Apply(ctx, current, request, evidence); err == nil {
			t.Fatal("Human profile accepted an Agent relay authorization detail and request context")
		}

		valid := testEvidence(
			t, now, digest, digest,
			"authorization:redteam:human-control",
			"proof:redteam:human-control",
			"nonce:redteam:human-control",
			replay,
		)
		if _, err := profile.Apply(ctx, current, request, valid); err != nil {
			t.Fatalf("cross-profile rejection poisoned a later valid proof: %v", err)
		}
	})

	t.Run("other audience realm", func(t *testing.T) {
		evidence := testEvidence(
			t, now, digest, digest,
			"authorization:redteam:audience",
			"proof:redteam:audience",
			"nonce:redteam:audience",
			nil,
		)
		evidence.Options.Grant.ExpectedAudience = "asb.example/realm/other"
		evidence.Options.SessionBinding.ExpectedAudience = "asb.example/realm/other"
		if _, err := profile.Apply(ctx, current, request, evidence); err == nil {
			t.Fatal("Human profile accepted proof from another audience realm")
		}

		evidence.Options.Grant.ExpectedAudience = testAudience
		evidence.Options.SessionBinding.ExpectedAudience = testAudience
		if _, err := profile.Apply(ctx, current, request, evidence); err != nil {
			t.Fatalf("audience rejection consumed or corrupted the valid proof: %v", err)
		}
	})
}

func crossProfileEvidence(
	t *testing.T,
	now time.Time,
	digest Digest,
	replay identitypolicy.ReplayCache,
) Evidence {
	t.Helper()
	managerSecret := []byte("manager-secret-for-human-binding-tests")
	actorSecret := []byte("actor-secret-for-human-binding-tests")
	relayDigest := humanrelay.Digest(digest)
	grant := signTestJWT(t, "manager-key", managerSecret, jwt.MapClaims{
		"iss": "human-operation-authority", "sub": testActorID, "aud": testAudience,
		"jti": "authorization:redteam:relay-substitution",
		"iat": now.Add(-2 * time.Minute).Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"profile_type": clients.TokenTypeIdentityGrant, "profile_version": clients.ProfileVersion,
		"cnf":                   map[string]any{"kid": "actor-key"},
		"authorization_details": []string{relaybinding.AuthorizationDetail(relayDigest)},
	})
	expected := identitypolicy.Binding{
		LeafPublicKeySHA256: repeatedDigest('1'), TLSExporterSHA256: repeatedDigest('2'),
		RequestContextSHA256: RequestContextSHA256(digest), Nonce: "nonce:redteam:relay-substitution",
	}
	statement := signTestJWT(t, "actor-key", actorSecret, jwt.MapClaims{
		"iss": "human-gateway", "aud": testAudience,
		"jti": "proof:redteam:relay-substitution",
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(2 * time.Minute).Unix(),
		"profile_type": clients.TokenTypeSessionBinding, "profile_version": clients.ProfileVersion,
		"grant_hash":             clients.IdentityGrantHash(grant),
		"leaf_public_key_sha256": expected.LeafPublicKeySHA256,
		"tls_exporter_sha256":    expected.TLSExporterSHA256,
		"request_context_sha256": relaybinding.RequestContextSHA256(relayDigest),
		"nonce":                  expected.Nonce,
	})
	if relaybinding.AuthorizationDetail(relayDigest) == AuthorizationDetail(digest) ||
		relaybinding.RequestContextSHA256(relayDigest) == RequestContextSHA256(digest) {
		t.Fatal("Human and relay profile domains are not separated")
	}
	if replay == nil {
		t.Fatal("test requires an explicit replay cache")
	}
	return Evidence{
		GrantJWT: grant, SessionBindingJWT: statement,
		Options: clients.SessionIdentityJWTOptions{
			Grant: clients.JWTVerifyOptions{
				ExpectedIssuer: "human-operation-authority", ExpectedAudience: testAudience,
				ValidMethods: []string{"HS256"}, LocalKeys: []clients.LocalKey{{KeyID: "manager-key", Key: managerSecret}},
			},
			SessionBinding: clients.JWTVerifyOptions{
				ExpectedIssuer: "human-gateway", ExpectedAudience: testAudience,
				ValidMethods: []string{"HS256"}, LocalKeys: []clients.LocalKey{{KeyID: "actor-key", Key: actorSecret}},
			},
			ExpectedBinding: expected,
			ReplayCache:     replay,
		},
	}
}
