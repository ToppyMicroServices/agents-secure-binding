// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/humanrelay"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
	"github.com/golang-jwt/jwt/v5"
)

const (
	relayTestAudience = "human-relay:test"
	relayTestActorID  = "service:agent-gateway"
)

func TestProfileVerifiesExactAgentRelayIntent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	request := relayTestRequest("agent:requester")
	profile := relayTestProfile(t, ctx, request.RequesterParticipantID, taskcoord.ParticipantAgent, taskcoord.ParticipantActive, now)
	digest, err := humanrelay.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	evidence := relayTestEvidence(t, now, digest, digest, "authorization:relay:1", "proof:relay:1", "nonce:relay:1", nil)

	projection, err := profile.VerifyAndConsume(ctx, request, evidence)
	if err != nil {
		t.Fatalf("VerifyAndConsume() error = %v", err)
	}
	if projection.RequestDigest != digest.String() || projection.ActorID != relayTestActorID {
		t.Fatalf("request digest/actor = %q/%q", projection.RequestDigest, projection.ActorID)
	}
	if projection.AuthorizationID != "authorization:relay:1" || projection.ProofID != "proof:relay:1" {
		t.Fatalf("authorization/proof = %q/%q", projection.AuthorizationID, projection.ProofID)
	}
	if projection.VerifierNonce != "nonce:relay:1" || !projection.IssuedAt.Equal(now.Add(-time.Minute)) ||
		!projection.ExpiresAt.Equal(now.Add(2*time.Minute)) {
		t.Fatalf("projection validity = %+v", projection)
	}
}

func TestProfileRejectsRequestAndSessionMismatch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	original := relayTestRequest("agent:requester")
	originalDigest, err := humanrelay.RequestDigest(original)
	if err != nil {
		t.Fatal(err)
	}
	changed := original
	changed.ContentRef = "https://relay.example.test/content/changed"
	changedDigest, err := humanrelay.RequestDigest(changed)
	if err != nil {
		t.Fatal(err)
	}
	profile := relayTestProfile(t, ctx, original.RequesterParticipantID, taskcoord.ParticipantAgent, taskcoord.ParticipantActive, now)

	t.Run("original session proof on changed request", func(t *testing.T) {
		evidence := relayTestEvidence(t, now, originalDigest, originalDigest, "authorization:relay:original", "proof:relay:original", "nonce:original", nil)
		_, err := profile.VerifyAndConsume(ctx, changed, evidence)
		if !errors.Is(err, ErrRequestContextMismatch) {
			t.Fatalf("error = %v, want ErrRequestContextMismatch", err)
		}
	})

	t.Run("changed session proof with original authorization", func(t *testing.T) {
		evidence := relayTestEvidence(t, now, originalDigest, changedDigest, "authorization:relay:changed", "proof:relay:changed", "nonce:changed", nil)
		_, err := profile.VerifyAndConsume(ctx, changed, evidence)
		if !errors.Is(err, identitypolicy.ErrMismatch) {
			t.Fatalf("error = %v, want identitypolicy.ErrMismatch", err)
		}
	})
}

func TestProfileRejectsWrongOrInactiveParticipant(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		kind   taskcoord.ParticipantKind
		status taskcoord.ParticipantStatus
		want   error
	}{
		{name: "Human", kind: taskcoord.ParticipantHuman, status: taskcoord.ParticipantActive, want: ErrAgentRequired},
		{name: "automated service", kind: taskcoord.ParticipantAutomatedService, status: taskcoord.ParticipantActive, want: ErrAgentRequired},
		{name: "suspended Agent", kind: taskcoord.ParticipantAgent, status: taskcoord.ParticipantSuspended, want: ErrAgentInactive},
		{name: "revoked Agent", kind: taskcoord.ParticipantAgent, status: taskcoord.ParticipantRevoked, want: ErrAgentInactive},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			request := relayTestRequest("participant:test:" + test.name)
			profile := relayTestProfile(t, ctx, request.RequesterParticipantID, test.kind, test.status, now)
			digest, err := humanrelay.RequestDigest(request)
			if err != nil {
				t.Fatal(err)
			}
			evidence := relayTestEvidence(t, now, digest, digest,
				"authorization:participant:"+string(rune('a'+index)),
				"proof:participant:"+string(rune('a'+index)),
				"nonce:participant:"+string(rune('a'+index)), nil)
			_, err = profile.VerifyAndConsume(ctx, request, evidence)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestProfileConsumesSessionProofOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	request := relayTestRequest("agent:requester")
	profile := relayTestProfile(t, ctx, request.RequesterParticipantID, taskcoord.ParticipantAgent, taskcoord.ParticipantActive, now)
	digest, err := humanrelay.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	evidence := relayTestEvidence(t, now, digest, digest, "authorization:relay:replay", "proof:relay:replay", "nonce:relay:replay", nil)

	const attempts = 8
	start := make(chan struct{})
	results := make(chan error, attempts)
	var wait sync.WaitGroup
	for range attempts {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := profile.VerifyAndConsume(ctx, request, evidence)
			results <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)

	accepted := 0
	for err := range results {
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, identitypolicy.ErrReplayDetected):
		default:
			t.Fatalf("unexpected replay result = %v", err)
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted attempts = %d, want 1", accepted)
	}
}

func TestFreshASBProofRecoversOriginalRelayReceipt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clock := time.Now().UTC().Truncate(time.Second)
	request := relayTestRequest("agent:requester")
	participants := taskcoord.NewMemoryStore()
	for _, participant := range []taskcoord.Participant{
		{
			Schema: taskcoord.ParticipantSchemaV1, ParticipantID: request.RequesterParticipantID,
			Kind: taskcoord.ParticipantAgent, IdentityRef: "identity:agent:requester",
			Status: taskcoord.ParticipantActive, RegisteredAt: clock.Add(-time.Hour),
		},
		{
			Schema: taskcoord.ParticipantSchemaV1, ParticipantID: "human:private:relay",
			Kind: taskcoord.ParticipantHuman, IdentityRef: "identity:human:private",
			Status: taskcoord.ParticipantActive, RegisteredAt: clock.Add(-time.Hour),
		},
	} {
		if err := participants.RegisterParticipant(ctx, participant); err != nil {
			t.Fatal(err)
		}
	}
	directory := taskcoord.NewMemoryReachabilityDirectory(participants)
	consent := taskcoord.HumanMatchConsent{
		Schema: taskcoord.HumanMatchConsentSchemaV1, ConsentID: "consent:relay:retry",
		HumanParticipantID: "human:private:relay", CandidateID: "candidate:relay:retry",
		RequesterParticipantID: request.RequesterParticipantID,
		Purpose:                request.Purpose, Capability: request.Capability, Channel: request.Channel,
		ContactRequestRef: "https://relay.example.test/contact/retry",
		ActorID:           "gateway:human", AuthorizationID: "authorization:consent:retry",
		ProofID: "proof:consent:retry", GrantedAt: clock.Add(-5 * time.Minute), ExpiresAt: clock.Add(time.Hour),
	}
	if err := directory.RegisterHumanMatchConsent(ctx, consent); err != nil {
		t.Fatal(err)
	}
	if _, err := directory.IssueHumanReachabilityGrant(ctx, taskcoord.HumanReachabilityGrantDefinition{
		GrantID: request.GrantID, ConsentID: consent.ConsentID,
		ApprovedByParticipantID: consent.HumanParticipantID, CandidateID: consent.CandidateID,
		RequesterParticipantID: request.RequesterParticipantID,
		Purpose:                request.Purpose, Capability: request.Capability, Channel: request.Channel,
		RelaySessionRef: "https://relay.example.test/sessions/retry",
		IssuedAt:        clock.Add(-time.Minute), ExpiresAt: clock.Add(30 * time.Minute),
		ApprovalActorID: "gateway:human", ApprovalAuthorizationID: "authorization:approval:retry",
		ApprovalProofID: "proof:approval:retry",
	}); err != nil {
		t.Fatal(err)
	}

	profile := Profile{Participants: participants, Now: func() time.Time { return clock }}
	relayStore, err := humanrelay.NewMemoryStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	service, err := humanrelay.NewService(relayStore, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	digest, err := humanrelay.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	replay := identitypolicy.NewMemoryReplayCacheWithClock(func() time.Time { return clock })
	firstEvidence := relayTestEvidence(
		t, clock, digest, digest,
		"authorization:relay:first", "proof:relay:first", "nonce:relay:first", replay,
	)
	firstAuth, err := profile.VerifyAndConsume(ctx, request, firstEvidence)
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.Queue(ctx, request, firstAuth)
	if err != nil {
		t.Fatal(err)
	}

	clock = clock.Add(time.Second)
	retryEvidence := relayTestEvidence(
		t, clock, digest, digest,
		"authorization:relay:retry", "proof:relay:retry", "nonce:relay:retry", replay,
	)
	retryAuth, err := profile.VerifyAndConsume(ctx, request, retryEvidence)
	if err != nil {
		t.Fatalf("fresh ASB proof error = %v", err)
	}
	recovered, err := service.Queue(ctx, request, retryAuth)
	if err != nil {
		t.Fatalf("lost-response recovery error = %v", err)
	}
	if recovered != first {
		t.Fatalf("recovered receipt = %+v, want original %+v", recovered, first)
	}
	events, err := relayStore.Events(request.IntentID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("fresh proof duplicated relay intent: %+v", events)
	}
}

func TestProfileRejectsAmbiguousPolicyAndMissingReplayCache(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	request := relayTestRequest("agent:requester")
	profile := relayTestProfile(t, ctx, request.RequesterParticipantID, taskcoord.ParticipantAgent, taskcoord.ParticipantActive, now)
	digest, err := humanrelay.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("missing replay cache", func(t *testing.T) {
		evidence := relayTestEvidence(t, now, digest, digest, "authorization:relay:no-replay", "proof:relay:no-replay", "nonce:no-replay", nil)
		evidence.Options.ReplayCache = nil
		_, err := profile.VerifyAndConsume(ctx, request, evidence)
		if !errors.Is(err, clients.ErrMissingReplayCache) {
			t.Fatalf("error = %v, want clients.ErrMissingReplayCache", err)
		}
	})
	t.Run("typed-nil replay cache", func(t *testing.T) {
		evidence := relayTestEvidence(t, now, digest, digest, "authorization:relay:typed-nil-replay", "proof:relay:typed-nil-replay", "nonce:typed-nil-replay", nil)
		var replay *identitypolicy.MemoryReplayCache
		evidence.Options.ReplayCache = replay
		_, err := profile.VerifyAndConsume(ctx, request, evidence)
		if !errors.Is(err, clients.ErrMissingReplayCache) {
			t.Fatalf("error = %v, want clients.ErrMissingReplayCache", err)
		}
	})
	t.Run("typed-nil Participant resolver", func(t *testing.T) {
		var participants *taskcoord.MemoryStore
		typedNilProfile := Profile{Participants: participants}
		_, err := typedNilProfile.resolveParticipant(ctx, request.RequesterParticipantID)
		if !errors.Is(err, ErrMissingParticipantResolver) {
			t.Fatalf("error = %v, want ErrMissingParticipantResolver", err)
		}
	})

	for _, mutate := range []struct {
		name string
		set  func(*identitypolicy.Policy)
	}{
		{name: "disabled policy", set: func(policy *identitypolicy.Policy) { policy.Mode = identitypolicy.ModeDisabled }},
		{name: "contains-all set mode", set: func(policy *identitypolicy.Policy) { policy.SetMode = identitypolicy.SetModeContainsAll }},
		{name: "caller authorization detail", set: func(policy *identitypolicy.Policy) {
			policy.Expected.AuthorizationDetails = []string{"urn:caller-selected"}
		}},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			evidence := relayTestEvidence(t, now, digest, digest, "authorization:relay:"+mutate.name, "proof:relay:"+mutate.name, "nonce:"+mutate.name, nil)
			mutate.set(&evidence.Options.Policy)
			_, err := profile.VerifyAndConsume(ctx, request, evidence)
			if !errors.Is(err, ErrAmbiguousPolicy) {
				t.Fatalf("error = %v, want ErrAmbiguousPolicy", err)
			}
		})
	}
}

func relayTestRequest(requesterParticipantID string) humanrelay.RelayIntentRequest {
	return humanrelay.RelayIntentRequest{
		IntentID:               "intent:relay:1",
		GrantID:                "grant:reachability:1",
		RequesterParticipantID: requesterParticipantID,
		Purpose:                "human-review",
		Capability:             "review-document",
		Channel:                taskcoord.ReachabilityEmail,
		ContentRef:             "https://relay.example.test/content/1",
		ContentDigest:          relayRepeatedDigest('a'),
	}
}

func relayTestProfile(
	t *testing.T,
	ctx context.Context,
	participantID string,
	kind taskcoord.ParticipantKind,
	status taskcoord.ParticipantStatus,
	now time.Time,
) Profile {
	t.Helper()
	store := taskcoord.NewMemoryStore()
	participant := taskcoord.Participant{
		Schema: taskcoord.ParticipantSchemaV1, ParticipantID: participantID, Kind: kind,
		IdentityRef: "urn:identity:opaque:" + participantID, Status: status, RegisteredAt: now.Add(-time.Hour),
	}
	if err := store.RegisterParticipant(ctx, participant); err != nil {
		t.Fatal(err)
	}
	return Profile{Participants: store, Now: func() time.Time { return now }}
}

func relayTestEvidence(
	t *testing.T,
	now time.Time,
	authorizedDigest humanrelay.Digest,
	contextDigest humanrelay.Digest,
	authorizationID string,
	proofID string,
	nonce string,
	replay identitypolicy.ReplayCache,
) Evidence {
	t.Helper()
	managerSecret := []byte("manager-secret-for-agent-relay-tests")
	actorSecret := []byte("actor-secret-for-agent-relay-tests")
	grant := relaySignTestJWT(t, "manager-key", managerSecret, jwt.MapClaims{
		"iss":                   "agent-relay-authority",
		"sub":                   relayTestActorID,
		"aud":                   relayTestAudience,
		"jti":                   authorizationID,
		"iat":                   now.Add(-2 * time.Minute).Unix(),
		"exp":                   now.Add(5 * time.Minute).Unix(),
		"profile_type":          clients.TokenTypeIdentityGrant,
		"profile_version":       clients.ProfileVersion,
		"cnf":                   map[string]any{"kid": "actor-key"},
		"authorization_details": []string{AuthorizationDetail(authorizedDigest)},
	})
	binding := identitypolicy.Binding{
		LeafPublicKeySHA256:  relayRepeatedDigest('1'),
		TLSExporterSHA256:    relayRepeatedDigest('2'),
		RequestContextSHA256: RequestContextSHA256(contextDigest),
		Nonce:                nonce,
	}
	statement := relaySignTestJWT(t, "actor-key", actorSecret, jwt.MapClaims{
		"iss":                    "agent-gateway",
		"aud":                    relayTestAudience,
		"jti":                    proofID,
		"iat":                    now.Add(-time.Minute).Unix(),
		"exp":                    now.Add(2 * time.Minute).Unix(),
		"profile_type":           clients.TokenTypeSessionBinding,
		"profile_version":        clients.ProfileVersion,
		"grant_hash":             clients.IdentityGrantHash(grant),
		"leaf_public_key_sha256": binding.LeafPublicKeySHA256,
		"tls_exporter_sha256":    binding.TLSExporterSHA256,
		"request_context_sha256": binding.RequestContextSHA256,
		"nonce":                  nonce,
	})
	if replay == nil {
		replay = identitypolicy.NewMemoryReplayCacheWithClock(func() time.Time { return now })
	}
	return Evidence{
		GrantJWT: grant, SessionBindingJWT: statement,
		Options: clients.SessionIdentityJWTOptions{
			Grant: clients.JWTVerifyOptions{
				ExpectedIssuer: "agent-relay-authority", ExpectedAudience: relayTestAudience,
				ValidMethods: []string{"HS256"}, LocalKeys: []clients.LocalKey{{KeyID: "manager-key", Key: managerSecret}},
			},
			SessionBinding: clients.JWTVerifyOptions{
				ExpectedIssuer: "agent-gateway", ExpectedAudience: relayTestAudience,
				ValidMethods: []string{"HS256"}, LocalKeys: []clients.LocalKey{{KeyID: "actor-key", Key: actorSecret}},
			},
			ExpectedBinding: binding,
			ReplayCache:     replay,
		},
	}
}

func relaySignTestJWT(t *testing.T, keyID string, secret []byte, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = keyID
	signed, err := token.SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func relayRepeatedDigest(character byte) string {
	return strings.Repeat(string(character), 64)
}
