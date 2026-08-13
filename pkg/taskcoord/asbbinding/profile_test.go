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

	"github.com/golang-jwt/jwt/v5"
	"github.com/thinksyncs/agents-secure-binding/pkg/atls/identitypolicy"
	"github.com/thinksyncs/agents-secure-binding/pkg/clients"
	"github.com/thinksyncs/agents-secure-binding/pkg/taskcoord"
)

const (
	testAudience = "split-agent:test"
	testActorID  = "service:human-gateway"
)

func TestProfileAppliesExactHumanAssignmentRequest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	human := testParticipant("human:alice", taskcoord.ParticipantHuman, true, now.Add(-time.Hour))
	store := taskcoord.NewMemoryStore()
	registerParticipants(t, ctx, store, human)
	current := offeredHumanAssignment(t, human, now.Add(-10*time.Minute))
	profile := Profile{Participants: store, Now: func() time.Time { return now }}
	request := TransitionRequest{
		ParticipantID:    human.ParticipantID,
		EventID:          "event:accept:1",
		TaskID:           current.TaskID,
		AssignmentID:     current.AssignmentID,
		Operation:        taskcoord.OperationAccept,
		ExpectedRevision: current.Revision,
		Detail:           "accept bounded responsibility",
		EvidenceRef:      "urn:evidence:human-accept:1",
	}
	digest, err := TransitionDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	evidence := testEvidence(t, now, digest, digest, "authorization:human:1", "proof:session:1", "nonce:1", nil)

	transition, err := profile.Apply(ctx, current, request, evidence)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if transition.Assignment.Status != taskcoord.AssignmentAccepted {
		t.Fatalf("status = %s, want ACCEPTED", transition.Assignment.Status)
	}
	if transition.Record.ParticipantID != human.ParticipantID || transition.Record.ActorID != testActorID {
		t.Fatalf("participant/actor = %q/%q", transition.Record.ParticipantID, transition.Record.ActorID)
	}
	if transition.Record.AuthorizationID != "authorization:human:1" || transition.Record.ProofID != "proof:session:1" {
		t.Fatalf("authorization/proof = %q/%q", transition.Record.AuthorizationID, transition.Record.ProofID)
	}
	if !transition.Record.At.Equal(now) {
		t.Fatalf("event time = %s, want verifier time %s", transition.Record.At, now)
	}
}

func TestProfileRejectsActorSessionChangingAuthorizedRequest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	human := testParticipant("human:alice", taskcoord.ParticipantHuman, false, now.Add(-time.Hour))
	store := taskcoord.NewMemoryStore()
	registerParticipants(t, ctx, store, human)
	current := offeredHumanAssignment(t, human, now.Add(-10*time.Minute))
	profile := Profile{Participants: store, Now: func() time.Time { return now }}
	authorized := TransitionRequest{
		ParticipantID: human.ParticipantID, EventID: "event:accept:1", TaskID: current.TaskID,
		AssignmentID: current.AssignmentID, Operation: taskcoord.OperationAccept,
		ExpectedRevision: current.Revision, Detail: "original",
	}
	changed := authorized
	changed.Detail = "substituted after Human authorization"
	authorizedDigest, err := TransitionDigest(authorized)
	if err != nil {
		t.Fatal(err)
	}
	changedDigest, err := TransitionDigest(changed)
	if err != nil {
		t.Fatal(err)
	}
	// The Actor can create a fresh session proof for the changed request, but
	// the operation-authority grant still authorizes only the original digest.
	evidence := testEvidence(t, now, authorizedDigest, changedDigest, "authorization:human:1", "proof:session:changed", "nonce:changed", nil)
	_, err = profile.Apply(ctx, current, changed, evidence)
	if !errors.Is(err, identitypolicy.ErrMismatch) {
		t.Fatalf("error = %v, want identitypolicy.ErrMismatch", err)
	}
}

func TestProfileRejectsOriginalProofOnMutatedRequest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	human := testParticipant("human:alice", taskcoord.ParticipantHuman, false, now.Add(-time.Hour))
	store := taskcoord.NewMemoryStore()
	registerParticipants(t, ctx, store, human)
	current := offeredHumanAssignment(t, human, now.Add(-10*time.Minute))
	profile := Profile{Participants: store, Now: func() time.Time { return now }}
	original := TransitionRequest{
		ParticipantID: human.ParticipantID, EventID: "event:accept:1", TaskID: current.TaskID,
		AssignmentID: current.AssignmentID, Operation: taskcoord.OperationAccept,
		ExpectedRevision: current.Revision,
	}
	digest, err := TransitionDigest(original)
	if err != nil {
		t.Fatal(err)
	}
	evidence := testEvidence(t, now, digest, digest, "authorization:human:1", "proof:session:1", "nonce:1", nil)
	mutated := original
	mutated.EventID = "event:accept:2"
	_, err = profile.Apply(ctx, current, mutated, evidence)
	if !errors.Is(err, ErrRequestContextMismatch) {
		t.Fatalf("error = %v, want ErrRequestContextMismatch", err)
	}
}

func TestProfileRejectsReplay(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	human := testParticipant("human:alice", taskcoord.ParticipantHuman, false, now.Add(-time.Hour))
	store := taskcoord.NewMemoryStore()
	registerParticipants(t, ctx, store, human)
	current := offeredHumanAssignment(t, human, now.Add(-10*time.Minute))
	profile := Profile{Participants: store, Now: func() time.Time { return now }}
	request := TransitionRequest{
		ParticipantID: human.ParticipantID, EventID: "event:accept:1", TaskID: current.TaskID,
		AssignmentID: current.AssignmentID, Operation: taskcoord.OperationAccept,
		ExpectedRevision: current.Revision,
	}
	digest, err := TransitionDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	evidence := testEvidence(t, now, digest, digest, "authorization:human:1", "proof:session:1", "nonce:1", nil)
	if _, err := profile.Apply(ctx, current, request, evidence); err != nil {
		t.Fatal(err)
	}
	if _, err := profile.Apply(ctx, current, request, evidence); !errors.Is(err, identitypolicy.ErrReplayDetected) {
		t.Fatalf("replay error = %v, want ErrReplayDetected", err)
	}
}

func TestProfileIntersectsTrustedAcceptanceWindow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	human := testParticipant("human:alice", taskcoord.ParticipantHuman, false, now.Add(-time.Hour))
	store := taskcoord.NewMemoryStore()
	registerParticipants(t, ctx, store, human)
	profile := Profile{Participants: store, Now: func() time.Time { return now }}
	request := TransitionRequest{
		ParticipantID: human.ParticipantID, EventID: "event:accept:1", TaskID: "task:1",
		AssignmentID: "assignment:1", Operation: taskcoord.OperationAccept, ExpectedRevision: 1,
	}
	digest, err := TransitionDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	evidence := testEvidence(t, now, digest, digest, "authorization:1", "proof:1", "nonce:1", nil)
	evidence.AcceptedUntil = now.Add(30 * time.Second)

	accepted, err := profile.accept(ctx, human.ParticipantID, digest, evidence, now)
	if err != nil {
		t.Fatal(err)
	}
	if !accepted.expiresAt.Equal(evidence.AcceptedUntil) {
		t.Fatalf("expires_at = %s, want %s", accepted.expiresAt, evidence.AcceptedUntil)
	}

	expired := evidence
	expired.AcceptedUntil = now
	if _, err := profile.accept(ctx, human.ParticipantID, digest, expired, now); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("expired local window error = %v, want ErrInvalidProjection", err)
	}
}

func TestProfileAcceptsAtMostOneConcurrentReplay(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	human := testParticipant("human:alice", taskcoord.ParticipantHuman, false, now.Add(-time.Hour))
	store := taskcoord.NewMemoryStore()
	registerParticipants(t, ctx, store, human)
	current := offeredHumanAssignment(t, human, now.Add(-10*time.Minute))
	profile := Profile{Participants: store, Now: func() time.Time { return now }}
	request := TransitionRequest{
		ParticipantID: human.ParticipantID, EventID: "event:accept:1", TaskID: current.TaskID,
		AssignmentID: current.AssignmentID, Operation: taskcoord.OperationAccept,
		ExpectedRevision: current.Revision,
	}
	digest, err := TransitionDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	evidence := testEvidence(t, now, digest, digest, "authorization:human:1", "proof:session:1", "nonce:1", nil)

	const attempts = 8
	start := make(chan struct{})
	errorsByAttempt := make(chan error, attempts)
	var wait sync.WaitGroup
	for range attempts {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := profile.Apply(ctx, current, request, evidence)
			errorsByAttempt <- err
		}()
	}
	close(start)
	wait.Wait()
	close(errorsByAttempt)

	accepted := 0
	for err := range errorsByAttempt {
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, identitypolicy.ErrReplayDetected):
		default:
			t.Fatalf("unexpected concurrent error = %v", err)
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted attempts = %d, want 1", accepted)
	}
}

func TestProfileRejectsInactiveOrNonHumanParticipant(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	activeHuman := testParticipant("human:active", taskcoord.ParticipantHuman, false, now.Add(-time.Hour))
	current := offeredHumanAssignment(t, activeHuman, now.Add(-10*time.Minute))
	tests := []struct {
		name        string
		participant taskcoord.Participant
		want        error
	}{
		{
			name: "suspended Human",
			participant: func() taskcoord.Participant {
				participant := activeHuman
				participant.Status = taskcoord.ParticipantSuspended
				return participant
			}(),
			want: ErrHumanInactive,
		},
		{
			name:        "Agent",
			participant: testParticipant("agent:gateway", taskcoord.ParticipantAgent, false, now.Add(-time.Hour)),
			want:        ErrHumanRequired,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			store := taskcoord.NewMemoryStore()
			registerParticipants(t, ctx, store, test.participant)
			request := TransitionRequest{
				ParticipantID: test.participant.ParticipantID, EventID: "event:accept:1", TaskID: current.TaskID,
				AssignmentID: current.AssignmentID, Operation: taskcoord.OperationAccept,
				ExpectedRevision: current.Revision,
			}
			digest, err := TransitionDigest(request)
			if err != nil {
				t.Fatal(err)
			}
			evidence := testEvidence(t, now, digest, digest, "authorization:human:1", "proof:"+test.name, "nonce:"+test.name, nil)
			profile := Profile{Participants: store, Now: func() time.Time { return now }}
			_, err = profile.Apply(ctx, current, request, evidence)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestProfileOffersDelegatesAndAuthorsInteraction(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	human := testParticipant("human:alice", taskcoord.ParticipantHuman, true, now.Add(-time.Hour))
	agent := testParticipant("agent:reviewer", taskcoord.ParticipantAgent, false, now.Add(-time.Hour))
	store := taskcoord.NewMemoryStore()
	registerParticipants(t, ctx, store, human, agent)
	profile := Profile{Participants: store, Now: func() time.Time { return now }}

	dueAt := now.Add(time.Hour)
	offerRequest := OfferRequest{
		ParticipantID: human.ParticipantID, EventID: "event:offer:1", TaskID: "task:offered:1",
		AssignmentID: "assignment:offered:1", TargetParticipantID: agent.ParticipantID,
		Role: taskcoord.RoleReviewer, AuthorityDigest: repeatedDigest('d'), DueAt: &dueAt,
	}
	offerDigest, err := OfferDigest(offerRequest)
	if err != nil {
		t.Fatal(err)
	}
	offered, err := profile.Offer(ctx, offerRequest, testEvidence(t, now, offerDigest, offerDigest, "authorization:offer:1", "proof:offer:1", "nonce:offer:1", nil))
	if err != nil {
		t.Fatalf("Offer() error = %v", err)
	}
	if offered.Assignment.OfferedByParticipantID != human.ParticipantID || offered.Assignment.ParticipantID != agent.ParticipantID {
		t.Fatalf("offer binding = %+v", offered.Assignment)
	}

	parent := acceptedHumanAssignment(t, human, now.Add(-10*time.Minute))
	delegationRequest := DelegationRequest{
		ParticipantID: human.ParticipantID, EventID: "event:delegate:1",
		ParentTaskID: parent.TaskID, ParentAssignmentID: parent.AssignmentID,
		ExpectedRevision: parent.Revision, ChildEventID: "event:child:offer:1",
		DecisionID:  "decision:1",
		ChildTaskID: "task:child:1", ChildAssignmentID: "assignment:child:1",
		TargetParticipantID: agent.ParticipantID, Role: taskcoord.RoleReviewer,
		AuthorityDigest: repeatedDigest('e'), DueAt: &dueAt,
	}
	delegationDigest, err := DelegationDigest(delegationRequest)
	if err != nil {
		t.Fatal(err)
	}
	verified := taskcoord.VerifiedDelegation{
		DecisionID: "decision:1", ParentAssignmentID: parent.AssignmentID,
		ChildAssignmentID: delegationRequest.ChildAssignmentID,
		FromParticipantID: human.ParticipantID, ToParticipantID: agent.ParticipantID,
		ParentAuthorityDigest: parent.AuthorityDigest,
		ChildAuthorityDigest:  delegationRequest.AuthorityDigest,
		PolicyRef:             "urn:policy:delegation:1", EvidenceRef: "urn:evidence:delegation:1",
		VerifiedAt: now.Add(-time.Minute),
	}
	delegated, err := profile.Delegate(ctx, parent, delegationRequest, verified,
		testEvidence(t, now, delegationDigest, delegationDigest, "authorization:delegate:1", "proof:delegate:1", "nonce:delegate:1", nil))
	if err != nil {
		t.Fatalf("Delegate() error = %v", err)
	}
	if delegated.Parent.Status != taskcoord.AssignmentAccepted || delegated.Child.Status != taskcoord.AssignmentOffered {
		t.Fatalf("delegation states = %s/%s", delegated.Parent.Status, delegated.Child.Status)
	}

	interactionRequest := InteractionRequest{
		ParticipantID: human.ParticipantID, EventID: "event:question:1",
		InteractionID: "interaction:1", TaskID: parent.TaskID, AssignmentID: parent.AssignmentID,
		Kind: taskcoord.InteractionQuestion, ContentRef: "urn:content:question:1",
		ContentDigest: repeatedDigest('f'),
	}
	interactionDigest, err := InteractionDigest(interactionRequest)
	if err != nil {
		t.Fatal(err)
	}
	interaction, err := profile.NewInteractionEvent(ctx, interactionRequest,
		testEvidence(t, now, interactionDigest, interactionDigest, "authorization:interaction:1", "proof:interaction:1", "nonce:interaction:1", nil))
	if err != nil {
		t.Fatalf("NewInteractionEvent() error = %v", err)
	}
	if interaction.ParticipantID != human.ParticipantID || interaction.ActorID != testActorID ||
		interaction.ContentDigest != interactionRequest.ContentDigest {
		t.Fatalf("interaction = %+v", interaction)
	}
}

func TestProfileRequiresReplayAndOwnsExactAuthorizationDetailPolicy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	human := testParticipant("human:alice", taskcoord.ParticipantHuman, false, now.Add(-time.Hour))
	store := taskcoord.NewMemoryStore()
	registerParticipants(t, ctx, store, human)
	current := offeredHumanAssignment(t, human, now.Add(-10*time.Minute))
	profile := Profile{Participants: store, Now: func() time.Time { return now }}
	request := TransitionRequest{
		ParticipantID: human.ParticipantID, EventID: "event:accept:1", TaskID: current.TaskID,
		AssignmentID: current.AssignmentID, Operation: taskcoord.OperationAccept,
		ExpectedRevision: current.Revision,
	}
	digest, err := TransitionDigest(request)
	if err != nil {
		t.Fatal(err)
	}

	missingReplay := testEvidence(t, now, digest, digest, "authorization:1", "proof:1", "nonce:1", identitypolicy.NewMemoryReplayCache())
	missingReplay.Options.ReplayCache = nil
	if _, err := profile.Apply(ctx, current, request, missingReplay); !errors.Is(err, clients.ErrMissingReplayCache) {
		t.Fatalf("missing replay error = %v", err)
	}

	ambiguous := testEvidence(t, now, digest, digest, "authorization:2", "proof:2", "nonce:2", nil)
	ambiguous.Options.Policy.SetMode = identitypolicy.SetModeContainsAll
	if _, err := profile.Apply(ctx, current, request, ambiguous); !errors.Is(err, ErrAmbiguousPolicy) {
		t.Fatalf("ambiguous policy error = %v", err)
	}
}

func TestProfileExposesOnlyDigestInApplicationBinding(t *testing.T) {
	t.Parallel()
	request := InteractionRequest{
		ParticipantID: "human:private-person", EventID: "event:question:privacy",
		InteractionID: "interaction:privacy", TaskID: "task:privacy", AssignmentID: "assignment:privacy",
		Kind: taskcoord.InteractionQuestion, ContentRef: "urn:encrypted-content:private",
		ContentDigest: repeatedDigest('a'),
	}
	digest, err := InteractionDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	material := AuthorizationDetail(digest) + string(RequestContext(digest))
	for _, forbidden := range []string{request.ParticipantID, request.ContentRef, "mailto:", "tel:"} {
		if strings.Contains(material, forbidden) {
			t.Fatalf("application binding leaked %q", forbidden)
		}
	}
}

func testEvidence(
	t *testing.T,
	now time.Time,
	authorizedDigest Digest,
	contextDigest Digest,
	authorizationID string,
	proofID string,
	nonce string,
	replay identitypolicy.ReplayCache,
) Evidence {
	t.Helper()
	managerSecret := []byte("manager-secret-for-human-binding-tests")
	actorSecret := []byte("actor-secret-for-human-binding-tests")
	grant := signTestJWT(t, "manager-key", managerSecret, jwt.MapClaims{
		"iss":                   "human-operation-authority",
		"sub":                   testActorID,
		"aud":                   testAudience,
		"jti":                   authorizationID,
		"iat":                   now.Add(-2 * time.Minute).Unix(),
		"exp":                   now.Add(5 * time.Minute).Unix(),
		"profile_type":          clients.TokenTypeIdentityGrant,
		"profile_version":       clients.ProfileVersion,
		"cnf":                   map[string]any{"kid": "actor-key"},
		"authorization_details": []string{AuthorizationDetail(authorizedDigest)},
	})
	binding := identitypolicy.Binding{
		LeafPublicKeySHA256:  repeatedDigest('1'),
		TLSExporterSHA256:    repeatedDigest('2'),
		RequestContextSHA256: RequestContextSHA256(contextDigest),
		Nonce:                nonce,
	}
	statement := signTestJWT(t, "actor-key", actorSecret, jwt.MapClaims{
		"iss":                    "human-gateway",
		"aud":                    testAudience,
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
		GrantJWT:          grant,
		SessionBindingJWT: statement,
		Options: clients.SessionIdentityJWTOptions{
			Grant: clients.JWTVerifyOptions{
				ExpectedIssuer: "human-operation-authority", ExpectedAudience: testAudience,
				ValidMethods: []string{"HS256"}, LocalKeys: []clients.LocalKey{{KeyID: "manager-key", Key: managerSecret}},
			},
			SessionBinding: clients.JWTVerifyOptions{
				ExpectedIssuer: "human-gateway", ExpectedAudience: testAudience,
				ValidMethods: []string{"HS256"}, LocalKeys: []clients.LocalKey{{KeyID: "actor-key", Key: actorSecret}},
			},
			ExpectedBinding: binding,
			ReplayCache:     replay,
		},
	}
}

func signTestJWT(t *testing.T, keyID string, secret []byte, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = keyID
	signed, err := token.SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func testParticipant(id string, kind taskcoord.ParticipantKind, mayDelegate bool, registeredAt time.Time) taskcoord.Participant {
	return taskcoord.Participant{
		Schema: taskcoord.ParticipantSchemaV1, ParticipantID: id, Kind: kind,
		IdentityRef: "urn:identity:opaque:" + id, Status: taskcoord.ParticipantActive,
		MayDelegate: mayDelegate, RegisteredAt: registeredAt,
	}
}

func registerParticipants(t *testing.T, ctx context.Context, store *taskcoord.MemoryStore, participants ...taskcoord.Participant) {
	t.Helper()
	for _, participant := range participants {
		if err := store.RegisterParticipant(ctx, participant); err != nil {
			t.Fatal(err)
		}
	}
}

func offeredHumanAssignment(t *testing.T, human taskcoord.Participant, at time.Time) taskcoord.Assignment {
	t.Helper()
	definition := taskcoord.AssignmentDefinition{
		EventID: "event:initial-offer", AssignmentID: "assignment:human:1", TaskID: "task:human:1",
		ParticipantID: human.ParticipantID, Role: taskcoord.RoleAssignee,
		AuthorityDigest: repeatedDigest('a'), OfferedAt: at,
	}
	auth := taskcoord.AuthenticatedOperation{
		ActorID: "service:orchestrator", ParticipantID: "agent:owner",
		AuthorizationID: "authorization:initial-offer", ProofID: "proof:initial-offer",
		Operation: taskcoord.OperationOffer, TaskID: definition.TaskID, AssignmentID: definition.AssignmentID,
		TargetParticipantID: human.ParticipantID, VerifierNonce: "nonce:initial-offer",
		IssuedAt: at.Add(-time.Minute), ExpiresAt: at.Add(time.Minute),
	}
	transition, err := taskcoord.Offer(definition, human, auth)
	if err != nil {
		t.Fatal(err)
	}
	return transition.Assignment
}

func acceptedHumanAssignment(t *testing.T, human taskcoord.Participant, at time.Time) taskcoord.Assignment {
	t.Helper()
	offered := offeredHumanAssignment(t, human, at)
	acceptAt := at.Add(time.Minute)
	transition, err := taskcoord.Apply(offered, taskcoord.Event{
		ID: "event:initial-accept", Kind: taskcoord.OperationAccept,
		ExpectedRevision: offered.Revision, At: acceptAt,
		Auth: taskcoord.AuthenticatedOperation{
			ActorID: testActorID, ParticipantID: human.ParticipantID,
			AuthorizationID: "authorization:initial-accept", ProofID: "proof:initial-accept",
			Operation: taskcoord.OperationAccept, TaskID: offered.TaskID, AssignmentID: offered.AssignmentID,
			VerifierNonce: "nonce:initial-accept", IssuedAt: acceptAt.Add(-time.Minute),
			ExpiresAt: acceptAt.Add(time.Minute),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return transition.Assignment
}
