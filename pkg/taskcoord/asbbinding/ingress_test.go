// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
	"github.com/golang-jwt/jwt/v5"
)

const (
	ingressManagerKeyID = "manager-key"
	ingressActorKeyID   = "actor-key"
)

var (
	ingressManagerSecret = []byte("manager-secret-for-live-ingress-test")
	ingressActorSecret   = []byte("actor-secret-for-live-ingress-test")
)

const (
	testMissingOracleAssignment      = "assignment:oracle:missing"
	testMissingOracleTask            = "task:oracle:missing"
	testUnauthorizedOperationMessage = "operation is not authorized"
)

func TestHumanTaskCoordIngressDemo(t *testing.T) {
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	server, client, store := newLiveIngress(t, now)

	request := TransitionRequest{
		ParticipantID: "human:alice", EventID: "event:accept:live", TaskID: "task:human:1",
		AssignmentID: "assignment:human:1", Operation: taskcoord.OperationAccept,
		ExpectedRevision: 1, Detail: "accept through the TLS ingress",
	}
	challenge := requestChallenge(t, client, server.URL, OperationAssignmentTransition, request, http.StatusCreated)
	digest, err := TransitionDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	if challenge.RequestDigest != digest.String() || challenge.Nonce == "" ||
		challenge.binding.LeafPublicKeySHA256 == "" || challenge.binding.TLSExporterSHA256 == "" ||
		challenge.binding.RequestContextSHA256 != RequestContextSHA256(digest) {
		t.Fatalf("client did not derive the expected TLS binding: %+v", challenge)
	}
	t.Logf("bound: request_digest=%s tls_exporter_sha256=%s", challenge.RequestDigest, challenge.binding.TLSExporterSHA256)
	grant, proof := signedIngressEvidence(t, now, digest, challenge)
	response := executeOperation(t, client, server.URL, ExecuteRequest{
		ChallengeID: challenge.ChallengeID, Operation: OperationAssignmentTransition,
		Request: mustJSON(t, request), GrantJWT: grant, SessionBindingJWT: proof,
	}, http.StatusOK)
	if response.Assignment == nil || response.Record == nil ||
		response.Assignment.Status != taskcoord.AssignmentAccepted {
		t.Fatalf("execute response = %+v", response)
	}
	requireGatewayAssurance(t, response.Record.Assurance)
	requireGatewayAssurance(t, response.Assignment.LastTransition.Assurance)
	stored, err := store.LoadAssignment(context.Background(), request.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != taskcoord.AssignmentAccepted || stored.Revision != 2 ||
		stored.LastTransition.ActorID != testActorID ||
		stored.LastTransition.ParticipantID != request.ParticipantID {
		t.Fatalf("stored Assignment = %+v", stored)
	}
	requireGatewayAssurance(t, stored.LastTransition.Assurance)
	t.Logf("accepted: participant=%s actor=%s status=%s revision=%d",
		stored.LastTransition.ParticipantID, stored.LastTransition.ActorID, stored.Status, stored.Revision)

	interactionRequest := InteractionRequest{
		ParticipantID: "human:alice", EventID: "event:question:live",
		InteractionID: "interaction:live", TaskID: stored.TaskID, AssignmentID: stored.AssignmentID,
		Kind: taskcoord.InteractionQuestion, ContentRef: "urn:encrypted-content:question:live",
		ContentDigest: repeatedDigest('c'),
	}
	interactionChallenge := requestChallenge(
		t, client, server.URL, OperationInteractionAppend, interactionRequest, http.StatusCreated,
	)
	interactionDigest, err := InteractionDigest(interactionRequest)
	if err != nil {
		t.Fatal(err)
	}
	interactionGrant, interactionProof := signedIngressEvidence(t, now, interactionDigest, interactionChallenge)
	interactionResponse := executeOperation(t, client, server.URL, ExecuteRequest{
		ChallengeID: interactionChallenge.ChallengeID, Operation: OperationInteractionAppend,
		Request: mustJSON(t, interactionRequest), GrantJWT: interactionGrant,
		SessionBindingJWT: interactionProof,
	}, http.StatusOK)
	if interactionResponse.Interaction == nil ||
		interactionResponse.Interaction.EventID != interactionRequest.EventID {
		t.Fatalf("interaction response = %+v", interactionResponse)
	}
	requireGatewayAssurance(t, interactionResponse.Interaction.Assurance)
	storedInteraction, err := store.LoadInteractionEvent(context.Background(), interactionRequest.EventID)
	if err != nil {
		t.Fatal(err)
	}
	requireGatewayAssurance(t, storedInteraction.Assurance)
	t.Logf("appended: interaction=%s kind=%s content_digest=%s",
		storedInteraction.InteractionID, storedInteraction.Kind, storedInteraction.ContentDigest)
}

func TestIngressReleasesConnectionCountersOnConsumeAndExpiry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	digest := Digest{1}

	consumed := &Ingress{MaxPending: 1, MaxTotalPending: 1}
	for index := 0; index < 512; index++ {
		id := fmt.Sprintf("challenge:consume:%d", index)
		connection := fmt.Sprintf("connection:consume:%d", index)
		entry := pendingChallenge{
			connectionKey: connection, requestKind: RequestKindAssignmentTransition,
			digest: digest, expiresAt: now.Add(time.Minute),
			expectedBinding: identitypolicy.Binding{LeafPublicKeySHA256: fmt.Sprintf("leaf:consume:%d", index)},
		}
		if err := consumed.putChallenge(id, entry, now); err != nil {
			t.Fatal(err)
		}
		if _, err := consumed.takeChallenge(id, connection, entry.requestKind, digest, now); err != nil {
			t.Fatal(err)
		}
	}
	if len(consumed.pending) != 0 || len(consumed.connections) != 0 || len(consumed.identities) != 0 {
		t.Fatalf("consumed challenge state retained: pending=%d connections=%d identities=%d",
			len(consumed.pending), len(consumed.connections), len(consumed.identities))
	}

	expired := &Ingress{MaxPending: 1, MaxTotalPending: 512}
	for index := 0; index < 512; index++ {
		id := fmt.Sprintf("challenge:expire:%d", index)
		connection := fmt.Sprintf("connection:expire:%d", index)
		entry := pendingChallenge{
			connectionKey: connection, requestKind: RequestKindInteractionAppend,
			digest: digest, expiresAt: now.Add(time.Second),
			expectedBinding: identitypolicy.Binding{LeafPublicKeySHA256: fmt.Sprintf("leaf:expire:%d", index)},
		}
		if err := expired.putChallenge(id, entry, now); err != nil {
			t.Fatal(err)
		}
	}
	expired.mu.Lock()
	expired.pruneLocked(now.Add(2 * time.Second))
	expired.mu.Unlock()
	if len(expired.pending) != 0 || len(expired.connections) != 0 || len(expired.identities) != 0 {
		t.Fatalf("expired challenge state retained: pending=%d connections=%d identities=%d",
			len(expired.pending), len(expired.connections), len(expired.identities))
	}
}

func TestIngressRejectsChallengeIDCollisionWithoutClobberingState(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	digest := Digest{1}
	first := pendingChallenge{
		connectionKey: "connection:first", requestKind: RequestKindAssignmentTransition,
		digest: digest, expiresAt: now.Add(time.Minute),
		expectedBinding: identitypolicy.Binding{LeafPublicKeySHA256: "leaf:first"},
	}
	second := pendingChallenge{
		connectionKey: "connection:second", requestKind: RequestKindInteractionAppend,
		digest: Digest{2}, expiresAt: now.Add(2 * time.Minute),
		expectedBinding: identitypolicy.Binding{LeafPublicKeySHA256: "leaf:second"},
	}
	ingress := &Ingress{MaxPending: 4, MaxTotalPending: 4}
	if err := ingress.putChallenge("challenge:collision", first, now); err != nil {
		t.Fatal(err)
	}
	if err := ingress.putChallenge("challenge:collision", second, now); !errors.Is(err, errChallengeCollision) {
		t.Fatalf("collision error = %v, want %v", err, errChallengeCollision)
	}
	if len(ingress.pending) != 1 || ingress.pending["challenge:collision"] != first ||
		ingress.connections[first.connectionKey] != 1 || ingress.identities["leaf:first"] != 1 ||
		ingress.connections[second.connectionKey] != 0 || ingress.identities["leaf:second"] != 0 {
		t.Fatalf("collision changed pending state: pending=%+v connections=%+v identities=%+v",
			ingress.pending, ingress.connections, ingress.identities)
	}
	if _, err := ingress.takeChallenge(
		"challenge:collision", first.connectionKey, first.requestKind, first.digest, now,
	); err != nil {
		t.Fatalf("original challenge was not consumable: %v", err)
	}
	if len(ingress.pending) != 0 || len(ingress.connections) != 0 || len(ingress.identities) != 0 {
		t.Fatalf("original challenge counters leaked after consume: pending=%+v connections=%+v identities=%+v",
			ingress.pending, ingress.connections, ingress.identities)
	}
}

func TestIngressRegeneratesCollidingChallengeIDsAndFailsClosed(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	request := TransitionRequest{
		ParticipantID: "human:alice", EventID: "event:accept:collision", TaskID: "task:human:1",
		AssignmentID: "assignment:human:1", Operation: taskcoord.OperationAccept, ExpectedRevision: 1,
	}
	scriptedRandom := func(values ...byte) io.Reader {
		var raw []byte
		for _, value := range values {
			raw = append(raw, bytes.Repeat([]byte{value}, challengeBytes)...)
		}
		return bytes.NewReader(raw)
	}

	t.Run("one collision then a unique identifier", func(t *testing.T) {
		server, client := newLiveIngressWithStore(t, now, seededIngressStore(t, now), func(ingress *Ingress) {
			ingress.Random = scriptedRandom('a', 'b', 'a', 'c', 'd', 'e')
		})
		first := requestChallenge(t, client, server.URL, OperationAssignmentTransition, request, http.StatusCreated)
		second := requestChallenge(t, client, server.URL, OperationAssignmentTransition, request, http.StatusCreated)
		if first.ChallengeID == second.ChallengeID || second.ChallengeID != hex.EncodeToString(bytes.Repeat([]byte{'d'}, challengeBytes)) {
			t.Fatalf("challenge IDs = %q/%q, want collision regeneration", first.ChallengeID, second.ChallengeID)
		}
	})

	t.Run("repeated collisions preserve the original challenge", func(t *testing.T) {
		server, client := newLiveIngressWithStore(t, now, seededIngressStore(t, now), func(ingress *Ingress) {
			ingress.Random = scriptedRandom('a', 'b', 'a', 'c', 'a', 'd', 'a', 'e')
		})
		first := requestChallenge(t, client, server.URL, OperationAssignmentTransition, request, http.StatusCreated)
		requestChallenge(t, client, server.URL, OperationAssignmentTransition, request, http.StatusInternalServerError)

		digest, err := TransitionDigest(request)
		if err != nil {
			t.Fatal(err)
		}
		grant, proof := signedIngressEvidence(t, now, digest, first)
		response := executeOperation(t, client, server.URL, ExecuteRequest{
			ChallengeID: first.ChallengeID, Operation: OperationAssignmentTransition,
			Request: mustJSON(t, request), GrantJWT: grant, SessionBindingJWT: proof,
		}, http.StatusOK)
		if response.Assignment == nil || response.Assignment.Status != taskcoord.AssignmentAccepted {
			t.Fatalf("original challenge did not remain usable: %+v", response)
		}
	})
}

func TestIngressEnforcesVerifierWidePendingLimitAcrossConnections(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	digest := Digest{1}
	ingress := &Ingress{MaxPending: 2, MaxTotalPending: 3}
	entry := func(index int) pendingChallenge {
		return pendingChallenge{
			connectionKey: fmt.Sprintf("connection:global:%d", index),
			requestKind:   RequestKindAssignmentTransition,
			digest:        digest,
			expiresAt:     now.Add(time.Minute),
			expectedBinding: identitypolicy.Binding{
				LeafPublicKeySHA256: fmt.Sprintf("leaf:global:%d", index),
			},
		}
	}
	for index := 0; index < 3; index++ {
		if err := ingress.putChallenge(fmt.Sprintf("challenge:global:%d", index), entry(index), now); err != nil {
			t.Fatal(err)
		}
	}
	if err := ingress.putChallenge("challenge:global:3", entry(3), now); !errors.Is(err, ErrChallengeLimit) {
		t.Fatalf("fourth connection error = %v, want %v", err, ErrChallengeLimit)
	}
	if _, err := ingress.takeChallenge("challenge:global:0", "connection:global:0", RequestKindAssignmentTransition, digest, now); err != nil {
		t.Fatal(err)
	}
	if err := ingress.putChallenge("challenge:global:3", entry(3), now); err != nil {
		t.Fatalf("replacement after consume: %v", err)
	}
}

func TestIngressEnforcesVerifierWidePendingLimitConcurrently(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	digest := Digest{1}
	const (
		attempts = 64
		limit    = 7
	)
	ingress := &Ingress{MaxPending: 1, MaxTotalPending: limit}
	start := make(chan struct{})
	results := make(chan error, attempts)
	for index := 0; index < attempts; index++ {
		go func(index int) {
			<-start
			results <- ingress.putChallenge(
				fmt.Sprintf("challenge:concurrent:%d", index),
				pendingChallenge{
					connectionKey: fmt.Sprintf("connection:concurrent:%d", index),
					requestKind:   RequestKindAssignmentTransition,
					digest:        digest,
					expiresAt:     now.Add(time.Minute),
					expectedBinding: identitypolicy.Binding{
						LeafPublicKeySHA256: fmt.Sprintf("leaf:concurrent:%d", index),
					},
				},
				now,
			)
		}(index)
	}
	close(start)
	accepted := 0
	for index := 0; index < attempts; index++ {
		err := <-results
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, ErrChallengeLimit):
		default:
			t.Fatalf("putChallenge error = %v", err)
		}
	}
	if accepted != limit || len(ingress.pending) != limit {
		t.Fatalf("accepted=%d pending=%d, want %d", accepted, len(ingress.pending), limit)
	}
}

func TestIngressEnforcesVerifiedLeafPendingLimitAcrossConnections(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	digest := Digest{1}
	ingress := &Ingress{MaxPending: 2, MaxTotalPending: 8}
	entry := func(index int) pendingChallenge {
		return pendingChallenge{
			connectionKey: fmt.Sprintf("connection:leaf:%d", index),
			requestKind:   RequestKindInteractionAppend,
			digest:        digest,
			expiresAt:     now.Add(time.Minute),
			expectedBinding: identitypolicy.Binding{
				LeafPublicKeySHA256: "shared-verified-leaf-key",
			},
		}
	}
	for index := 0; index < 2; index++ {
		if err := ingress.putChallenge(fmt.Sprintf("challenge:leaf:%d", index), entry(index), now); err != nil {
			t.Fatal(err)
		}
	}
	if err := ingress.putChallenge("challenge:leaf:2", entry(2), now); !errors.Is(err, ErrChallengeLimit) {
		t.Fatalf("third connection for one leaf error = %v, want %v", err, ErrChallengeLimit)
	}
}

func TestIngressRejectsNegativeChallengeLimits(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name            string
		maxPending      int
		maxTotalPending int
	}{
		{name: "per-scope", maxPending: -1},
		{name: "verifier-wide", maxTotalPending: -1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ingress := newTestIngress(now, taskcoord.NewMemoryStore(), identitypolicy.NewMemoryReplayCache())
			ingress.MaxPending = test.maxPending
			ingress.MaxTotalPending = test.maxTotalPending
			if _, err := ingress.Handler(); !errors.Is(err, ErrInvalidChallengeLimits) {
				t.Fatalf("Handler error = %v, want %v", err, ErrInvalidChallengeLimits)
			}
		})
	}
}

func TestIngressOffersHumanAuthoredAssignment(t *testing.T) {
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	ctx := context.Background()
	store := taskcoord.NewMemoryStore()
	human := testParticipant("human:alice", taskcoord.ParticipantHuman, false, now.Add(-time.Hour))
	target := testParticipant("agent:reviewer", taskcoord.ParticipantAgent, false, now.Add(-time.Hour))
	registerParticipants(t, ctx, store, human, target)
	server, client := newLiveIngressWithStore(t, now, store, nil)

	request := OfferRequest{
		ParticipantID: human.ParticipantID, EventID: "event:offer:live", TaskID: "task:offered:live",
		AssignmentID: "assignment:offered:live", TargetParticipantID: target.ParticipantID,
		Role: taskcoord.RoleReviewer, AuthorityDigest: repeatedDigest('d'),
	}
	challenge := requestChallenge(t, client, server.URL, OperationAssignmentOffer, request, http.StatusCreated)
	digest, err := OfferDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	grant, proof := signedIngressEvidence(t, now, digest, challenge)
	response := executeOperation(t, client, server.URL, ExecuteRequest{
		ChallengeID: challenge.ChallengeID, Operation: OperationAssignmentOffer,
		Request: mustJSON(t, request), GrantJWT: grant, SessionBindingJWT: proof,
	}, http.StatusOK)
	if response.Assignment == nil || response.Record == nil ||
		response.Assignment.Status != taskcoord.AssignmentOffered {
		t.Fatalf("offer response = %+v", response)
	}
	requireGatewayAssurance(t, response.Record.Assurance)
	requireGatewayAssurance(t, response.Assignment.LastTransition.Assurance)
	stored, err := store.LoadAssignment(ctx, request.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Revision != 1 || stored.ParticipantID != target.ParticipantID ||
		stored.OfferedByParticipantID != human.ParticipantID ||
		stored.LastTransition.ActorID != testActorID {
		t.Fatalf("stored offer = %+v", stored)
	}
	requireGatewayAssurance(t, stored.LastTransition.Assurance)
}

func TestIngressDelegatesAfterASBAndPolicyVerification(t *testing.T) {
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	store, parent, target := seededDelegationIngressStore(t, now)
	var verifierCalls atomic.Int32
	server, client := newLiveIngressWithStore(t, now, store, func(ingress *Ingress) {
		ingress.Policy.DelegationVerifier = DelegationDecisionVerifierFunc(func(
			_ context.Context,
			gotParent taskcoord.Assignment,
			request DelegationRequest,
			at time.Time,
		) (taskcoord.VerifiedDelegation, error) {
			verifierCalls.Add(1)
			if gotParent.AssignmentID != parent.AssignmentID {
				return taskcoord.VerifiedDelegation{}, taskcoord.ErrInvalidDelegation
			}
			return verifiedDelegationFor(gotParent, request, at), nil
		})
	})

	request := liveDelegationRequest(parent, target.ParticipantID)
	challenge := requestChallenge(t, client, server.URL, OperationAssignmentDelegation, request, http.StatusCreated)
	digest, err := DelegationDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	grant, proof := signedIngressEvidence(t, now, digest, challenge)
	response := executeOperation(t, client, server.URL, ExecuteRequest{
		ChallengeID: challenge.ChallengeID, Operation: OperationAssignmentDelegation,
		Request: mustJSON(t, request), GrantJWT: grant, SessionBindingJWT: proof,
	}, http.StatusOK)
	if verifierCalls.Load() != 1 {
		t.Fatalf("delegation verifier calls = %d, want 1", verifierCalls.Load())
	}
	if response.ParentAssignment == nil || response.ParentRecord == nil ||
		response.ChildAssignment == nil || response.ChildRecord == nil || response.Delegation == nil ||
		response.ParentAssignment.Status != taskcoord.AssignmentAccepted ||
		response.ChildAssignment.Status != taskcoord.AssignmentOffered {
		t.Fatalf("delegation response = %+v", response)
	}
	requireGatewayAssurance(t, response.ParentRecord.Assurance)
	requireGatewayAssurance(t, response.ChildRecord.Assurance)
	requireGatewayAssurance(t, response.Delegation.Assurance)
	storedParent, err := store.LoadAssignment(context.Background(), parent.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	storedChild, err := store.LoadAssignment(context.Background(), request.ChildAssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	storedDelegation, err := store.LoadDelegation(context.Background(), request.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if storedParent.Status != taskcoord.AssignmentAccepted || storedParent.Revision != parent.Revision+1 ||
		storedChild.ParentAssignmentID != parent.AssignmentID ||
		storedDelegation.ChildAssignmentID != request.ChildAssignmentID {
		t.Fatalf("stored delegation = parent=%+v child=%+v edge=%+v", storedParent, storedChild, storedDelegation)
	}
	requireGatewayAssurance(t, storedParent.LastTransition.Assurance)
	requireGatewayAssurance(t, storedChild.LastTransition.Assurance)
	requireGatewayAssurance(t, storedDelegation.Assurance)
}

func TestIngressVerifiesASBBeforeDelegationDecisionLookup(t *testing.T) {
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	store, parent, target := seededDelegationIngressStore(t, now)
	var verifierCalls atomic.Int32
	server, client := newLiveIngressWithStore(t, now, store, func(ingress *Ingress) {
		ingress.Policy.DelegationVerifier = DelegationDecisionVerifierFunc(func(
			_ context.Context,
			parent taskcoord.Assignment,
			request DelegationRequest,
			at time.Time,
		) (taskcoord.VerifiedDelegation, error) {
			verifierCalls.Add(1)
			return verifiedDelegationFor(parent, request, at), nil
		})
	})
	request := liveDelegationRequest(parent, target.ParticipantID)
	challenge := requestChallenge(t, client, server.URL, OperationAssignmentDelegation, request, http.StatusCreated)
	digest, err := DelegationDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	grant, proof := signedIngressEvidence(t, now, digest, challenge)
	executeOperation(t, client, server.URL, ExecuteRequest{
		ChallengeID: challenge.ChallengeID, Operation: OperationAssignmentDelegation,
		Request: mustJSON(t, request), GrantJWT: grant + "corrupt", SessionBindingJWT: proof,
	}, http.StatusForbidden)
	if verifierCalls.Load() != 0 {
		t.Fatalf("delegation verifier ran before ASB acceptance: %d calls", verifierCalls.Load())
	}
	storedParent, err := store.LoadAssignment(context.Background(), parent.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	if storedParent.Revision != parent.Revision {
		t.Fatalf("rejected request changed parent: %+v", storedParent)
	}
}

func TestIngressRejectsUntrustedDelegationProjection(t *testing.T) {
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	store, parent, target := seededDelegationIngressStore(t, now)
	server, client := newLiveIngressWithStore(t, now, store, func(ingress *Ingress) {
		ingress.Policy.DelegationVerifier = DelegationDecisionVerifierFunc(func(
			_ context.Context,
			parent taskcoord.Assignment,
			request DelegationRequest,
			at time.Time,
		) (taskcoord.VerifiedDelegation, error) {
			return verifiedDelegationFor(parent, request, at), nil
		})
	})
	request := liveDelegationRequest(parent, target.ParticipantID)
	raw := map[string]any{
		"participant_id": request.ParticipantID, "event_id": request.EventID,
		"parent_task_id": request.ParentTaskID, "parent_assignment_id": request.ParentAssignmentID,
		"expected_revision": request.ExpectedRevision, "decision_id": request.DecisionID,
		"child_event_id": request.ChildEventID, "child_task_id": request.ChildTaskID,
		"child_assignment_id": request.ChildAssignmentID, "target_participant_id": request.TargetParticipantID,
		"role": request.Role, "authority_digest": request.AuthorityDigest,
		"verified_delegation": map[string]any{"policy_ref": "client:asserted"},
	}
	body := mustJSON(t, ChallengeRequest{Operation: OperationAssignmentDelegation, Request: mustJSON(t, raw)})
	response, err := client.Post(server.URL+IngressChallengePath, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("client policy projection status = %d, body = %s", response.StatusCode, payload)
	}
}

func TestIngressRequiresDelegationDecisionVerifier(t *testing.T) {
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	store, parent, target := seededDelegationIngressStore(t, now)
	server, client := newLiveIngressWithStore(t, now, store, nil)
	requestChallenge(
		t, client, server.URL, OperationAssignmentDelegation,
		liveDelegationRequest(parent, target.ParticipantID), http.StatusForbidden,
	)
}

func TestIngressRejectsTypedNilDelegationDecisionVerifier(t *testing.T) {
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	store, parent, target := seededDelegationIngressStore(t, now)
	server, client := newLiveIngressWithStore(t, now, store, func(ingress *Ingress) {
		var verifier *panicDelegationVerifier
		ingress.Policy.DelegationVerifier = verifier
	})
	requestChallenge(
		t, client, server.URL, OperationAssignmentDelegation,
		liveDelegationRequest(parent, target.ParticipantID), http.StatusForbidden,
	)
}

func TestIngressRejectsMismatchedDelegationDecisionWithoutWrites(t *testing.T) {
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	store, parent, target := seededDelegationIngressStore(t, now)
	server, client := newLiveIngressWithStore(t, now, store, func(ingress *Ingress) {
		ingress.Policy.DelegationVerifier = DelegationDecisionVerifierFunc(func(
			_ context.Context,
			parent taskcoord.Assignment,
			request DelegationRequest,
			at time.Time,
		) (taskcoord.VerifiedDelegation, error) {
			decision := verifiedDelegationFor(parent, request, at)
			decision.ToParticipantID = "agent:other"
			return decision, nil
		})
	})
	request := liveDelegationRequest(parent, target.ParticipantID)
	challenge := requestChallenge(t, client, server.URL, OperationAssignmentDelegation, request, http.StatusCreated)
	digest, err := DelegationDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	grant, proof := signedIngressEvidence(t, now, digest, challenge)
	executeOperation(t, client, server.URL, ExecuteRequest{
		ChallengeID: challenge.ChallengeID, Operation: OperationAssignmentDelegation,
		Request: mustJSON(t, request), GrantJWT: grant, SessionBindingJWT: proof,
	}, http.StatusForbidden)
	storedParent, err := store.LoadAssignment(context.Background(), parent.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	if storedParent.Revision != parent.Revision {
		t.Fatalf("mismatched decision changed parent: %+v", storedParent)
	}
	if _, err := store.LoadAssignment(context.Background(), request.ChildAssignmentID); err == nil {
		t.Fatal("mismatched decision created child Assignment")
	}
	if _, err := store.LoadDelegation(context.Background(), request.EventID); err == nil {
		t.Fatal("mismatched decision created delegation record")
	}
}

func TestIngressRejectsChallengeOnAnotherTLSConnection(t *testing.T) {
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	server, firstClient, _ := newLiveIngress(t, now)
	secondClient := cloneHTTPClient(t, firstClient)
	request := TransitionRequest{
		ParticipantID: "human:alice", EventID: "event:accept:cross-connection", TaskID: "task:human:1",
		AssignmentID: "assignment:human:1", Operation: taskcoord.OperationAccept, ExpectedRevision: 1,
	}
	challenge := requestChallenge(t, firstClient, server.URL, OperationAssignmentTransition, request, http.StatusCreated)
	digest, err := TransitionDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	grant, proof := signedIngressEvidence(t, now, digest, challenge)
	executeOperation(t, secondClient, server.URL, ExecuteRequest{
		ChallengeID: challenge.ChallengeID, Operation: OperationAssignmentTransition,
		Request: mustJSON(t, request), GrantJWT: grant, SessionBindingJWT: proof,
	}, http.StatusUnauthorized)
}

func TestIngressRejectsRequestMutationAndStaleRevision(t *testing.T) {
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	server, client, store := newLiveIngress(t, now)
	request := TransitionRequest{
		ParticipantID: "human:alice", EventID: "event:accept:mutation", TaskID: "task:human:1",
		AssignmentID: "assignment:human:1", Operation: taskcoord.OperationAccept,
		ExpectedRevision: 1, Detail: "original",
	}
	challenge := requestChallenge(t, client, server.URL, OperationAssignmentTransition, request, http.StatusCreated)
	digest, err := TransitionDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	grant, proof := signedIngressEvidence(t, now, digest, challenge)
	mutated := request
	mutated.Detail = "changed"
	executeOperation(t, client, server.URL, ExecuteRequest{
		ChallengeID: challenge.ChallengeID, Operation: OperationAssignmentTransition,
		Request: mustJSON(t, mutated), GrantJWT: grant, SessionBindingJWT: proof,
	}, http.StatusUnauthorized)

	fresh := request
	fresh.EventID = "event:accept:fresh"
	fresh.Detail = ""
	freshChallenge := requestChallenge(t, client, server.URL, OperationAssignmentTransition, fresh, http.StatusCreated)
	freshDigest, err := TransitionDigest(fresh)
	if err != nil {
		t.Fatal(err)
	}
	freshGrant, freshProof := signedIngressEvidence(t, now, freshDigest, freshChallenge)
	executeOperation(t, client, server.URL, ExecuteRequest{
		ChallengeID: freshChallenge.ChallengeID, Operation: OperationAssignmentTransition,
		Request: mustJSON(t, fresh), GrantJWT: freshGrant, SessionBindingJWT: freshProof,
	}, http.StatusOK)

	stale := fresh
	stale.EventID = "event:accept:stale"
	stale.Operation = taskcoord.OperationDecline
	staleChallenge := requestChallenge(t, client, server.URL, OperationAssignmentTransition, stale, http.StatusCreated)
	staleDigest, err := TransitionDigest(stale)
	if err != nil {
		t.Fatal(err)
	}
	staleGrant, staleProof := signedIngressEvidence(t, now, staleDigest, staleChallenge)
	executeOperation(t, client, server.URL, ExecuteRequest{
		ChallengeID: staleChallenge.ChallengeID, Operation: OperationAssignmentTransition,
		Request: mustJSON(t, stale), GrantJWT: staleGrant, SessionBindingJWT: staleProof,
	}, http.StatusConflict)

	stored, err := store.LoadAssignment(context.Background(), request.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != taskcoord.AssignmentAccepted || stored.Revision != 2 {
		t.Fatalf("stale request changed Assignment: %+v", stored)
	}
}

func TestIngressAuthenticatesBeforeAssignmentLookup(t *testing.T) {
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	baseStore := seededIngressStore(t, now)
	current, err := baseStore.LoadAssignment(context.Background(), "assignment:human:1")
	if err != nil {
		t.Fatal(err)
	}
	store := &assignmentLookupCountingStore{Store: baseStore}
	server, client := newLiveIngressWithStore(t, now, store, func(ingress *Ingress) {
		ingress.Policy.DelegationVerifier = DelegationDecisionVerifierFunc(func(
			_ context.Context,
			parent taskcoord.Assignment,
			request DelegationRequest,
			at time.Time,
		) (taskcoord.VerifiedDelegation, error) {
			return verifiedDelegationFor(parent, request, at), nil
		})
	})

	transition := TransitionRequest{
		ParticipantID: current.ParticipantID, EventID: "event:oracle:transition",
		TaskID: current.TaskID, AssignmentID: current.AssignmentID,
		Operation: taskcoord.OperationAccept, ExpectedRevision: current.Revision,
	}
	interaction := InteractionRequest{
		ParticipantID: current.ParticipantID, EventID: "event:oracle:interaction",
		InteractionID: "interaction:oracle", TaskID: current.TaskID,
		AssignmentID: current.AssignmentID, Kind: taskcoord.InteractionQuestion,
		ContentRef: "urn:encrypted-content:oracle", ContentDigest: repeatedDigest('f'),
	}
	delegation := liveDelegationRequest(current, "agent:oracle-target")
	delegation.EventID = "event:oracle:delegation"
	delegation.ChildEventID = "event:oracle:child"
	delegation.ChildTaskID = "task:oracle:child"
	delegation.ChildAssignmentID = "assignment:oracle:child"

	tests := []struct {
		name      string
		operation string
		request   any
	}{
		{name: "transition existing", operation: OperationAssignmentTransition, request: transition},
		{name: "transition missing", operation: OperationAssignmentTransition, request: func() TransitionRequest {
			request := transition
			request.EventID = "event:oracle:transition:missing"
			request.AssignmentID = testMissingOracleAssignment
			request.TaskID = testMissingOracleTask
			return request
		}()},
		{name: "transition stale", operation: OperationAssignmentTransition, request: func() TransitionRequest {
			request := transition
			request.EventID = "event:oracle:transition:stale"
			request.ExpectedRevision++
			return request
		}()},
		{name: "interaction existing", operation: OperationInteractionAppend, request: interaction},
		{name: "interaction missing", operation: OperationInteractionAppend, request: func() InteractionRequest {
			request := interaction
			request.EventID = "event:oracle:interaction:missing"
			request.InteractionID = "interaction:oracle:missing"
			request.AssignmentID = testMissingOracleAssignment
			request.TaskID = testMissingOracleTask
			return request
		}()},
		{name: "interaction wrong task", operation: OperationInteractionAppend, request: func() InteractionRequest {
			request := interaction
			request.EventID = "event:oracle:interaction:wrong-task"
			request.InteractionID = "interaction:oracle:wrong-task"
			request.TaskID = "task:oracle:wrong"
			return request
		}()},
		{name: "delegation existing", operation: OperationAssignmentDelegation, request: delegation},
		{name: "delegation missing", operation: OperationAssignmentDelegation, request: func() DelegationRequest {
			request := delegation
			request.EventID = "event:oracle:delegation:missing"
			request.ParentAssignmentID = testMissingOracleAssignment
			request.ParentTaskID = testMissingOracleTask
			return request
		}()},
		{name: "delegation stale", operation: OperationAssignmentDelegation, request: func() DelegationRequest {
			request := delegation
			request.EventID = "event:oracle:delegation:stale"
			request.ExpectedRevision++
			return request
		}()},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			challenge := requestChallenge(t, client, server.URL, test.operation, test.request, http.StatusCreated)
			operation, err := decodeOperation(test.operation, mustJSON(t, test.request))
			if err != nil {
				t.Fatal(err)
			}
			grant, proof := signedIngressEvidence(t, now, operation.digest, challenge)
			status, message := executeOperationError(t, client, server.URL, ExecuteRequest{
				ChallengeID: challenge.ChallengeID, Operation: test.operation,
				Request: mustJSON(t, test.request), GrantJWT: grant + "corrupt",
				SessionBindingJWT: proof,
			})
			if status != http.StatusForbidden || message != testUnauthorizedOperationMessage {
				t.Fatalf("authorization response = %d %q, want %d %q",
					status, message, http.StatusForbidden, testUnauthorizedOperationMessage)
			}
		})
	}
	if got := store.loads.Load(); got != 0 {
		t.Fatalf("unverified operations loaded Assignment state %d times", got)
	}

	missing := transition
	missing.EventID = "event:oracle:valid:missing"
	missing.AssignmentID = "assignment:oracle:valid:missing"
	missing.TaskID = "task:oracle:valid:missing"
	executeValidOperation(t, client, server.URL, now, OperationAssignmentTransition, missing, http.StatusNotFound)

	stale := transition
	stale.EventID = "event:oracle:valid:stale"
	stale.ExpectedRevision++
	executeValidOperation(t, client, server.URL, now, OperationAssignmentTransition, stale, http.StatusConflict)
	if got := store.loads.Load(); got != 2 {
		t.Fatalf("verified operations loaded Assignment state %d times, want 2", got)
	}
}

func TestIngressVerifiesProofBeforeAcceptedUntilAndParticipantLookup(t *testing.T) {
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	store := &participantLookupFailingStore{
		Store: seededIngressStore(t, now),
		err:   errors.New("sensitive participant storage detail"),
	}
	var policyCalls atomic.Int32
	server, client := newLiveIngressWithStore(t, now, store, func(ingress *Ingress) {
		ingress.Policy.AcceptedUntil = func(context.Context, RequestKind, Digest) (time.Time, error) {
			policyCalls.Add(1)
			return time.Time{}, errors.New("sensitive acceptance policy detail")
		}
	})
	request := TransitionRequest{
		ParticipantID: "human:alice", EventID: "event:accept:preauth-policy",
		TaskID: "task:human:1", AssignmentID: "assignment:human:1",
		Operation: taskcoord.OperationAccept, ExpectedRevision: 1,
	}
	challenge := requestChallenge(t, client, server.URL, OperationAssignmentTransition, request, http.StatusCreated)
	digest, err := TransitionDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	grant, proof := signedIngressEvidence(t, now, digest, challenge)
	status, message := executeOperationError(t, client, server.URL, ExecuteRequest{
		ChallengeID: challenge.ChallengeID, Operation: OperationAssignmentTransition,
		Request: mustJSON(t, request), GrantJWT: grant + "corrupt", SessionBindingJWT: proof,
	})
	if status != http.StatusForbidden || message != testUnauthorizedOperationMessage {
		t.Fatalf("authorization response = %d %q, want %d %q",
			status, message, http.StatusForbidden, testUnauthorizedOperationMessage)
	}
	if got := policyCalls.Load(); got != 0 {
		t.Fatalf("AcceptedUntil ran before proof verification: %d calls", got)
	}
	if got := store.loads.Load(); got != 0 {
		t.Fatalf("Participant storage ran before proof verification: %d calls", got)
	}
}

func TestIngressCollapsesAcceptedUntilErrorAfterProof(t *testing.T) {
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	baseStore := seededIngressStore(t, now)
	store := &assignmentLookupCountingStore{Store: baseStore}
	var policyCalls atomic.Int32
	server, client := newLiveIngressWithStore(t, now, store, func(ingress *Ingress) {
		ingress.Policy.AcceptedUntil = func(context.Context, RequestKind, Digest) (time.Time, error) {
			policyCalls.Add(1)
			return time.Time{}, errors.New("sensitive acceptance policy detail")
		}
	})
	request := TransitionRequest{
		ParticipantID: "human:alice", EventID: "event:accept:policy-error",
		TaskID: "task:human:1", AssignmentID: "assignment:human:1",
		Operation: taskcoord.OperationAccept, ExpectedRevision: 1,
	}
	challenge := requestChallenge(t, client, server.URL, OperationAssignmentTransition, request, http.StatusCreated)
	digest, err := TransitionDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	grant, proof := signedIngressEvidence(t, now, digest, challenge)
	status, message := executeOperationError(t, client, server.URL, ExecuteRequest{
		ChallengeID: challenge.ChallengeID, Operation: OperationAssignmentTransition,
		Request: mustJSON(t, request), GrantJWT: grant, SessionBindingJWT: proof,
	})
	if status != http.StatusForbidden || message != testUnauthorizedOperationMessage {
		t.Fatalf("policy response = %d %q, want %d %q",
			status, message, http.StatusForbidden, testUnauthorizedOperationMessage)
	}
	if got := policyCalls.Load(); got != 1 {
		t.Fatalf("AcceptedUntil calls = %d, want 1 after verified proof", got)
	}
	if got := store.loads.Load(); got != 0 {
		t.Fatalf("policy rejection loaded Assignment state %d times", got)
	}
}

func TestIngressRejectsPlainHTTPAndUnverifiedClient(t *testing.T) {
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	store := seededIngressStore(t, now)
	handler := mustIngressHandler(t, now, store, identitypolicy.NewMemoryReplayCache())
	request := TransitionRequest{
		ParticipantID: "human:alice", EventID: "event:accept:no-tls", TaskID: "task:human:1",
		AssignmentID: "assignment:human:1", Operation: taskcoord.OperationAccept, ExpectedRevision: 1,
	}
	body := mustJSON(t, ChallengeRequest{Operation: OperationAssignmentTransition, Request: mustJSON(t, request)})
	recorder := httptest.NewRecorder()
	httpRequest := httptest.NewRequest(http.MethodPost, IngressChallengePath, bytes.NewReader(body))
	handler.ServeHTTP(recorder, httpRequest)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("plaintext status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}

	server, _, _ := newLiveIngress(t, now)
	unverified := server.Client()
	response, err := unverified.Post(server.URL+IngressChallengePath, "application/json", bytes.NewReader(body))
	if err == nil {
		defer response.Body.Close()
		t.Fatalf("TLS request without client certificate unexpectedly returned status %d", response.StatusCode)
	}
}

func TestIngressStrictJSONRejectsDuplicateAndUnknownMembers(t *testing.T) {
	tests := []string{
		`{"operation":"ASSIGNMENT_TRANSITION","operation":"INTERACTION_APPEND","request":{}}`,
		`{"operation":"ASSIGNMENT_TRANSITION","request":{},"verified":true}`,
		`{"operation":"ASSIGNMENT_TRANSITION","request":{"participant_id":"human:1","participant_id":"human:2"}}`,
	}
	for _, input := range tests {
		var request ChallengeRequest
		if err := decodeIngressJSON(strings.NewReader(input), &request); err == nil {
			t.Fatalf("invalid JSON accepted: %s", input)
		}
	}
}

func TestServerTLSConfigRequiresCertificateAndClientCA(t *testing.T) {
	if _, err := ServerTLSConfig(tls.Certificate{}, x509.NewCertPool()); err == nil {
		t.Fatal("missing server certificate was accepted")
	}
	ca, _, serverCert, _ := ingressCertificates(t)
	if _, err := ServerTLSConfig(serverCert, nil); err == nil {
		t.Fatal("missing client CA was accepted")
	}
	config, err := ServerTLSConfig(serverCert, ca)
	if err != nil {
		t.Fatal(err)
	}
	if config.MinVersion != tls.VersionTLS13 || config.MaxVersion != tls.VersionTLS13 ||
		config.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("TLS config = %+v", config)
	}
	ingress := newTestIngress(time.Now(), taskcoord.NewMemoryStore(), identitypolicy.NewMemoryReplayCache())
	if _, err := ingress.NewTLSServer("", serverCert, ca); err == nil {
		t.Fatal("missing listen address was accepted")
	}
	httpServer, err := ingress.NewTLSServer("127.0.0.1:8443", serverCert, ca)
	if err != nil {
		t.Fatal(err)
	}
	if httpServer.TLSConfig == nil || httpServer.ReadHeaderTimeout == 0 || httpServer.MaxHeaderBytes == 0 {
		t.Fatalf("HTTP server safety limits were not configured: %+v", httpServer)
	}
}

func TestIngressHandlerRejectsTypedNilDependencies(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	var store *taskcoord.MemoryStore
	ingress := newTestIngress(now, store, identitypolicy.NewMemoryReplayCache())
	if _, err := ingress.Handler(); !errors.Is(err, ErrMissingStore) {
		t.Fatalf("typed-nil Store error = %v, want %v", err, ErrMissingStore)
	}

	var replay *identitypolicy.MemoryReplayCache
	ingress = newTestIngress(now, taskcoord.NewMemoryStore(), replay)
	if _, err := ingress.Handler(); !errors.Is(err, ErrMissingReplayCache) {
		t.Fatalf("typed-nil ReplayCache error = %v, want %v", err, ErrMissingReplayCache)
	}
}

func newLiveIngress(t *testing.T, now time.Time) (*httptest.Server, *http.Client, *taskcoord.MemoryStore) {
	t.Helper()
	store := seededIngressStore(t, now)
	server, client := newLiveIngressWithStore(t, now, store, nil)
	return server, client, store
}

func newLiveIngressWithStore(
	t *testing.T,
	now time.Time,
	store taskcoord.Store,
	configure func(*Ingress),
) (*httptest.Server, *http.Client) {
	t.Helper()
	replay, err := identitypolicy.NewDirectoryReplayCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ingress := newTestIngress(now, store, replay)
	if configure != nil {
		configure(ingress)
	}
	ca, serverRoots, serverCert, clientCert := ingressCertificates(t)
	configured, err := ingress.NewTLSServer("127.0.0.1:0", serverCert, ca)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(configured.Handler)
	server.TLS = configured.TLSConfig
	server.EnableHTTP2 = true
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)

	clientTLS := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: serverRoots, Certificates: []tls.Certificate{clientCert},
	}
	transport := &http.Transport{
		TLSClientConfig: clientTLS, ForceAttemptHTTP2: true, MaxConnsPerHost: 1,
	}
	client := &http.Client{Transport: transport}
	t.Cleanup(transport.CloseIdleConnections)
	return server, client
}

type assignmentLookupCountingStore struct {
	taskcoord.Store
	loads atomic.Int32
}

type participantLookupFailingStore struct {
	taskcoord.Store
	loads atomic.Int32
	err   error
}

func (s *participantLookupFailingStore) LoadParticipant(
	ctx context.Context,
	participantID string,
) (taskcoord.Participant, error) {
	s.loads.Add(1)
	return taskcoord.Participant{}, s.err
}

func (s *assignmentLookupCountingStore) LoadAssignment(
	ctx context.Context,
	assignmentID string,
) (taskcoord.Assignment, error) {
	s.loads.Add(1)
	return s.Store.LoadAssignment(ctx, assignmentID)
}

func mustIngressHandler(
	t *testing.T,
	now time.Time,
	store taskcoord.Store,
	replay identitypolicy.ReplayCache,
) http.Handler {
	t.Helper()
	ingress := newTestIngress(now, store, replay)
	handler, err := ingress.Handler()
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func newTestIngress(now time.Time, store taskcoord.Store, replay identitypolicy.ReplayCache) *Ingress {
	return &Ingress{
		Store: store, Now: func() time.Time { return now }, ChallengeTTL: time.Minute,
		Policy: IngressPolicy{
			Grant: clients.JWTVerifyOptions{
				ExpectedIssuer: "human-operation-authority", ExpectedAudience: testAudience,
				ValidMethods: []string{"HS256"},
				LocalKeys:    []clients.LocalKey{{KeyID: ingressManagerKeyID, Key: ingressManagerSecret}},
			},
			SessionBinding: clients.JWTVerifyOptions{
				ExpectedIssuer: "human-gateway", ExpectedAudience: testAudience,
				ValidMethods: []string{"HS256"},
				LocalKeys:    []clients.LocalKey{{KeyID: ingressActorKeyID, Key: ingressActorSecret}},
			},
			ReplayCache: replay,
		},
	}
}

func seededIngressStore(t *testing.T, now time.Time) *taskcoord.MemoryStore {
	t.Helper()
	ctx := context.Background()
	store := taskcoord.NewMemoryStore()
	human := testParticipant("human:alice", taskcoord.ParticipantHuman, false, now.Add(-time.Hour))
	registerParticipants(t, ctx, store, human)
	assignment := offeredHumanAssignment(t, human, now.Add(-10*time.Minute))
	if err := store.CommitAssignment(ctx, 0, assignment, assignment.LastTransition); err != nil {
		t.Fatal(err)
	}
	return store
}

func seededDelegationIngressStore(
	t *testing.T,
	now time.Time,
) (*taskcoord.MemoryStore, taskcoord.Assignment, taskcoord.Participant) {
	t.Helper()
	ctx := context.Background()
	store := taskcoord.NewMemoryStore()
	human := testParticipant("human:alice", taskcoord.ParticipantHuman, true, now.Add(-time.Hour))
	target := testParticipant("agent:reviewer", taskcoord.ParticipantAgent, false, now.Add(-time.Hour))
	registerParticipants(t, ctx, store, human, target)
	offered := offeredHumanAssignment(t, human, now.Add(-10*time.Minute))
	if err := store.CommitAssignment(ctx, 0, offered, offered.LastTransition); err != nil {
		t.Fatal(err)
	}
	acceptedAt := now.Add(-9 * time.Minute)
	accepted, err := taskcoord.Apply(offered, taskcoord.Event{
		ID: "event:accept:delegation-parent", Kind: taskcoord.OperationAccept,
		ExpectedRevision: offered.Revision, At: acceptedAt,
		Auth: taskcoord.AuthenticatedOperation{
			ActorID: testActorID, ParticipantID: human.ParticipantID,
			AuthorizationID: "authorization:accept:delegation-parent",
			ProofID:         "proof:accept:delegation-parent", Operation: taskcoord.OperationAccept,
			TaskID: offered.TaskID, AssignmentID: offered.AssignmentID,
			VerifierNonce: "nonce:accept:delegation-parent",
			IssuedAt:      acceptedAt.Add(-time.Minute), ExpiresAt: acceptedAt.Add(time.Minute),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitAssignment(ctx, offered.Revision, accepted.Assignment, accepted.Record); err != nil {
		t.Fatal(err)
	}
	return store, accepted.Assignment, target
}

func liveDelegationRequest(parent taskcoord.Assignment, targetParticipantID string) DelegationRequest {
	return DelegationRequest{
		ParticipantID: parent.ParticipantID, EventID: "event:delegate:live",
		ParentTaskID: parent.TaskID, ParentAssignmentID: parent.AssignmentID,
		ExpectedRevision: parent.Revision, DecisionID: "decision:delegate:live",
		ChildEventID: "event:child:offer:live", ChildTaskID: "task:child:live",
		ChildAssignmentID: "assignment:child:live", TargetParticipantID: targetParticipantID,
		Role: taskcoord.RoleReviewer, AuthorityDigest: repeatedDigest('e'),
	}
}

func verifiedDelegationFor(
	parent taskcoord.Assignment,
	request DelegationRequest,
	at time.Time,
) taskcoord.VerifiedDelegation {
	return taskcoord.VerifiedDelegation{
		DecisionID: request.DecisionID, ParentAssignmentID: parent.AssignmentID,
		ChildAssignmentID: request.ChildAssignmentID,
		FromParticipantID: parent.ParticipantID, ToParticipantID: request.TargetParticipantID,
		ParentAuthorityDigest: parent.AuthorityDigest, ChildAuthorityDigest: request.AuthorityDigest,
		PolicyRef: "urn:policy:delegation:live", EvidenceRef: "urn:evidence:delegation:live",
		VerifiedAt: at,
	}
}

func requireGatewayAssurance(t *testing.T, provenance *taskcoord.AssuranceProvenance) {
	t.Helper()
	if provenance == nil ||
		provenance.ProfileID != taskcoord.HumanRequestProfileV1 ||
		provenance.AssuranceLevel != taskcoord.HumanAssuranceGatewayAssertedForHuman {
		t.Fatalf("Human assurance provenance = %#v, want gateway-asserted-for-human", provenance)
	}
}

func requestChallenge(
	t *testing.T,
	client *http.Client,
	baseURL string,
	operation string,
	request any,
	wantStatus int,
) liveChallenge {
	t.Helper()
	body := mustJSON(t, ChallengeRequest{Operation: operation, Request: mustJSON(t, request)})
	response, err := client.Post(baseURL+IngressChallengePath, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("challenge request: %v", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != wantStatus {
		t.Fatalf("challenge status = %d, want %d, body = %s", response.StatusCode, wantStatus, raw)
	}
	var result liveChallenge
	if wantStatus < 300 {
		if err := json.Unmarshal(raw, &result.ChallengeResponse); err != nil {
			t.Fatal(err)
		}
		operationEnvelope, err := decodeOperation(operation, mustJSON(t, request))
		if err != nil {
			t.Fatal(err)
		}
		transport, ok := client.Transport.(*http.Transport)
		if !ok || len(transport.TLSClientConfig.Certificates) == 0 ||
			transport.TLSClientConfig.Certificates[0].Leaf == nil || response.TLS == nil {
			t.Fatal("test client does not expose TLS binding material")
		}
		result.binding, err = BindingFromTLS(
			response.TLS,
			transport.TLSClientConfig.Certificates[0].Leaf,
			operationEnvelope.digest,
			result.Nonce,
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	return result
}

type liveChallenge struct {
	ChallengeResponse
	binding identitypolicy.Binding
}

func executeOperation(
	t *testing.T,
	client *http.Client,
	baseURL string,
	request ExecuteRequest,
	wantStatus int,
) ExecuteResponse {
	t.Helper()
	response, err := client.Post(baseURL+IngressExecutePath, "application/json", bytes.NewReader(mustJSON(t, request)))
	if err != nil {
		t.Fatalf("execute request: %v", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != wantStatus {
		t.Fatalf("execute status = %d, want %d, body = %s", response.StatusCode, wantStatus, raw)
	}
	var result ExecuteResponse
	if wantStatus < 300 {
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}
	}
	return result
}

func executeOperationError(
	t *testing.T,
	client *http.Client,
	baseURL string,
	request ExecuteRequest,
) (int, string) {
	t.Helper()
	response, err := client.Post(baseURL+IngressExecutePath, "application/json", bytes.NewReader(mustJSON(t, request)))
	if err != nil {
		t.Fatalf("execute request: %v", err)
	}
	defer response.Body.Close()
	var payload struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, payload.Error
}

func executeValidOperation(
	t *testing.T,
	client *http.Client,
	baseURL string,
	now time.Time,
	operation string,
	request any,
	wantStatus int,
) {
	t.Helper()
	challenge := requestChallenge(t, client, baseURL, operation, request, http.StatusCreated)
	envelope, err := decodeOperation(operation, mustJSON(t, request))
	if err != nil {
		t.Fatal(err)
	}
	grant, proof := signedIngressEvidence(t, now, envelope.digest, challenge)
	executeOperation(t, client, baseURL, ExecuteRequest{
		ChallengeID: challenge.ChallengeID, Operation: operation,
		Request: mustJSON(t, request), GrantJWT: grant, SessionBindingJWT: proof,
	}, wantStatus)
}

func signedIngressEvidence(
	t *testing.T,
	now time.Time,
	digest Digest,
	challenge liveChallenge,
) (string, string) {
	t.Helper()
	grant := signTestJWT(t, ingressManagerKeyID, ingressManagerSecret, jwt.MapClaims{
		"iss": "human-operation-authority", "sub": testActorID, "aud": testAudience,
		"jti": "authorization:" + challenge.ChallengeID, "iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(5 * time.Minute).Unix(), "profile_type": clients.TokenTypeIdentityGrant,
		"profile_version": clients.ProfileVersion, "cnf": map[string]any{"kid": ingressActorKeyID},
		"authorization_details": []string{AuthorizationDetail(digest)},
	})
	proof := signTestJWT(t, ingressActorKeyID, ingressActorSecret, jwt.MapClaims{
		"iss": "human-gateway", "aud": testAudience, "jti": "proof:" + challenge.ChallengeID,
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Minute).Unix(),
		"profile_type": clients.TokenTypeSessionBinding, "profile_version": clients.ProfileVersion,
		"grant_hash":             clients.IdentityGrantHash(grant),
		"leaf_public_key_sha256": challenge.binding.LeafPublicKeySHA256,
		"tls_exporter_sha256":    challenge.binding.TLSExporterSHA256,
		"request_context_sha256": challenge.binding.RequestContextSHA256,
		"nonce":                  challenge.Nonce,
	})
	return grant, proof
}

func cloneHTTPClient(t *testing.T, source *http.Client) *http.Client {
	t.Helper()
	original, ok := source.Transport.(*http.Transport)
	if !ok {
		t.Fatal("source client does not use *http.Transport")
	}
	transport := original.Clone()
	transport.CloseIdleConnections()
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport}
}

func mustJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func ingressCertificates(t *testing.T) (*x509.CertPool, *x509.CertPool, tls.Certificate, tls.Certificate) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ASB demo CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(caCertificate)
	serverCert := issuedCertificate(t, caCertificate, caKey, big.NewInt(2), "localhost", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	clientCert := issuedCertificate(t, caCertificate, caKey, big.NewInt(3), "human-gateway", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	return certPool, certPool.Clone(), serverCert, clientCert
}

func issuedCertificate(
	t *testing.T,
	ca *x509.Certificate,
	caKey *ecdsa.PrivateKey,
	serial *big.Int,
	commonName string,
	usage []x509.ExtKeyUsage,
) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: commonName},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usage,
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key, Leaf: leaf}
}
