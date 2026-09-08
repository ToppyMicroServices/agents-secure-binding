// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

func TestHumanProtocolRedTeamRejectsKindAndChallengeMixUp(t *testing.T) {
	now := time.Date(2026, 9, 2, 11, 0, 0, 0, time.UTC)

	t.Run("operation kind", func(t *testing.T) {
		server, client, store := newLiveIngress(t, now)
		request := redTeamTransitionRequest("kind-confusion")
		challenge := requestChallenge(t, client, server.URL, OperationAssignmentTransition, request, http.StatusCreated)
		digest, err := TransitionDigest(request)
		if err != nil {
			t.Fatal(err)
		}
		grant, proof := signedIngressEvidence(t, now, digest, challenge)
		interaction := InteractionRequest{
			ParticipantID: request.ParticipantID, EventID: "event:redteam:kind-confusion:interaction",
			InteractionID: "interaction:redteam:kind-confusion", TaskID: request.TaskID,
			AssignmentID: request.AssignmentID, Kind: taskcoord.InteractionQuestion,
			ContentRef: "urn:content:redteam:kind-confusion", ContentDigest: repeatedDigest('c'),
		}
		response := postIngressExecute(t, client, server.URL, ExecuteRequest{
			ChallengeID: challenge.ChallengeID, Operation: OperationInteractionAppend,
			Request: mustJSON(t, interaction), GrantJWT: grant, SessionBindingJWT: proof,
		})
		assertRedTeamIngressError(t, response, http.StatusUnauthorized, IngressCodeChallengeRejected)

		// A confused use burns only that one-shot challenge. It cannot then be
		// replayed with the originally bound operation.
		response = postIngressExecute(t, client, server.URL, ExecuteRequest{
			ChallengeID: challenge.ChallengeID, Operation: OperationAssignmentTransition,
			Request: mustJSON(t, request), GrantJWT: grant, SessionBindingJWT: proof,
		})
		assertRedTeamIngressError(t, response, http.StatusUnauthorized, IngressCodeChallengeRejected)
		assertRedTeamAssignmentUnchanged(t, store, request.AssignmentID)
	})

	t.Run("challenge and proof", func(t *testing.T) {
		server, client, store := newLiveIngress(t, now)
		request := redTeamTransitionRequest("challenge-confusion")
		first := requestChallenge(t, client, server.URL, OperationAssignmentTransition, request, http.StatusCreated)
		second := requestChallenge(t, client, server.URL, OperationAssignmentTransition, request, http.StatusCreated)
		digest, err := TransitionDigest(request)
		if err != nil {
			t.Fatal(err)
		}
		firstGrant, firstProof := signedIngressEvidence(t, now, digest, first)
		secondGrant, secondProof := signedIngressEvidence(t, now, digest, second)

		mixed := postIngressExecute(t, client, server.URL, ExecuteRequest{
			ChallengeID: second.ChallengeID, Operation: OperationAssignmentTransition,
			Request: mustJSON(t, request), GrantJWT: firstGrant, SessionBindingJWT: firstProof,
		})
		assertRedTeamIngressError(t, mixed, http.StatusForbidden, IngressCodeOperationRejected)
		assertRedTeamResponseOmits(t, mixed.body, request.ParticipantID, firstGrant, firstProof)

		consumed := postIngressExecute(t, client, server.URL, ExecuteRequest{
			ChallengeID: second.ChallengeID, Operation: OperationAssignmentTransition,
			Request: mustJSON(t, request), GrantJWT: secondGrant, SessionBindingJWT: secondProof,
		})
		assertRedTeamIngressError(t, consumed, http.StatusUnauthorized, IngressCodeChallengeRejected)

		valid := postIngressExecute(t, client, server.URL, ExecuteRequest{
			ChallengeID: first.ChallengeID, Operation: OperationAssignmentTransition,
			Request: mustJSON(t, request), GrantJWT: firstGrant, SessionBindingJWT: firstProof,
		})
		if valid.err != nil || valid.status != http.StatusOK {
			t.Fatalf("correct challenge/proof pair status=%d error=%v body=%s", valid.status, valid.err, valid.body)
		}
		stored, err := store.LoadAssignment(context.Background(), request.AssignmentID)
		if err != nil || stored.Status != taskcoord.AssignmentAccepted || stored.Revision != 2 {
			t.Fatalf("correct challenge/proof pair stored Assignment=%+v error=%v", stored, err)
		}
	})
}

func TestHumanProtocolRedTeamSerializesConcurrentHTTP2ChallengeUse(t *testing.T) {
	now := time.Date(2026, 9, 2, 11, 30, 0, 0, time.UTC)
	server, client, store := newLiveIngress(t, now)
	request := redTeamTransitionRequest("http2-race")
	challenge := requestChallenge(t, client, server.URL, OperationAssignmentTransition, request, http.StatusCreated)
	digest, err := TransitionDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	grant, proof := signedIngressEvidence(t, now, digest, challenge)
	body := mustJSON(t, ExecuteRequest{
		ChallengeID: challenge.ChallengeID, Operation: OperationAssignmentTransition,
		Request: mustJSON(t, request), GrantJWT: grant, SessionBindingJWT: proof,
	})

	start := make(chan struct{})
	results := make(chan redTeamHTTPResult, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			results <- doRedTeamHTTPRequest(client, server.URL+IngressExecutePath, body)
		}()
	}
	close(start)
	workers.Wait()
	close(results)

	statuses := make([]int, 0, 2)
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent HTTP/2 execute error: %v", result.err)
		}
		if result.protoMajor != 2 {
			t.Fatalf("execute used HTTP/%d, want HTTP/2", result.protoMajor)
		}
		statuses = append(statuses, result.status)
	}
	sort.Ints(statuses)
	if len(statuses) != 2 || statuses[0] != http.StatusOK || statuses[1] != http.StatusUnauthorized {
		t.Fatalf("concurrent execute statuses=%v, want [%d %d]", statuses, http.StatusOK, http.StatusUnauthorized)
	}
	stored, err := store.LoadAssignment(context.Background(), request.AssignmentID)
	if err != nil || stored.Status != taskcoord.AssignmentAccepted || stored.Revision != 2 {
		t.Fatalf("concurrent execute stored Assignment=%+v error=%v", stored, err)
	}
}

func TestHumanProtocolRedTeamRejectsChallengeAcrossResumedTLSConnection(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	server, client, store := newLiveIngress(t, now)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("test client does not use *http.Transport")
	}
	transport.TLSClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(4)

	request := redTeamTransitionRequest("tls-resumption")
	challenge := requestChallenge(t, client, server.URL, OperationAssignmentTransition, request, http.StatusCreated)
	digest, err := TransitionDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	grant, proof := signedIngressEvidence(t, now, digest, challenge)
	transport.CloseIdleConnections()
	result := postIngressExecute(t, client, server.URL, ExecuteRequest{
		ChallengeID: challenge.ChallengeID, Operation: OperationAssignmentTransition,
		Request: mustJSON(t, request), GrantJWT: grant, SessionBindingJWT: proof,
	})
	if !result.didResume {
		t.Fatal("second TLS 1.3 connection did not resume the cached session")
	}
	assertRedTeamIngressError(t, result, http.StatusUnauthorized, IngressCodeChallengeRejected)
	assertRedTeamAssignmentUnchanged(t, store, request.AssignmentID)
}

type redTeamHTTPResult struct {
	status     int
	protoMajor int
	didResume  bool
	body       []byte
	err        error
}

func redTeamTransitionRequest(suffix string) TransitionRequest {
	return TransitionRequest{
		ParticipantID: "human:alice", EventID: "event:redteam:" + suffix,
		TaskID: "task:human:1", AssignmentID: "assignment:human:1",
		Operation: taskcoord.OperationAccept, ExpectedRevision: 1,
	}
}

func postIngressExecute(t *testing.T, client *http.Client, baseURL string, request ExecuteRequest) redTeamHTTPResult {
	t.Helper()
	return doRedTeamHTTPRequest(client, baseURL+IngressExecutePath, mustJSON(t, request))
}

func doRedTeamHTTPRequest(client *http.Client, url string, body []byte) redTeamHTTPResult {
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return redTeamHTTPResult{err: err}
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return redTeamHTTPResult{err: err}
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(response.Body)
	result := redTeamHTTPResult{
		status: response.StatusCode, protoMajor: response.ProtoMajor,
		body: raw, err: readErr,
	}
	if response.TLS != nil {
		result.didResume = response.TLS.DidResume
	}
	return result
}

func assertRedTeamIngressError(t *testing.T, result redTeamHTTPResult, status int, code IngressErrorCode) {
	t.Helper()
	if result.err != nil {
		t.Fatalf("ingress request error: %v", result.err)
	}
	if result.status != status {
		t.Fatalf("ingress status=%d, want %d, body=%s", result.status, status, result.body)
	}
	var payload IngressErrorResponse
	if err := json.Unmarshal(result.body, &payload); err != nil {
		t.Fatalf("decode ingress error: %v; body=%s", err, result.body)
	}
	if payload.Code != code || payload.Retryable {
		t.Fatalf("ingress error=%+v, want code=%s retryable=false", payload, code)
	}
}

func assertRedTeamResponseOmits(t *testing.T, body []byte, canaries ...string) {
	t.Helper()
	for _, canary := range canaries {
		if canary != "" && strings.Contains(string(body), canary) {
			t.Fatalf("public response leaked canary %q: %s", canary, body)
		}
	}
}

func assertRedTeamAssignmentUnchanged(t *testing.T, store *taskcoord.MemoryStore, assignmentID string) {
	t.Helper()
	stored, err := store.LoadAssignment(context.Background(), assignmentID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != taskcoord.AssignmentOffered || stored.Revision != 1 {
		t.Fatalf("rejected request changed Assignment: %+v", stored)
	}
}
