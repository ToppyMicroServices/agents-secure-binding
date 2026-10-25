// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

type ingressTransactionCounter struct {
	taskcoord.Store
	calls atomic.Int32
}

func (s *ingressTransactionCounter) RunHumanTransaction(context.Context, func(HumanTransaction) error) error {
	s.calls.Add(1)
	return taskcoord.ErrStoreUnavailable
}

func TestInvalidIngressProofDoesNotEnterDurableTransaction(t *testing.T) {
	now := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	transition := TransitionRequest{
		ParticipantID: "human:alice", EventID: "event:admission", TaskID: "task:human:1",
		AssignmentID: "assignment:human:1", Operation: taskcoord.OperationAccept, ExpectedRevision: 1,
	}
	recovery := RecoveryRequest{ParticipantID: "human:alice", OperationID: "event:earlier", RequestDigest: repeatedDigest('a')}
	for _, tc := range []struct {
		name, operation, path string
		request               any
	}{
		{"execute", OperationAssignmentTransition, IngressExecutePath, transition},
		{"recover", OperationRecover, IngressRecoverPath, recovery},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &ingressTransactionCounter{Store: seededIngressStore(t, now)}
			server, client := newLiveIngressWithStore(t, now, store, nil)
			operation, err := decodeOperation(tc.operation, mustJSON(t, tc.request))
			if err != nil {
				t.Fatal(err)
			}
			for _, corrupt := range []string{"grant", "binding", "none"} {
				challenge := requestChallenge(t, client, server.URL, tc.operation, tc.request, http.StatusCreated)
				grant, binding := signedIngressEvidence(t, now, operation.digest, challenge)
				if corrupt == "grant" {
					grant = invalidIngressSignature(grant)
				} else if corrupt == "binding" {
					binding = invalidIngressSignature(binding)
				}
				request := ExecuteRequest{ChallengeID: challenge.ChallengeID, Operation: tc.operation, Request: mustJSON(t, tc.request), GrantJWT: grant, SessionBindingJWT: binding}
				response, err := client.Post(server.URL+tc.path, "application/json", strings.NewReader(string(mustJSON(t, request))))
				if err != nil {
					t.Fatal(err)
				}
				_ = response.Body.Close()
				wantStatus, wantCalls := http.StatusForbidden, int32(0)
				if corrupt == "none" {
					wantStatus, wantCalls = http.StatusServiceUnavailable, 1
				}
				if response.StatusCode != wantStatus || store.calls.Load() != wantCalls {
					t.Fatalf("%s: status=%d transaction calls=%d", corrupt, response.StatusCode, store.calls.Load())
				}
			}
		})
	}
}

func invalidIngressSignature(token string) string {
	parts := strings.Split(token, ".")
	parts[2] = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	return strings.Join(parts, ".")
}
