// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/thinksyncs/agents-secure-binding/pkg/atls/identitypolicy"
)

func TestDraft06Section21RejectsMissingOrWrongExporter(t *testing.T) {
	now, _, statement, expected := section21FixtureV2()
	for _, value := range []string{"", sha256String([]byte("wrong-exporter"))} {
		observed := statement.Binding
		observed.TLSExporterSHA256 = value
		if err := identitypolicy.ValidateAcceptedBindingV2(observed, expected, now); err == nil {
			t.Fatalf("TLS exporter %q was accepted", value)
		}
	}
}

func TestDraft06Section21RejectsReserializedGrantHash(t *testing.T) {
	now, grant, statement, _ := section21FixtureV2()
	statement.GrantHash = sha256String([]byte("same-claims-different-serialization"))
	if err := identitypolicy.ValidateSessionBindingStatementV2(grant, statement, now); err == nil {
		t.Fatal("proof over a reserialized grant hash was accepted")
	}
}

func TestDraft06Section21RejectsPeerOnlyD3(t *testing.T) {
	now, grant, statement, expected := section21FixtureV2()
	grant.Values.Service = ""
	assertion, err := identitypolicy.NewAssertionFromSessionBindingV2(grant, statement, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := identitypolicy.ValidateAssertionV2(receiverPolicyV2(), assertion, expected, now); err == nil {
		t.Fatal("D3 value supplied only outside the authenticated grant was accepted")
	}
}

func TestDraft06Section21RejectsWrongRoleTypeTaskContextTargetAndOperation(t *testing.T) {
	now, grant, statement, expected := section21FixtureV2()
	tests := map[string]func(*identitypolicy.VerifiedGrantV2, *identitypolicy.VerifiedSessionBindingStatementV2){
		"endpoint_role": func(_ *identitypolicy.VerifiedGrantV2, s *identitypolicy.VerifiedSessionBindingStatementV2) {
			s.Binding.EndpointRole = demoDisallowedEndpointRole
		},
		"interaction_type": func(_ *identitypolicy.VerifiedGrantV2, s *identitypolicy.VerifiedSessionBindingStatementV2) {
			s.Binding.InteractionType = demoDisallowedInteractionType
		},
		"task": func(g *identitypolicy.VerifiedGrantV2, _ *identitypolicy.VerifiedSessionBindingStatementV2) {
			g.Values.TaskID = "task-other"
		},
		"context": func(g *identitypolicy.VerifiedGrantV2, _ *identitypolicy.VerifiedSessionBindingStatementV2) {
			g.Values.ThreadID = "context-other"
		},
		"target": func(g *identitypolicy.VerifiedGrantV2, _ *identitypolicy.VerifiedSessionBindingStatementV2) {
			g.Target.Resource = demoOtherResource
		},
		"operation": func(g *identitypolicy.VerifiedGrantV2, _ *identitypolicy.VerifiedSessionBindingStatementV2) {
			g.Target.Operation = demoDisallowedOperation
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changedGrant, changedStatement := grant, statement
			mutate(&changedGrant, &changedStatement)
			assertion, err := identitypolicy.NewAssertionFromSessionBindingV2(changedGrant, changedStatement, now)
			if err == nil {
				err = identitypolicy.ValidateAssertionV2(receiverPolicyV2(), assertion, expected, now)
			}
			if err == nil {
				t.Fatalf("wrong %s was accepted", name)
			}
		})
	}
}

func TestDraft06Section21RejectsEffectiveAuthorizationFromWrongConnection(t *testing.T) {
	now, grant, statement, expected := section21FixtureV2()
	statement.Binding.TLSExporterSHA256 = sha256String([]byte("another-connection"))
	assertion, err := identitypolicy.NewAssertionFromSessionBindingV2(grant, statement, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := identitypolicy.ValidateAssertionV2(receiverPolicyV2(), assertion, expected, now); err == nil {
		t.Fatal("effective authorization from another TLS connection was accepted")
	}
}

func TestDraft06Section21RejectsBorrowedOrMissingAttestation(t *testing.T) {
	now, _, statement, expected := section21FixtureV2()
	for _, binder := range []string{"", sha256String([]byte("borrowed-attestation"))} {
		observed := statement.Binding
		observed.AttestationBinderSHA256 = binder
		if err := identitypolicy.ValidateAcceptedBindingV2(observed, expected, now); err == nil {
			t.Fatalf("attestation binder %q was accepted", binder)
		}
	}
}

func TestDraft06Section21RejectsWrongAppraisalPolicy(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	token, err := signJWT(demoVerifierKeyID, key, attestationResultClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: demoVerifierIssuer, Subject: demoAgentIssuer,
			Audience: jwt.ClaimStrings{demoAudience}, ID: "attestation-result",
			IssuedAt: jwt.NewNumericDate(now.Add(-time.Second)), ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
		},
		ProfileType: v2AttestationProfile, ProfileVersion: v2AttestationVersion,
		AppraisalPolicyID: "urn:agents-secure-binding:attestation-policy:wrong",
		Platform:          platformSimulated, Simulation: true,
		BinderSHA256: sha256String([]byte("binder")), EvidenceSHA256: sha256String([]byte("evidence")),
		MeasurementSHA256: sha256String([]byte(demoMeasurement)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseAttestationResultV2(token, &key.PublicKey, now); err == nil {
		t.Fatal("wrong appraisal_policy_id was accepted")
	}
}

func TestDraft06Section21SurplusAuthorizationDoesNotExpandEffectiveSet(t *testing.T) {
	now, grant, statement, expected := section21FixtureV2()
	grant.Values.Scopes = append(grant.Values.Scopes, "documents:delete")
	grant.Values.Resources = append(grant.Values.Resources, demoOtherResource)
	policy := receiverPolicyV2()
	policy.SetMode = identitypolicy.SetModeContainsAll
	assertion, err := identitypolicy.NewAssertionFromSessionBindingV2(grant, statement, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := identitypolicy.ValidateAssertionV2(policy, assertion, expected, now); err != nil {
		t.Fatal(err)
	}
	effective, err := identitypolicy.EffectiveAuthorization(policy, assertion)
	if err != nil {
		t.Fatal(err)
	}
	if len(effective.Scopes) != 1 || effective.Scopes[0] != demoReadScope || len(effective.Resources) != 1 || effective.Resources[0] != demoResource {
		t.Fatalf("surplus authorization expanded the effective set: %+v", effective)
	}
}

func TestDraft06Section21RejectsNonceReuseOnAnotherTask(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	store := newChallengeStoreV2()
	store.records["nonce"] = challengeRecordV2{
		attemptID: "attempt", channel: "channel", peerSPKI: "spki",
		expiresAt: now.Add(time.Minute), state: challengeIssuedV2,
	}
	if _, err := store.begin("nonce", "attempt", "channel", "spki", now); err != nil {
		t.Fatal(err)
	}
	if err := store.consume("nonce"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.begin("nonce", "attempt", "channel", "spki", now); err == nil {
		t.Fatal("consumed nonce was accepted for another task")
	}
}

func TestDraft06ChallengeRestartDiscardsPendingStateAndFailsClosed(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	beforeRestart := newChallengeStoreV2()
	challenge, err := beforeRestart.issueForBindingV2("channel", "spki", now)
	if err != nil {
		t.Fatal(err)
	}
	afterRestart := newChallengeStoreV2()
	if _, err := afterRestart.begin(challenge.VerifierNonce, challenge.AttemptID, "channel", "spki", now); err == nil {
		t.Fatal("fresh challenge store accepted pre-restart pending state")
	}
}

func TestDraft06RejectsProofExpiryExtendedBeyondChallenge(t *testing.T) {
	challengeExpiry := time.Unix(1_800_000_030, 987_000_000).UTC()
	if err := validateChallengeBoundExpiryV2(challengeExpiry.Unix(), challengeExpiry); err != nil {
		t.Fatal(err)
	}
	if err := validateChallengeBoundExpiryV2(challengeExpiry.Add(time.Second).Unix(), challengeExpiry); err == nil {
		t.Fatal("proof expiry extended beyond the authenticated challenge was accepted")
	}
}

func TestDraft06Section21RejectsReverseCallbackContinuationAndDerivedSigner(t *testing.T) {
	now, grant, statement, expected := section21FixtureV2()
	tests := map[string]func(*identitypolicy.VerifiedSessionBindingStatementV2){
		"reverse_role": func(s *identitypolicy.VerifiedSessionBindingStatementV2) {
			s.Binding.EndpointRole = demoDisallowedEndpointRole
		},
		"callback": func(s *identitypolicy.VerifiedSessionBindingStatementV2) {
			s.Binding.InteractionType = demoDisallowedInteractionType
		},
		"continuation": func(s *identitypolicy.VerifiedSessionBindingStatementV2) { s.Binding.InteractionType = "continuation" },
		"derived_grant_signer": func(s *identitypolicy.VerifiedSessionBindingStatementV2) {
			s.SignerKey = "derived-agent-key"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := statement
			mutate(&changed)
			assertion, err := identitypolicy.NewAssertionFromSessionBindingV2(grant, changed, now)
			if err == nil {
				err = identitypolicy.ValidateAssertionV2(receiverPolicyV2(), assertion, expected, now)
			}
			if err == nil {
				t.Fatalf("%s was accepted", name)
			}
		})
	}
}

func TestDraft06Section21FailsClosedWhenCreatorIsolationIsRequired(t *testing.T) {
	now, grant, statement, expected := section21FixtureV2()
	assertion, err := identitypolicy.NewAssertionFromSessionBindingV2(grant, statement, now)
	if err != nil {
		t.Fatal(err)
	}
	policy := receiverPolicyV2()
	policy.RequireCreatorIsolatedKey = true
	if err := identitypolicy.ValidateAssertionV2(policy, assertion, expected, now); !errors.Is(err, identitypolicy.ErrCreatorIsolationUnverified) {
		t.Fatalf("creator-isolation error = %v", err)
	}
}

func TestDraft06Section21FailsClosedWhenReplayIsUnavailable(t *testing.T) {
	_, grant, statement, _ := section21FixtureV2()
	if grant.GrantHash != statement.GrantHash {
		t.Fatal("section 21 replay fixture grant hash mismatch")
	}
	if err := identitypolicy.MarkSessionBindingUsedV2(nil, statement); !errors.Is(err, identitypolicy.ErrMissingReplayCacheV2) {
		t.Fatalf("nil replay cache error = %v", err)
	}
	failing := replayCacheFailureV2{}
	if err := identitypolicy.MarkSessionBindingUsedV2(failing, statement); !errors.Is(err, errReplayOutageV2) {
		t.Fatalf("replay outage error = %v", err)
	}
}

func TestDraft06Section21RejectsZeroRTT(t *testing.T) {
	if err := requireNoEarlyDataV2(true); err == nil {
		t.Fatal("0-RTT was accepted")
	}
	state := &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true, DidResume: true, PeerCertificates: []*x509.Certificate{{}}, VerifiedChains: [][]*x509.Certificate{{{}}}}
	if err := validateTLSSessionV2(state); err == nil {
		t.Fatal("a resumed TLS session was accepted")
	}
}

func TestDraft06Section21RejectsGatewayAsFinalEndpoint(t *testing.T) {
	for _, header := range []string{"Forwarded", "Via", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
		request, err := http.NewRequest(http.MethodPost, "https://agent-b/message:send", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set(header, "gateway")
		if err := rejectTransportIndirectionV2(request); err == nil {
			t.Fatalf("gateway header %s was accepted", header)
		}
	}
}

func TestDraft06Section21TaskAndTargetMutationsChangeSeparateContexts(t *testing.T) {
	newRequest := func() a2aSendMessageRequest {
		request := newTaskRequestV2()
		request.Message.MessageID = "section21-message"
		return request
	}
	baseline, err := canonicalRequestContextsV2(newRequest())
	if err != nil {
		t.Fatal(err)
	}
	taskMutation := newRequest()
	taskMutation.Message.MessageID = "another-message"
	taskChanged, err := canonicalRequestContextsV2(taskMutation)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(baseline.Task, taskChanged.Task) || !bytes.Equal(baseline.Target, taskChanged.Target) {
		t.Fatal("task mutation did not remain isolated to task_context")
	}
	for name, mutate := range map[string]func(*a2aSendMessageRequest){
		"target":    func(r *a2aSendMessageRequest) { r.Message.Parts[0].Metadata["resource"] = demoOtherResource },
		"operation": func(r *a2aSendMessageRequest) { r.Message.Parts[0].Metadata["operation"] = demoDisallowedOperation },
	} {
		t.Run(name, func(t *testing.T) {
			request := newRequest()
			mutate(&request)
			changed, err := canonicalRequestContextsV2(request)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(baseline.Task, changed.Task) || bytes.Equal(baseline.Target, changed.Target) {
				t.Fatalf("%s mutation did not remain isolated to target_context", name)
			}
		})
	}
}

func TestDraft06StrictJSONRejectsDuplicateAliasAndReplacementCharacter(t *testing.T) {
	raw, err := json.Marshal(newTaskRequestV2())
	if err != nil {
		t.Fatal(err)
	}
	duplicate := strings.Replace(string(raw), `"messageId":`, `"messageId":"duplicate","message\u0049d":`, 1)
	caseAlias := strings.Replace(string(raw), `"messageId":`, `"MessageId":`, 1)
	replacement := strings.Replace(string(raw), "message-task", "message-\ufffd-task", 1)
	controlRequest := newTaskRequestV2()
	controlRequest.Message.MessageID = "message\ncontrol"
	control, err := json.Marshal(controlRequest)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string][]byte{
		"escaped_duplicate": []byte(duplicate),
		"case_alias":        []byte(caseAlias),
		"replacement":       []byte(replacement),
		"control":           control,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeStrictA2ARequestV2(value); err == nil {
				t.Fatalf("strict decoder accepted %s", name)
			}
		})
	}
}

func TestDraft06CanonicalListsUseCountSortAndRejectDuplicates(t *testing.T) {
	encoded, err := encodeCanonicalListV2([]string{"b", "a"})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 0, 0, 2, 0, 0, 0, 1, 'a', 0, 0, 0, 1, 'b'}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("canonical list = %x, want %x", encoded, want)
	}
	if _, err := encodeCanonicalListV2([]string{"same", "same"}); err == nil {
		t.Fatal("duplicate canonical-list member was accepted")
	}
	contexts, err := canonicalRequestContextsV2(newTaskRequestV2())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(contexts.Task, []byte("selected_extensions")) || bytes.Contains(contexts.Task, []byte("\x00extensions")) {
		t.Fatal("task_context did not use the selected_extensions field")
	}
}

func TestDraft06ChallengeRequestIsExactlyEmptyObject(t *testing.T) {
	if _, err := decodeChallengeRequestV2([]byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`{"endpoint_role":"client-tls-endpoint"}`, `{"x":1}`, `[]`} {
		if _, err := decodeChallengeRequestV2([]byte(raw)); err == nil {
			t.Fatalf("challenge request %s was accepted", raw)
		}
	}
}

func TestDraft06ChallengeRegeneratesNonceAndAttemptCollisions(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	store := newChallengeStoreV2()
	store.records["live-nonce"] = challengeRecordV2{attemptID: "live-attempt", expiresAt: now.Add(time.Minute), state: challengeIssuedV2}
	values := []string{
		"live-nonce", "candidate-attempt-1",
		"candidate-nonce-2", "live-attempt",
		"fresh-nonce", "fresh-attempt",
	}
	store.random = func(int) (string, error) {
		value := values[0]
		values = values[1:]
		return value, nil
	}
	challenge, err := store.issueForBindingV2("channel", "spki", now)
	if err != nil {
		t.Fatal(err)
	}
	if challenge.VerifierNonce != "fresh-nonce" || challenge.AttemptID != "fresh-attempt" || len(store.records) != 2 {
		t.Fatalf("collision regeneration result = %+v records=%d", challenge, len(store.records))
	}
}

func TestDraft06ChallengeFailsClosedAfterCollisionBudget(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	store := newChallengeStoreV2()
	store.records["collision"] = challengeRecordV2{attemptID: "existing-attempt", expiresAt: now.Add(time.Minute), state: challengeIssuedV2}
	store.random = func(int) (string, error) { return "collision", nil }
	if _, err := store.issueForBindingV2("channel", "spki", now); err == nil {
		t.Fatal("challenge collision exhaustion did not fail closed")
	}
	if len(store.records) != 1 || store.records["collision"].attemptID != "existing-attempt" {
		t.Fatal("challenge collision overwrote live state")
	}
}

func TestDraft06RechecksCurrentClientCertificateValidity(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	valid := &x509.Certificate{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute)}
	if err := validateCertificateAtV2(valid, now); err != nil {
		t.Fatal(err)
	}
	for _, certificate := range []*x509.Certificate{
		{NotBefore: now.Add(time.Second), NotAfter: now.Add(time.Minute)},
		{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(-time.Second)},
	} {
		if err := validateCertificateAtV2(certificate, now); err == nil {
			t.Fatal("certificate outside its current validity interval was accepted")
		}
	}
}

func TestDraft06TargetComparisonUsesExactRawValues(t *testing.T) {
	request := newTaskRequestV2()
	request.Message.Parts[0].Metadata["resource"] = " " + demoResource
	if _, _, err := taskOperationAndResourceV2(request.Message); err == nil {
		t.Fatal("whitespace-normalized target was accepted")
	}
}

func section21FixtureV2() (time.Time, identitypolicy.VerifiedGrantV2, identitypolicy.VerifiedSessionBindingStatementV2, identitypolicy.BindingV2) {
	now := time.Unix(1_800_000_000, 0).UTC()
	binding := identitypolicy.BindingV2{
		EndpointRole: v2EndpointRole, InteractionType: v2InteractionType,
		AcceptedEndpointSPKISHA256: sha256String([]byte("spki")),
		TLSExporterSHA256:          sha256String([]byte("exporter")),
		BindingContextSHA256:       sha256String([]byte("context")),
		AttestationBinderSHA256:    sha256String([]byte("binder")),
		VerifierNonce:              "bm9uY2Utbm9uY2Utbm9uY2U", AttemptID: "YXR0ZW1wdA",
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
	}
	grant := identitypolicy.VerifiedGrantV2{
		VerifiedGrant: identitypolicy.VerifiedGrant{
			Issuer: demoManagerIssuer, IssuerKey: demoManagerKeyID, Audience: demoAudience,
			GrantHash: sha256String([]byte("grant")), ConfirmationKey: demoAgentKeyID,
			Values: identitypolicy.Values{
				Service: demoService, Deployment: demoDeployment, Workload: demoWorkload,
				Agent: demoAgentIssuer, TaskID: demoTaskID, ThreadID: demoThreadID, IntentRef: demoIntent,
				CapabilityRef: demoCapability, Scopes: []string{demoReadScope}, Resources: []string{demoResource},
			},
			IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(2 * time.Minute),
		},
		Target: identitypolicy.TargetV2{Resource: demoResource, Operation: demoOperation},
	}
	statement := identitypolicy.VerifiedSessionBindingStatementV2{
		GrantHash: grant.GrantHash, Audience: demoAudience, SignerKey: demoAgentKeyID, Binding: binding,
	}
	return now, grant, statement, binding
}

var errReplayOutageV2 = errors.New("replay outage")

type replayCacheFailureV2 struct{}

func (replayCacheFailureV2) MarkUsed(string, time.Time) error { return errReplayOutageV2 }
