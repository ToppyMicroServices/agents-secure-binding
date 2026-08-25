// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package identitypolicy

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPrepareAssertionV2UsesEarliestApplicableExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	tests := map[string]struct {
		configure func(*VerifiedGrantV2, *VerifiedSessionBindingStatementV2, *AcceptanceInputsV2)
		want      time.Time
	}{
		"proof": {
			configure: func(_ *VerifiedGrantV2, statement *VerifiedSessionBindingStatementV2, _ *AcceptanceInputsV2) {
				statement.Binding.ExpiresAt = now.Add(time.Minute)
			},
			want: now.Add(time.Minute),
		},
		"endpoint credential": {
			configure: func(_ *VerifiedGrantV2, _ *VerifiedSessionBindingStatementV2, inputs *AcceptanceInputsV2) {
				inputs.Freshness.EndpointCredentialExpiresAt = now.Add(time.Minute)
			},
			want: now.Add(time.Minute),
		},
		"challenge": {
			configure: func(_ *VerifiedGrantV2, _ *VerifiedSessionBindingStatementV2, inputs *AcceptanceInputsV2) {
				inputs.Freshness.EvidenceChallengeExpiresAt = now.Add(time.Minute)
			},
			want: now.Add(time.Minute),
		},
		"local policy": {
			configure: func(_ *VerifiedGrantV2, _ *VerifiedSessionBindingStatementV2, inputs *AcceptanceInputsV2) {
				inputs.Freshness.LocalPolicyExpiresAt = now.Add(time.Minute)
			},
			want: now.Add(time.Minute),
		},
		"exported authenticator": {
			configure: func(_ *VerifiedGrantV2, _ *VerifiedSessionBindingStatementV2, inputs *AcceptanceInputsV2) {
				inputs.Freshness.ExportedAuthenticatorExpiresAt = now.Add(time.Minute)
			},
			want: now.Add(time.Minute),
		},
		"attestation collateral": {
			configure: func(_ *VerifiedGrantV2, _ *VerifiedSessionBindingStatementV2, inputs *AcceptanceInputsV2) {
				inputs.Freshness.AttestationCollateralExpiresAt = now.Add(time.Minute)
			},
			want: now.Add(time.Minute),
		},
		"attestation result": {
			configure: func(_ *VerifiedGrantV2, statement *VerifiedSessionBindingStatementV2, inputs *AcceptanceInputsV2) {
				statement.Binding.AttestationBinderSHA256 = "attestation-binder"
				result := testVerifiedAttestationResultV2(now, statement.Binding.AttestationBinderSHA256)
				result.ExpiresAt = now.Add(time.Minute)
				inputs.AttestationResult = &result
			},
			want: now.Add(time.Minute),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			grant := testVerifiedGrantV2(now)
			grant.ExpiresAt = now.Add(10 * time.Minute)
			statement := testSessionBindingStatementV2(now)
			statement.Binding.ExpiresAt = now.Add(9 * time.Minute)
			inputs := testAcceptanceInputsV2(now, nil)
			inputs.Freshness.EndpointCredentialExpiresAt = now.Add(8 * time.Minute)
			inputs.Freshness.EvidenceChallengeExpiresAt = now.Add(7 * time.Minute)
			inputs.Freshness.LocalPolicyExpiresAt = now.Add(6 * time.Minute)
			test.configure(&grant, &statement, &inputs)

			assertion, err := NewAssertionFromSessionBindingV2(grant, statement, now)
			if err != nil {
				t.Fatalf("NewAssertionFromSessionBindingV2() error = %v", err)
			}
			prepared, err := PrepareAssertionV2(testCompletePolicyV2(), assertion, statement.Binding, now, inputs)
			if err != nil {
				t.Fatalf("PrepareAssertionV2() error = %v", err)
			}
			if !prepared.Expiry().Equal(test.want) {
				t.Fatalf("expiry = %v, want %v", prepared.Expiry(), test.want)
			}
		})
	}
}

func TestPrepareAssertionV2RejectsMissingOrExpiredTrustedFreshness(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	grant := testVerifiedGrantV2(now)
	statement := testSessionBindingStatementV2(now)
	assertion, err := NewAssertionFromSessionBindingV2(grant, statement, now)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]func(*FreshnessInputsV2){
		"missing endpoint expiry":  func(v *FreshnessInputsV2) { v.EndpointCredentialExpiresAt = time.Time{} },
		"missing challenge expiry": func(v *FreshnessInputsV2) { v.EvidenceChallengeExpiresAt = time.Time{} },
		"missing local expiry":     func(v *FreshnessInputsV2) { v.LocalPolicyExpiresAt = time.Time{} },
		"expired endpoint":         func(v *FreshnessInputsV2) { v.EndpointCredentialExpiresAt = now },
		"expired challenge":        func(v *FreshnessInputsV2) { v.EvidenceChallengeExpiresAt = now },
		"expired local policy":     func(v *FreshnessInputsV2) { v.LocalPolicyExpiresAt = now },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			inputs := testAcceptanceInputsV2(now, nil)
			mutate(&inputs.Freshness)
			if _, err := PrepareAssertionV2(testCompletePolicyV2(), assertion, statement.Binding, now, inputs); err == nil {
				t.Fatal("PrepareAssertionV2() error = nil")
			}
		})
	}
}

func TestPrepareAssertionV2RejectsAttestationForAnotherActor(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	grant := testVerifiedGrantV2(now)
	statement := testSessionBindingStatementV2(now)
	statement.Binding.AttestationBinderSHA256 = "attestation-binder"
	assertion, err := NewAssertionFromSessionBindingV2(grant, statement, now)
	if err != nil {
		t.Fatal(err)
	}
	result := testVerifiedAttestationResultV2(now, statement.Binding.AttestationBinderSHA256)
	result.Subject = "agent-bystander"
	inputs := testAcceptanceInputsV2(now, &result)

	if _, err := PrepareAssertionV2(testCompletePolicyV2(), assertion, statement.Binding, now, inputs); !errors.Is(err, ErrInvalidAttestationV2) {
		t.Fatalf("PrepareAssertionV2() error = %v, want ErrInvalidAttestationV2", err)
	}
}

func TestAcceptedAssertionV2OptionalResultsAreActuallyAbsent(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	grant := testVerifiedGrantV2(now)
	grant.Target = TargetV2{}
	statement := testSessionBindingStatementV2(now)
	assertion, err := NewAssertionFromSessionBindingV2(grant, statement, now)
	if err != nil {
		t.Fatal(err)
	}
	policy := testCompletePolicyV2()
	policy.Require.D6 = false
	policy.ExpectedTarget = TargetV2{}
	policy.Expected.DelegationID = ""
	prepared, err := PrepareAssertionV2(policy, assertion, statement.Binding, now, testAcceptanceInputsV2(now, nil))
	if err != nil {
		t.Fatal(err)
	}
	cache := &v2RecordingReplayCache{seen: make(map[string]struct{})}
	accepted, err := CommitPreparedAssertionV2(cache, prepared, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(accepted)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	wantTopLevel := map[string]struct{}{
		"scope": {}, "accepted_profile": {}, "accepted_channel": {},
		"accepted_actor": {}, "accepted_authority": {}, "accepted_interaction": {},
		"replay_commit": {}, "effective_authorization": {}, "expiry": {},
	}
	if len(document) != len(wantTopLevel) {
		t.Fatalf("application assertion members = %v, want %v", sortedJSONKeys(document), sortedSetKeys(wantTopLevel))
	}
	for member := range wantTopLevel {
		if _, ok := document[member]; !ok {
			t.Fatalf("application assertion is missing %q: %s", member, raw)
		}
	}
	for _, member := range []string{"accepted_target", "accepted_delegation", "attestation_result"} {
		if strings.Contains(string(raw), `"`+member+`"`) {
			t.Fatalf("optional member %q serialized in %s", member, raw)
		}
	}
	for _, auditMember := range []string{"grant", "proof", "issued_at", "replay_key", "signer_key_id", "authority_key_id", "result_id"} {
		if strings.Contains(string(raw), `"`+auditMember+`"`) {
			t.Fatalf("application assertion exposed audit member %q in %s", auditMember, raw)
		}
	}
	for _, secret := range []string{statement.Binding.VerifierNonce, statement.Binding.AttemptID, statement.JWTID, grant.JWTID, grant.GrantHash} {
		if secret != "" && strings.Contains(string(raw), secret) {
			t.Fatalf("application assertion exposed audit value %q in %s", secret, raw)
		}
	}
}

func sortedJSONKeys(values map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func sortedSetKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func TestCommitPreparedAssertionV2ReservesNonceThroughAcceptanceWindow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	grant := testVerifiedGrantV2(now)
	statement := testSessionBindingStatementV2(now)
	statement.Binding.AttestationBinderSHA256 = "attestation-binder"
	result := testVerifiedAttestationResultV2(now, statement.Binding.AttestationBinderSHA256)
	result.ExpiresAt = now.Add(30 * time.Second)
	inputs := testAcceptanceInputsV2(now, &result)
	inputs.Freshness.EvidenceChallengeExpiresAt = now.Add(2 * time.Minute)
	assertion, err := NewAssertionFromSessionBindingV2(grant, statement, now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareAssertionV2(testCompletePolicyV2(), assertion, statement.Binding, now, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if !prepared.Expiry().Equal(result.ExpiresAt) || !prepared.ReplayRetainUntil().Equal(inputs.Freshness.EvidenceChallengeExpiresAt) {
		t.Fatalf("prepared expiry = %v, replay retention = %v", prepared.Expiry(), prepared.ReplayRetainUntil())
	}

	cache := &v2RecordingReplayCache{seen: make(map[string]struct{})}
	accepted, err := CommitPreparedAssertionV2(cache, prepared, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if !cache.expiresAt.Equal(inputs.Freshness.EvidenceChallengeExpiresAt) || !accepted.ReplayCommit.RetainUntil.Equal(inputs.Freshness.EvidenceChallengeExpiresAt) {
		t.Fatalf("replay retention = %v, assertion = %#v", cache.expiresAt, accepted.ReplayCommit)
	}

	changedStatement := statement
	changedStatement.JWTID = "proof-v2-2"
	changedResult := result
	changedResult.ResultID = "attestation-result-v2-2"
	changedInputs := inputs
	changedInputs.AttestationResult = &changedResult
	changedAssertion, err := NewAssertionFromSessionBindingV2(grant, changedStatement, now)
	if err != nil {
		t.Fatal(err)
	}
	changedPrepared, err := PrepareAssertionV2(testCompletePolicyV2(), changedAssertion, changedStatement.Binding, now, changedInputs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CommitPreparedAssertionV2(cache, changedPrepared, func() time.Time { return now }); !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("changed proof/result reused verifier nonce: %v", err)
	}

	failing := &v2RecordingReplayCache{fail: true}
	failedAccepted, err := CommitPreparedAssertionV2(failing, prepared, func() time.Time { return now })
	if !errors.Is(err, ErrReplayUnavailable) || failedAccepted.ReplayCommit.State != "" {
		t.Fatalf("failed commit = %#v, %v", failedAccepted, err)
	}
}

func TestCommitPreparedAssertionV2RejectsExpiryCrossedDuringReplayCommit(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	grant := testVerifiedGrantV2(now)
	statement := testSessionBindingStatementV2(now)
	assertion, err := NewAssertionFromSessionBindingV2(grant, statement, now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareAssertionV2(testCompletePolicyV2(), assertion, statement.Binding, now, testAcceptanceInputsV2(now, nil))
	if err != nil {
		t.Fatal(err)
	}
	cache := &v2RecordingReplayCache{seen: make(map[string]struct{})}
	clockCalls := 0
	clock := func() time.Time {
		clockCalls++
		if clockCalls == 1 {
			return now
		}
		return prepared.Expiry()
	}

	accepted, err := CommitPreparedAssertionV2(cache, prepared, clock)
	if !errors.Is(err, ErrExpiredAssertion) {
		t.Fatalf("CommitPreparedAssertionV2() error = %v, want %v", err, ErrExpiredAssertion)
	}
	if accepted.ReplayCommit.State != "" || len(cache.seen) != 1 {
		t.Fatalf("expired commit returned %#v after %d replay records", accepted, len(cache.seen))
	}
}

func testCompletePolicyV2() PolicyV2 {
	return PolicyV2{
		Mode:    ModeRequired,
		SetMode: SetModeContainsAll,
		Require: RequirementsV2{D3: true, D4: true, D5: true, D6: true, D7: true},
		Expected: Values{
			Service: "document-service", Agent: "agent-a", TaskID: "task-1",
		},
		ExpectedTarget: TargetV2{Resource: "document-api", Operation: "summarize"},
		ExpectedAuthorization: AuthorizationV2{
			CapabilityRef: "cap:summarize", OntologyID: "ontology:documents",
			Scopes: []string{"document:read"}, Resources: []string{"document-records"},
			AuthorizationDetails: []string{"summarize"},
		},
	}
}

func testVerifiedAttestationResultV2(now time.Time, binder string) VerifiedAttestationResultV2 {
	return VerifiedAttestationResultV2{
		ProfileType: "sbaip.attestation-result", ProfileVersion: "2",
		ResultID: "attestation-result-v2-1", Issuer: "attestation-verifier",
		Subject: "agent-a", SignerKeyID: "verifier-key", Audience: "agent-b",
		AppraisalPolicyID: "urn:test:appraisal-policy:v2", BinderSHA256: binder,
		IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(2 * time.Minute),
	}
}
