// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package authorityquorum

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestServiceConsumesTwoOfThreeWithoutLeakingApprovalIdentity(t *testing.T) {
	t.Parallel()
	now := testNow()
	policy := testPolicy(t, now, 2, "authority:a", "authority:b", "authority:c")
	service := testService(policy, now)
	request := testApprovalRequest(policy, 'a')

	first := testAccepted(t, request, "authority:a", "proof:a", now, now.Add(3*time.Minute), policy)
	second := testAccepted(t, request, "authority:b", "proof:b", now, now.Add(2*time.Minute), policy)
	if _, err := service.Approve(context.Background(), request, first); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Approve(context.Background(), request, second); err != nil {
		t.Fatal(err)
	}
	quorum, err := service.Consume(context.Background(), ConsumeRequest{
		ConsumptionID: "consume:1", Binding: request.Binding(),
	})
	if err != nil {
		t.Fatalf("Consume() error = %v", err)
	}
	if quorum.ApprovalCount != 2 || quorum.Threshold != 2 {
		t.Fatalf("approval count/threshold = %d/%d", quorum.ApprovalCount, quorum.Threshold)
	}
	if !quorum.AcceptedUntil.Equal(second.ExpiresAt) {
		t.Fatalf("accepted_until = %s, want %s", quorum.AcceptedUntil, second.ExpiresAt)
	}
	raw, err := json.Marshal(quorum)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"authority:a", "authority:b", "proof:a", "proof:b",
		"authorization:proof:a", "authorization:proof:b", "nonce", "signature", "fragment",
	} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("VerifiedQuorum leaked %q: %s", forbidden, raw)
		}
	}
}

func TestServiceRejectsBelowThresholdAndDuplicateAuthority(t *testing.T) {
	t.Parallel()
	now := testNow()
	policy := testPolicy(t, now, 2, "authority:a", "authority:b", "authority:c")
	service := testService(policy, now)
	request := testApprovalRequest(policy, 'b')
	accepted := testAccepted(t, request, "authority:a", "proof:a", now, now.Add(time.Minute), policy)
	if _, err := service.Approve(context.Background(), request, accepted); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Consume(context.Background(), ConsumeRequest{
		ConsumptionID: "consume:below", Binding: request.Binding(),
	}); !errors.Is(err, ErrBelowThreshold) {
		t.Fatalf("below-threshold error = %v", err)
	}

	// An exact proof retry is idempotent.
	if _, err := service.Approve(context.Background(), request, accepted); err != nil {
		t.Fatalf("exact retry error = %v", err)
	}
	// A new proof from the same logical slot is still only one authority.
	rotated := testAccepted(t, request, "authority:a", "proof:a:rotated", now, now.Add(time.Minute), policy)
	if _, err := service.Approve(context.Background(), request, rotated); !errors.Is(err, ErrAuthorityAlreadyApproved) {
		t.Fatalf("rotation duplicate error = %v", err)
	}
}

func TestApprovalRequiresAuthenticatedBindingAndScopesProofID(t *testing.T) {
	t.Parallel()
	now := testNow()
	policy := testPolicy(t, now, 2, "authority:a", "authority:b")
	request := testApprovalRequest(policy, '8')
	acceptedA := testAccepted(t, request, "authority:a", "proof:shared", now, now.Add(time.Minute), policy)

	mutated := request
	mutated.OperationDigest = testDigest('9')
	if _, err := NewApproval(mutated, acceptedA, now); !errors.Is(err, ErrAuthenticatedBindingMismatch) {
		t.Fatalf("authenticated binding mismatch error = %v", err)
	}

	service := testService(policy, now)
	first, err := service.Approve(context.Background(), request, acceptedA)
	if err != nil {
		t.Fatal(err)
	}
	acceptedB := testAccepted(t, request, "authority:b", "proof:shared", now, now.Add(time.Minute), policy)
	second, err := service.Approve(context.Background(), request, acceptedB)
	if err != nil {
		t.Fatal(err)
	}
	if first.ApprovalID == second.ApprovalID {
		t.Fatalf("independent authorities received the same approval ID %q", first.ApprovalID)
	}
	if _, err := service.Consume(context.Background(), ConsumeRequest{
		ConsumptionID: "consume:shared-proof", Binding: request.Binding(),
	}); err != nil {
		t.Fatalf("consume independent same-JTI approvals: %v", err)
	}
}

func TestDecisionRejectsPrincipalCredentialAndMapRemapping(t *testing.T) {
	t.Parallel()
	now := testNow()
	policy := testPolicy(t, now, 2, "authority:a", "authority:b")
	request := testApprovalRequestWithDecision(policy, 'a', "decision:dedupe")
	service := testService(policy, now)
	first := testAccepted(t, request, "authority:a", "proof:first", now, now.Add(time.Minute), policy)
	if _, err := service.Approve(context.Background(), request, first); err != nil {
		t.Fatal(err)
	}

	sameCredential := testAccepted(t, request, "authority:b", "proof:second", now, now.Add(time.Minute), policy)
	sameCredential.CredentialDigest = first.CredentialDigest
	if _, err := service.Approve(context.Background(), request, sameCredential); !errors.Is(err, ErrCredentialAlreadyApproved) {
		t.Fatalf("credential remap error = %v", err)
	}

	samePrincipal := testAccepted(t, request, "authority:b", "proof:third", now, now.Add(time.Minute), policy)
	samePrincipal.PrincipalDigest = first.PrincipalDigest
	if _, err := service.Approve(context.Background(), request, samePrincipal); !errors.Is(err, ErrPrincipalAlreadyApproved) {
		t.Fatalf("principal remap error = %v", err)
	}

	wrongMap := testAccepted(t, request, "authority:b", "proof:fourth", now, now.Add(time.Minute), policy)
	wrongMap.AuthorityMapDigest = testDigest('e')
	if _, err := service.Approve(context.Background(), request, wrongMap); !errors.Is(err, ErrPolicyMismatch) {
		t.Fatalf("authority-map mismatch error = %v", err)
	}
}

func TestDecisionCannotMixOperationOrPolicy(t *testing.T) {
	t.Parallel()
	now := testNow()
	policy := testPolicy(t, now, 2, "authority:a", "authority:b")
	store := NewMemoryStoreWithClock(func() time.Time { return now })
	originalRequest := testApprovalRequest(policy, 'c')
	original, err := NewApproval(originalRequest, testAccepted(t, originalRequest,
		"authority:a", "proof:original", now, now.Add(time.Minute), policy,
	), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendApproval(context.Background(), policy, original); err != nil {
		t.Fatal(err)
	}

	changedOperation := originalRequest
	changedOperation.OperationDigest = testDigest('d')
	changed, err := NewApproval(changedOperation, testAccepted(t, changedOperation,
		"authority:b", "proof:changed", now, now.Add(time.Minute), policy,
	), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendApproval(context.Background(), policy, changed); !errors.Is(err, ErrDecisionConflict) {
		t.Fatalf("mixed operation error = %v", err)
	}

	rotatedPolicy := testPolicyEpoch(t, now, 2, 2, "authority:a", "authority:b")
	changedPolicyRequest := originalRequest
	changedPolicyRequest.PolicyDigest = rotatedPolicy.PolicyDigest
	changedPolicy, err := NewApproval(changedPolicyRequest, testAccepted(t, changedPolicyRequest,
		"authority:b", "proof:policy-2", now, now.Add(time.Minute), rotatedPolicy,
	), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendApproval(context.Background(), rotatedPolicy, changedPolicy); !errors.Is(err, ErrDecisionConflict) {
		t.Fatalf("mixed policy error = %v", err)
	}
}

func TestConsumeUsesLongestDeterministicThresholdWindow(t *testing.T) {
	t.Parallel()
	now := testNow()
	policy := testPolicy(t, now, 2, "authority:a", "authority:b", "authority:c")
	service := testService(policy, now)
	request := testApprovalRequest(policy, 'e')
	for _, accepted := range []AcceptedAuthority{
		testAccepted(t, request, "authority:a", "proof:a", now, now.Add(time.Minute), policy),
		testAccepted(t, request, "authority:b", "proof:b", now, now.Add(3*time.Minute), policy),
		testAccepted(t, request, "authority:c", "proof:c", now, now.Add(2*time.Minute), policy),
	} {
		if _, err := service.Approve(context.Background(), request, accepted); err != nil {
			t.Fatal(err)
		}
	}
	quorum, err := service.Consume(context.Background(), ConsumeRequest{
		ConsumptionID: "consume:longest", Binding: request.Binding(),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := now.Add(2 * time.Minute)
	if !quorum.AcceptedUntil.Equal(want) {
		t.Fatalf("accepted_until = %s, want %s", quorum.AcceptedUntil, want)
	}
}

func TestExpiryAndRevocationFailClosed(t *testing.T) {
	t.Parallel()
	now := testNow()
	policy := testPolicy(t, now, 1, "authority:a")
	current := now
	store := NewMemoryStoreWithClock(func() time.Time { return current })
	request := testApprovalRequest(policy, 'f')
	approval, err := NewApproval(request, testAccepted(t, request,
		"authority:a", "proof:expiring", now, now.Add(time.Second), policy,
	), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendApproval(context.Background(), policy, approval); err != nil {
		t.Fatal(err)
	}
	current = approval.ExpiresAt
	if _, err := store.ConsumeQuorum(context.Background(), policy, ConsumeRequest{
		ConsumptionID: "consume:expired", Binding: request.Binding(),
	}); !errors.Is(err, ErrBelowThreshold) {
		t.Fatalf("exact-expiry error = %v", err)
	}

	revokedRequest := testApprovalRequest(policy, '1')
	revocation := DecisionRevocation{
		Schema: RevocationSchemaV1, RevocationID: "revoke:before", DecisionID: revokedRequest.DecisionID,
		RevokedAt: now,
	}
	if err := store.RevokeDecision(context.Background(), revocation); err != nil {
		t.Fatal(err)
	}
	revokedApproval, err := NewApproval(revokedRequest, testAccepted(t, revokedRequest,
		"authority:a", "proof:revoked", now, now.Add(time.Minute), policy,
	), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendApproval(context.Background(), policy, revokedApproval); !errors.Is(err, ErrDecisionRevoked) {
		t.Fatalf("approval after revocation error = %v", err)
	}
}

func TestConcurrentConsumeHasOneWinnerAndSameIDIsIdempotent(t *testing.T) {
	t.Parallel()
	now := testNow()
	policy := testPolicy(t, now, 2, "authority:a", "authority:b")
	service := testService(policy, now)
	request := testApprovalRequest(policy, '2')
	for _, authorityID := range policy.AuthorityIDs {
		if _, err := service.Approve(context.Background(), request, testAccepted(t, request,
			authorityID, "proof:"+authorityID, now, now.Add(time.Minute), policy,
		)); err != nil {
			t.Fatal(err)
		}
	}

	const attempts = 16
	start := make(chan struct{})
	results := make(chan error, attempts)
	var wait sync.WaitGroup
	for index := range attempts {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			_, err := service.Consume(context.Background(), ConsumeRequest{
				ConsumptionID: "consume:" + string(rune('a'+index)), Binding: request.Binding(),
			})
			results <- err
		}(index)
	}
	close(start)
	wait.Wait()
	close(results)
	winners := 0
	for err := range results {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, ErrDecisionConsumed):
		default:
			t.Fatalf("concurrent consume error = %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("consume winners = %d, want 1", winners)
	}

	// Separate decision: same consumption ID returns the committed projection.
	current := now
	service = Service{
		Store: NewMemoryStoreWithClock(func() time.Time { return current }),
		Policies: PolicyResolverFunc(func(context.Context, string) (VerifiedPolicy, error) {
			return policy, nil
		}),
		Now: func() time.Time { return current },
	}
	request = testApprovalRequestWithDecision(policy, '3', "decision:idempotent")
	for _, authorityID := range policy.AuthorityIDs {
		_, err := service.Approve(context.Background(), request, testAccepted(t, request,
			authorityID, "proof:idempotent:"+authorityID, now, now.Add(time.Minute), policy,
		))
		if err != nil {
			t.Fatal(err)
		}
	}
	consume := ConsumeRequest{ConsumptionID: "consume:idempotent", Binding: request.Binding()}
	first, err := service.Consume(context.Background(), consume)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Consume(context.Background(), consume)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("idempotent projections differ: %+v / %+v", first, second)
	}
	stored := service.Store.(*MemoryStore)
	current = first.AcceptedUntil
	if _, err := stored.ConsumeQuorum(context.Background(), policy, consume); !errors.Is(err, ErrExpired) {
		t.Fatalf("committed retry at expiry error = %v", err)
	}
}

func TestConcurrentApprovalsCountOneLogicalAuthority(t *testing.T) {
	t.Parallel()
	now := testNow()
	policy := testPolicy(t, now, 2, "authority:a", "authority:b")
	service := testService(policy, now)
	request := testApprovalRequestWithDecision(policy, 'd', "decision:approval-race")

	const attempts = 16
	accepted := make([]AcceptedAuthority, attempts)
	for index := range attempts {
		accepted[index] = testAccepted(
			t, request, "authority:a", "proof:race:"+string(rune('a'+index)),
			now, now.Add(time.Minute), policy,
		)
	}
	start := make(chan struct{})
	results := make(chan error, attempts)
	var wait sync.WaitGroup
	for index := range attempts {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			_, err := service.Approve(context.Background(), request, accepted[index])
			results <- err
		}(index)
	}
	close(start)
	wait.Wait()
	close(results)
	winners := 0
	for err := range results {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, ErrAuthorityAlreadyApproved):
		default:
			t.Fatalf("concurrent approval error = %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("approval winners = %d, want 1", winners)
	}
	if _, err := service.Approve(context.Background(), request, testAccepted(
		t, request, "authority:b", "proof:race:b", now, now.Add(time.Minute), policy,
	)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Consume(context.Background(), ConsumeRequest{
		ConsumptionID: "consume:approval-race", Binding: request.Binding(),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestConsumptionIDIsGlobalAcrossDecisions(t *testing.T) {
	t.Parallel()
	now := testNow()
	policy := testPolicy(t, now, 1, "authority:a")
	service := testService(policy, now)
	firstRequest := testApprovalRequestWithDecision(policy, '4', "decision:first")
	secondRequest := testApprovalRequestWithDecision(policy, '5', "decision:second")
	for _, request := range []ApprovalRequest{firstRequest, secondRequest} {
		if _, err := service.Approve(context.Background(), request, testAccepted(
			t, request, "authority:a", "proof:"+request.DecisionID, now, now.Add(time.Minute), policy,
		)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := service.Consume(context.Background(), ConsumeRequest{
		ConsumptionID: "consume:global", Binding: firstRequest.Binding(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Consume(context.Background(), ConsumeRequest{
		ConsumptionID: "consume:global", Binding: secondRequest.Binding(),
	}); !errors.Is(err, ErrConsumptionConflict) {
		t.Fatalf("cross-decision consumption ID error = %v", err)
	}
}

func TestServiceValidatesRequestBeforePolicyLookup(t *testing.T) {
	t.Parallel()
	called := false
	service := Service{
		Store: NewMemoryStoreWithClock(testNow),
		Policies: PolicyResolverFunc(func(context.Context, string) (VerifiedPolicy, error) {
			called = true
			return VerifiedPolicy{}, errors.New("unexpected policy lookup")
		}),
		Now: testNow,
	}
	invalid := ApprovalRequest{OperationDigest: testDigest('6'), PolicyDigest: testDigest('7')}
	if _, err := service.Approve(context.Background(), invalid, AcceptedAuthority{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid approval request error = %v", err)
	}
	if called {
		t.Fatal("invalid approval request reached policy resolver")
	}
	if _, err := service.Consume(context.Background(), ConsumeRequest{Binding: invalid.Binding()}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid consume request error = %v", err)
	}
	if called {
		t.Fatal("invalid consume request reached policy resolver")
	}
}

func TestServiceResamplesTimeAfterPolicyLookup(t *testing.T) {
	t.Parallel()
	now := testNow()
	policy, err := NewVerifiedPolicy(
		"policy:short", "reveal.example", testDigest('f'), 1, 1, []string{"authority:a"},
		now.Add(-time.Minute), now.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	request := testApprovalRequestWithDecision(policy, 'b', "decision:slow-policy")
	current := now
	service := Service{
		Store: NewMemoryStoreWithClock(func() time.Time { return current }),
		Policies: PolicyResolverFunc(func(context.Context, string) (VerifiedPolicy, error) {
			current = policy.ExpiresAt
			return policy, nil
		}),
		Now: func() time.Time { return current },
	}
	accepted := testAccepted(t, request, "authority:a", "proof:slow", now, now.Add(time.Minute), policy)
	if _, err := service.Approve(context.Background(), request, accepted); !errors.Is(err, ErrExpired) {
		t.Fatalf("delayed policy lookup error = %v", err)
	}
}

func TestMemoryStoreChecksFreshnessAfterTakingCommitLock(t *testing.T) {
	t.Parallel()
	now := testNow()
	policy, err := NewVerifiedPolicy(
		"policy:commit-clock", "reveal.example", testDigest('f'), 1, 1,
		[]string{"authority:a"}, now.Add(-time.Minute), now.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	var clockNanos atomic.Int64
	clockNanos.Store(now.UnixNano())
	store := NewMemoryStoreWithClock(func() time.Time {
		return time.Unix(0, clockNanos.Load()).UTC()
	})
	request := testApprovalRequestWithDecision(policy, 'c', "decision:commit-clock")
	approval, err := NewApproval(
		request,
		testAccepted(t, request, "authority:a", "proof:commit-clock", now, now.Add(time.Minute), policy),
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendApproval(context.Background(), policy, approval); err != nil {
		t.Fatal(err)
	}

	store.mu.Lock()
	started := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		close(started)
		_, consumeErr := store.ConsumeQuorum(context.Background(), policy, ConsumeRequest{
			ConsumptionID: "consume:commit-clock", Binding: request.Binding(),
		})
		result <- consumeErr
	}()
	<-started
	clockNanos.Store(policy.ExpiresAt.UnixNano())
	store.mu.Unlock()
	if err := <-result; !errors.Is(err, ErrExpired) {
		t.Fatalf("commit-time expiry error = %v", err)
	}
}

func TestPolicyValidationAndStrictDecoding(t *testing.T) {
	t.Parallel()
	now := testNow()
	if _, err := NewVerifiedPolicy(
		"policy:duplicate", "reveal.example", testDigest('f'), 1, 1,
		[]string{"authority:a", "authority:a"}, now, now.Add(time.Hour),
	); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("duplicate policy error = %v", err)
	}
	if _, err := NewVerifiedPolicy(
		"policy:threshold", "reveal.example", testDigest('f'), 1, 3,
		[]string{"authority:a", "authority:b"}, now, now.Add(time.Hour),
	); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("impossible threshold error = %v", err)
	}

	policy := testPolicy(t, now, 1, "authority:a")
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeVerifiedPolicy(bytes.NewReader(raw)); err != nil {
		t.Fatalf("valid policy decode error = %v", err)
	}
	unknown := strings.TrimSuffix(string(raw), "}") + `,"unknown":true}`
	if _, err := DecodeVerifiedPolicy(strings.NewReader(unknown)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("unknown field error = %v", err)
	}
	if _, err := DecodeVerifiedPolicy(strings.NewReader(string(raw) + `{}`)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("trailing value error = %v", err)
	}
	duplicate := strings.Replace(string(raw), `"schema":`, `"schema":"duplicate","schema":`, 1)
	if _, err := DecodeVerifiedPolicy(strings.NewReader(duplicate)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("duplicate member error = %v", err)
	}
	invalidUTF8 := append([]byte(`{"schema":"`), 0xff, '}')
	if _, err := DecodeVerifiedPolicy(bytes.NewReader(invalidUTF8)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("UTF-8 error = %v", err)
	}
	oversized := strings.NewReader(strings.Repeat("x", MaxDocumentBytes+1))
	if _, err := DecodeVerifiedPolicy(oversized); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("oversize error = %v", err)
	}
}

func testNow() time.Time {
	return time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
}

func testPolicy(t *testing.T, now time.Time, threshold uint32, authorities ...string) VerifiedPolicy {
	t.Helper()
	return testPolicyEpoch(t, now, threshold, 1, authorities...)
}

func testPolicyEpoch(t *testing.T, now time.Time, threshold uint32, epoch uint64, authorities ...string) VerifiedPolicy {
	t.Helper()
	policy, err := NewVerifiedPolicy(
		"policy:split-knowledge", "reveal.example", testDigest('f'), epoch, threshold, authorities,
		now.Add(-time.Minute), now.Add(10*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func testService(policy VerifiedPolicy, now time.Time) Service {
	return Service{
		Store: NewMemoryStoreWithClock(func() time.Time { return now }),
		Policies: PolicyResolverFunc(func(context.Context, string) (VerifiedPolicy, error) {
			return policy, nil
		}),
		Now: func() time.Time { return now },
	}
}

func testApprovalRequest(policy VerifiedPolicy, fill byte) ApprovalRequest {
	return testApprovalRequestWithDecision(policy, fill, "decision:1")
}

func testApprovalRequestWithDecision(policy VerifiedPolicy, fill byte, decisionID string) ApprovalRequest {
	return ApprovalRequest{
		DecisionID: decisionID, PolicyDigest: policy.PolicyDigest, OperationDigest: testDigest(fill),
	}
}

func testAccepted(
	t *testing.T,
	request ApprovalRequest,
	authorityID, proofID string,
	now, expiresAt time.Time,
	policy VerifiedPolicy,
) AcceptedAuthority {
	t.Helper()
	digest, err := ApprovalDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	return AcceptedAuthority{
		ApprovalDigest: digest, AuthorityMapDigest: policy.AuthorityMapDigest,
		PrincipalDigest:  testDigest(authorityID[len(authorityID)-1]),
		CredentialDigest: testDigest(authorityID[len(authorityID)-1]),
		AuthorityID:      authorityID, AuthorizationID: "authorization:" + proofID,
		ProofIssuer: "issuer:" + authorityID, ProofID: proofID,
		ProofSignerKey: "key:" + authorityID,
		Audience:       policy.Audience, IssuedAt: now.Add(-time.Minute), ExpiresAt: expiresAt,
	}
}

func testDigest(fill byte) string {
	return "sha256:" + strings.Repeat(string(fill), 64)
}
