// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package leastprivilege_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
)

const (
	testBroadGrant       = "broad"
	testAdminPermission  = "admin"
	testDeniedPermission = "denied"
)

type authorizationFixture struct {
	config   lp.AuthorizerConfig
	request  lp.Request
	solution lp.Solution
	public   ed25519.PublicKey
	now      time.Time
}

func newAuthorizationFixture(t *testing.T) authorizationFixture {
	t.Helper()
	now := time.Date(2026, time.September, 9, 12, 0, 0, 0, time.UTC)
	problem := lp.Problem{
		Schema: lp.ProblemSchemaV1,
		Permissions: []lp.Permission{
			{ID: "read", Cost: 1},
			{ID: "write", Cost: 3},
			{ID: testAdminPermission, Cost: 20},
			{ID: testDeniedPermission, Cost: 100},
		},
		Grants: []lp.Grant{
			{ID: "narrow", Permissions: []string{"read"}},
			{ID: testBroadGrant, Permissions: []string{"read", "write"}},
		},
		Required:          []string{"read"},
		Allowed:           []string{"read", "write", testAdminPermission},
		Implications:      []lp.Implication{{AllOf: []string{"write"}, Then: []string{testAdminPermission}}},
		ForbiddenTogether: [][]string{{"read", testDeniedPermission}},
	}
	request := lp.Request{ActorID: "agent-1", TaskID: "task-1", Action: lp.Action{
		Operation: "storage:GetObject", Resource: "storage://reports/one.json", Arguments: []byte(`{"version":"1"}`),
	}}
	problemDigest, err := lp.DigestProblem(problem)
	if err != nil {
		t.Fatal(err)
	}
	actionDigest, err := lp.DigestAction(request.Action)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	solution, err := lp.Solve(context.Background(), problem, 4)
	if err != nil {
		t.Fatal(err)
	}
	return authorizationFixture{
		config: lp.AuthorizerConfig{
			Problem: problem, SigningKey: private, MaxEvaluations: 4,
			Clock: func() time.Time { return now },
			Mandate: lp.Mandate{
				ID: "mandate-1", PolicyRef: "policy://reports/v1", ActorID: request.ActorID, TaskID: request.TaskID,
				ActionDigest: actionDigest, ProblemDigest: problemDigest,
				NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
				MaxTTLSeconds: 30, AllowAutomatic: true,
			},
		},
		request: request, solution: solution, public: public, now: now,
	}
}

func (f authorizationFixture) authorizer(t *testing.T) *lp.Authorizer {
	t.Helper()
	a, err := lp.NewAuthorizer(f.config)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (f authorizationFixture) issue(t *testing.T) lp.Capability {
	t.Helper()
	capability, err := f.authorizer(t).Authorize(context.Background(), f.request, f.solution)
	if err != nil {
		t.Fatal(err)
	}
	return capability
}

func requireAuthorizationError(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("error = %v, want %v", got, want)
	}
}

func requireNoCapability(t *testing.T, capability lp.Capability) {
	t.Helper()
	if !reflect.DeepEqual(capability, lp.Capability{}) {
		t.Fatalf("failed authorization returned a capability: %+v", capability.Claims)
	}
}

func TestAuthorizationLifecycle(t *testing.T) {
	f := newAuthorizationFixture(t)
	capability := f.issue(t)
	if !reflect.DeepEqual(capability.Claims.Solution, f.solution) {
		t.Fatal("issued capability does not bind the verified solution")
	}
	if !capability.Claims.IssuedAt.Equal(f.now) || !capability.Claims.ExpiresAt.Equal(f.now.Add(30*time.Second)) {
		t.Fatalf("unexpected lifetime: %v..%v", capability.Claims.IssuedAt, capability.Claims.ExpiresAt)
	}
	if err := lp.CheckCapability(capability, f.public, f.config.Mandate, f.request, f.now); err != nil {
		t.Fatal(err)
	}
	store, err := lp.NewMemoryUseStore(1)
	if err != nil {
		t.Fatal(err)
	}
	// Read-only checking does not consume the mandate, even when repeated.
	if err := lp.CheckCapability(capability, f.public, f.config.Mandate, f.request, f.now); err != nil {
		t.Fatal(err)
	}
	if err := lp.ConsumeCapability(context.Background(), capability, f.public, f.config.Mandate, f.request, f.now, store); err != nil {
		t.Fatal(err)
	}
	requireAuthorizationError(t, lp.ConsumeCapability(context.Background(), capability, f.public, f.config.Mandate, f.request, f.now, store), lp.ErrReplay)
	if digest, err := lp.DigestCapability(capability); err != nil || !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("evidence digest = %q, %v", digest, err)
	}
}

func TestOptimalSolutionDoesNotOverrideHumanApproval(t *testing.T) {
	f := newAuthorizationFixture(t)
	f.config.Mandate.AllowAutomatic = false
	capability, err := f.authorizer(t).Authorize(context.Background(), f.request, f.solution)
	requireAuthorizationError(t, err, lp.ErrHumanRequired)
	requireNoCapability(t, capability)
}

func TestAuthorizationRejectsUnverifiedCandidates(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*authorizationFixture)
		want   error
	}{
		{"nonoptimal", func(f *authorizationFixture) {
			f.solution.Grants = []string{testBroadGrant}
			f.solution.Effective = []string{testAdminPermission, "read", "write"}
			f.solution.Cost = 24
		}, lp.ErrNotOptimal},
		{"forged_cost", func(f *authorizationFixture) { f.solution.Cost = 0 }, lp.ErrInvalidSolution},
		{"forged_grant", func(f *authorizationFixture) { f.solution.Grants = []string{"administrator"} }, lp.ErrInvalidSolution},
		{"forged_effective", func(f *authorizationFixture) { f.solution.Effective = []string{"write"} }, lp.ErrInvalidSolution},
		{"wrong_problem", func(f *authorizationFixture) { f.solution.ProblemDigest = "sha256:" + strings.Repeat("0", 64) }, lp.ErrInvalidSolution},
		{"verification_budget", func(f *authorizationFixture) { f.config.MaxEvaluations = 1 }, lp.ErrLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAuthorizationFixture(t)
			tc.mutate(&f)
			capability, err := f.authorizer(t).Authorize(context.Background(), f.request, f.solution)
			requireAuthorizationError(t, err, tc.want)
			requireNoCapability(t, capability)
		})
	}
}

func TestAuthorizationBindsExactRequest(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*lp.Request)
	}{
		{"actor", func(r *lp.Request) { r.ActorID = "agent-2" }},
		{"task", func(r *lp.Request) { r.TaskID = "task-2" }},
		{"operation", func(r *lp.Request) { r.Action.Operation = "storage:DeleteObject" }},
		{"resource", func(r *lp.Request) { r.Action.Resource = "storage://reports/two.json" }},
		{"arguments", func(r *lp.Request) { r.Action.Arguments = []byte(`{"version":"2"}`) }},
		{"argument_whitespace", func(r *lp.Request) { r.Action.Arguments = []byte(`{ "version":"1"}`) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAuthorizationFixture(t)
			a := f.authorizer(t)
			capability := f.issue(t)
			tc.mutate(&f.request)
			got, err := a.Authorize(context.Background(), f.request, f.solution)
			requireAuthorizationError(t, err, lp.ErrBinding)
			requireNoCapability(t, got)
			requireAuthorizationError(t, lp.CheckCapability(capability, f.public, f.config.Mandate, f.request, f.now), lp.ErrBinding)
		})
	}
}

func TestCapabilityRejectsTampering(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*lp.Capability)
	}{
		{"signature", func(c *lp.Capability) { c.Signature[0] ^= 1 }},
		{"missing_signature", func(c *lp.Capability) { c.Signature = nil }},
		{"schema", func(c *lp.Capability) { c.Claims.Schema = "untrusted/v1" }},
		{"id", func(c *lp.Capability) { c.Claims.ID = strings.Repeat("f", 64) }},
		{"mandate", func(c *lp.Capability) { c.Claims.MandateID += "-2" }},
		{"policy", func(c *lp.Capability) { c.Claims.PolicyRef += "-2" }},
		{"actor", func(c *lp.Capability) { c.Claims.ActorID += "-2" }},
		{"task", func(c *lp.Capability) { c.Claims.TaskID += "-2" }},
		{"action", func(c *lp.Capability) { c.Claims.ActionDigest = "sha256:" + strings.Repeat("0", 64) }},
		{"expiry", func(c *lp.Capability) { c.Claims.ExpiresAt = c.Claims.ExpiresAt.Add(time.Second) }},
		{"issued_at", func(c *lp.Capability) { c.Claims.IssuedAt = c.Claims.IssuedAt.Add(-time.Second) }},
		{"grants", func(c *lp.Capability) { c.Claims.Solution.Grants[0] = testBroadGrant }},
		{"effective", func(c *lp.Capability) { c.Claims.Solution.Effective[0] = testAdminPermission }},
		{"cost", func(c *lp.Capability) { c.Claims.Solution.Cost++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAuthorizationFixture(t)
			capability := f.issue(t)
			tc.mutate(&capability)
			requireAuthorizationError(t, lp.CheckCapability(capability, f.public, f.config.Mandate, f.request, f.now), lp.ErrInvalidCapability)
		})
	}
	f := newAuthorizationFixture(t)
	capability := f.issue(t)
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, public := range []ed25519.PublicKey{nil, make([]byte, 31), otherPublic} {
		requireAuthorizationError(t, lp.CheckCapability(capability, public, f.config.Mandate, f.request, f.now), lp.ErrInvalidCapability)
	}
}

func TestCapabilityEnforcesCurrentMandate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*lp.Mandate)
		want   error
	}{
		{"revoked_automatic", func(m *lp.Mandate) { m.AllowAutomatic = false }, lp.ErrHumanRequired},
		{"new_id", func(m *lp.Mandate) { m.ID = "mandate-2" }, lp.ErrBinding},
		{"policy_changed", func(m *lp.Mandate) { m.PolicyRef = "policy://reports/v2" }, lp.ErrBinding},
		{"problem_changed", func(m *lp.Mandate) { m.ProblemDigest = "sha256:" + strings.Repeat("0", 64) }, lp.ErrBinding},
		{"ttl_reduced", func(m *lp.Mandate) { m.MaxTTLSeconds-- }, lp.ErrBinding},
		{"expiry_reduced", func(m *lp.Mandate) { m.ExpiresAt = m.ExpiresAt.Add(-time.Second) }, lp.ErrBinding},
		{"missing_mandate", func(m *lp.Mandate) { *m = lp.Mandate{} }, lp.ErrInvalidMandate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAuthorizationFixture(t)
			capability := f.issue(t)
			current := f.config.Mandate
			tc.mutate(&current)
			requireAuthorizationError(t, lp.CheckCapability(capability, f.public, current, f.request, f.now), tc.want)
		})
	}
}

func TestAuthorizationTimeBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		offset time.Duration
	}{
		{"before_mandate", -2 * time.Minute},
		{"at_mandate_expiry", time.Minute},
		{"after_mandate_expiry", 2 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAuthorizationFixture(t)
			f.config.Clock = func() time.Time { return f.now.Add(tc.offset) }
			capability, err := f.authorizer(t).Authorize(context.Background(), f.request, f.solution)
			requireAuthorizationError(t, err, lp.ErrExpired)
			requireNoCapability(t, capability)
		})
	}
	f := newAuthorizationFixture(t)
	capability := f.issue(t)
	for _, now := range []time.Time{{}, f.now.Add(-time.Nanosecond), capability.Claims.ExpiresAt, f.config.Mandate.ExpiresAt} {
		requireAuthorizationError(t, lp.CheckCapability(capability, f.public, f.config.Mandate, f.request, now), lp.ErrExpired)
	}
	if err := lp.CheckCapability(capability, f.public, f.config.Mandate, f.request, capability.Claims.ExpiresAt.Add(-time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorizationRechecksClockAfterVerification(t *testing.T) {
	for _, tc := range []struct {
		name    string
		advance time.Duration
		wantTTL time.Duration
		wantErr error
	}{
		{"updated_issuance", 20 * time.Second, 30 * time.Second, nil},
		{"expiry_clamped", 50 * time.Second, 10 * time.Second, nil},
		{"expires_during_verification", time.Minute, 0, lp.ErrExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAuthorizationFixture(t)
			calls := 0
			f.config.Clock = func() time.Time {
				calls++
				if calls == 1 {
					return f.now
				}
				return f.now.Add(tc.advance)
			}
			capability, err := f.authorizer(t).Authorize(context.Background(), f.request, f.solution)
			if tc.wantErr != nil {
				requireAuthorizationError(t, err, tc.wantErr)
				requireNoCapability(t, capability)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if calls != 2 || !capability.Claims.IssuedAt.Equal(f.now.Add(tc.advance)) || capability.Claims.ExpiresAt.Sub(capability.Claims.IssuedAt) != tc.wantTTL {
				t.Fatalf("clock calls = %d, lifetime = %v..%v", calls, capability.Claims.IssuedAt, capability.Claims.ExpiresAt)
			}
		})
	}
}

func TestReissuedCapabilitiesShareSingleUseMandate(t *testing.T) {
	f := newAuthorizationFixture(t)
	a := f.authorizer(t)
	first, err := a.Authorize(context.Background(), f.request, f.solution)
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.Authorize(context.Background(), f.request, f.solution)
	if err != nil {
		t.Fatal(err)
	}
	if first.Claims.ID == second.Claims.ID {
		t.Fatal("reissued capabilities share an ID")
	}
	store, err := lp.NewMemoryUseStore(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := lp.ConsumeCapability(context.Background(), first, f.public, f.config.Mandate, f.request, f.now, store); err != nil {
		t.Fatal(err)
	}
	// A fresh capability after the original expires must not reset execution use.
	f.config.Clock = func() time.Time { return f.now.Add(31 * time.Second) }
	third := f.issue(t)
	for _, capability := range []lp.Capability{second, third} {
		requireAuthorizationError(t, lp.ConsumeCapability(context.Background(), capability, f.public, f.config.Mandate, f.request, capability.Claims.IssuedAt, store), lp.ErrReplay)
	}
}

func TestConcurrentCapabilityConsumptionAllowsOne(t *testing.T) {
	f := newAuthorizationFixture(t)
	capability := f.issue(t)
	store, err := lp.NewMemoryUseStore(1)
	if err != nil {
		t.Fatal(err)
	}
	const callers = 32
	var successes atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	failures := make(chan error, callers)
	for range callers {
		wg.Go(func() {
			<-start
			err := lp.ConsumeCapability(context.Background(), capability, f.public, f.config.Mandate, f.request, f.now, store)
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, lp.ErrReplay) {
				failures <- err
			}
		})
	}
	close(start)
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Errorf("unexpected consumption error: %v", err)
	}
	if got := successes.Load(); got != 1 {
		t.Fatalf("successful concurrent consumptions = %d, want 1", got)
	}
}

func TestMemoryUseStoreDoesNotEvictLiveUse(t *testing.T) {
	store, err := lp.NewMemoryUseStore(1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.September, 9, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(time.Minute)
	if err := store.Use(context.Background(), "a", expiry, now); err != nil {
		t.Fatal(err)
	}
	requireAuthorizationError(t, store.Use(context.Background(), "b", expiry, now), lp.ErrCapacity)
	requireAuthorizationError(t, store.Use(context.Background(), "a", expiry, now), lp.ErrReplay)
	if err := store.Use(context.Background(), "b", expiry.Add(time.Minute), expiry); err != nil {
		t.Fatalf("expired record should release capacity: %v", err)
	}
}

func TestMemoryUseStoreRejectsReplayAfterClockRollback(t *testing.T) {
	f := newAuthorizationFixture(t)
	capability := f.issue(t)
	store, err := lp.NewMemoryUseStore(2)
	if err != nil {
		t.Fatal(err)
	}
	if err := lp.ConsumeCapability(context.Background(), capability, f.public, f.config.Mandate, f.request, f.now, store); err != nil {
		t.Fatal(err)
	}
	// A later legitimate use reclaims the expired mandate record.
	later := f.config.Mandate.ExpiresAt.Add(time.Second)
	if err := store.Use(context.Background(), "later-mandate", later.Add(time.Minute), later); err != nil {
		t.Fatal(err)
	}
	// The wall clock moves backward into the original capability's validity.
	// Reclaimed consumption history must not permit that operation again.
	err = lp.ConsumeCapability(context.Background(), capability, f.public, f.config.Mandate, f.request, f.now, store)
	if err == nil {
		t.Fatal("clock rollback admitted an already-consumed mandate after cleanup")
	}
}

func TestMemoryUseStoreAcceptsOutOfOrderLiveRequests(t *testing.T) {
	store, err := lp.NewMemoryUseStore(2)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.September, 9, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(time.Minute)
	// Concurrent callers can capture timestamps in one order and acquire the
	// store lock in another. Neither request has expired or been consumed.
	if err := store.Use(context.Background(), "later-request", expiry, now.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := store.Use(context.Background(), "earlier-request", expiry, now); err != nil {
		t.Fatalf("out-of-order live request rejected without any pruned history: %v", err)
	}
}

func TestAuthorizationCancellation(t *testing.T) {
	for _, cancelAt := range []int{0, 1, 2} {
		t.Run([]string{"before_authorization", "before_verification", "after_verification"}[cancelAt], func(t *testing.T) {
			f := newAuthorizationFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			f.config.Clock = func() time.Time {
				calls++
				if calls == cancelAt {
					cancel()
				}
				return f.now
			}
			if cancelAt == 0 {
				cancel()
			}
			capability, err := f.authorizer(t).Authorize(ctx, f.request, f.solution)
			requireAuthorizationError(t, err, context.Canceled)
			requireNoCapability(t, capability)
		})
	}
	f := newAuthorizationFixture(t)
	capability := f.issue(t)
	store, err := lp.NewMemoryUseStore(1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	requireAuthorizationError(t, lp.ConsumeCapability(ctx, capability, f.public, f.config.Mandate, f.request, f.now, store), context.Canceled)
	requireAuthorizationError(t, store.Use(ctx, "cancelled", f.config.Mandate.ExpiresAt, f.now), context.Canceled)
	if err := lp.ConsumeCapability(context.Background(), capability, f.public, f.config.Mandate, f.request, f.now, store); err != nil {
		t.Fatalf("cancelled attempt consumed or filled the store: %v", err)
	}
}

func TestAuthorizerRejectsInvalidConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*lp.AuthorizerConfig)
		want   error
	}{
		{"nil_key", func(c *lp.AuthorizerConfig) { c.SigningKey = nil }, lp.ErrInvalidMandate},
		{"short_key", func(c *lp.AuthorizerConfig) { c.SigningKey = c.SigningKey[:32] }, lp.ErrInvalidMandate},
		{"long_key", func(c *lp.AuthorizerConfig) { c.SigningKey = append(c.SigningKey, 0) }, lp.ErrInvalidMandate},
		{"inconsistent_key", func(c *lp.AuthorizerConfig) { c.SigningKey[63] ^= 1 }, lp.ErrInvalidMandate},
		{"zero_budget", func(c *lp.AuthorizerConfig) { c.MaxEvaluations = 0 }, lp.ErrLimit},
		{"bad_problem", func(c *lp.AuthorizerConfig) { c.Problem.Schema = "invalid" }, lp.ErrInvalidProblem},
		{"wrong_problem_digest", func(c *lp.AuthorizerConfig) { c.Mandate.ProblemDigest = "sha256:" + strings.Repeat("0", 64) }, lp.ErrBinding},
		{"empty_mandate_id", func(c *lp.AuthorizerConfig) { c.Mandate.ID = "" }, lp.ErrInvalidMandate},
		{"invalid_actor", func(c *lp.AuthorizerConfig) { c.Mandate.ActorID += "\n" }, lp.ErrInvalidMandate},
		{"invalid_digest", func(c *lp.AuthorizerConfig) { c.Mandate.ActionDigest = "SHA256:" + strings.Repeat("0", 64) }, lp.ErrInvalidMandate},
		{"zero_not_before", func(c *lp.AuthorizerConfig) { c.Mandate.NotBefore = time.Time{} }, lp.ErrInvalidMandate},
		{"empty_lifetime", func(c *lp.AuthorizerConfig) { c.Mandate.ExpiresAt = c.Mandate.NotBefore }, lp.ErrInvalidMandate},
		{"zero_ttl", func(c *lp.AuthorizerConfig) { c.Mandate.MaxTTLSeconds = 0 }, lp.ErrInvalidMandate},
		{"excess_ttl", func(c *lp.AuthorizerConfig) { c.Mandate.MaxTTLSeconds = 3601 }, lp.ErrInvalidMandate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAuthorizationFixture(t)
			tc.mutate(&f.config)
			a, err := lp.NewAuthorizer(f.config)
			requireAuthorizationError(t, err, tc.want)
			if a != nil {
				t.Fatal("invalid configuration returned an authorizer")
			}
		})
	}
	f := newAuthorizationFixture(t)
	f.config.Clock = nil
	if _, err := lp.NewAuthorizer(f.config); err != nil {
		t.Fatalf("default clock should be accepted: %v", err)
	}
}

func TestAuthorizerOwnsCallerInputs(t *testing.T) {
	f := newAuthorizationFixture(t)
	a := f.authorizer(t)
	originalMandate := f.config.Mandate
	// Mutate every nested input collection after construction.
	f.config.Problem.Permissions[0].Cost = 999
	f.config.Problem.Grants[0].ID = "changed"
	f.config.Problem.Grants[0].Permissions[0] = testDeniedPermission
	f.config.Problem.Required[0] = testDeniedPermission
	f.config.Problem.Allowed[0] = testDeniedPermission
	f.config.Problem.Implications[0].AllOf[0] = "read"
	f.config.Problem.Implications[0].Then[0] = testDeniedPermission
	f.config.Problem.ForbiddenTogether[0][1] = "write"
	f.config.Mandate.AllowAutomatic = false
	for i := range f.config.SigningKey {
		f.config.SigningKey[i] = 0
	}
	capability, err := a.Authorize(context.Background(), f.request, f.solution)
	if err != nil {
		t.Fatalf("caller mutation changed the trusted snapshot: %v", err)
	}
	if err := lp.CheckCapability(capability, f.public, originalMandate, f.request, f.now); err != nil {
		t.Fatalf("caller signing-key mutation affected issuance: %v", err)
	}
	// Mutating the candidate after issuance cannot alter the signed result.
	f.solution.Grants[0] = testBroadGrant
	f.solution.Effective[0] = testAdminPermission
	if err := lp.CheckCapability(capability, f.public, originalMandate, f.request, f.now); err != nil {
		t.Fatalf("candidate shares storage with the signed claims: %v", err)
	}
}

func TestAuthorizerSnapshotsCandidateBeforeVerification(t *testing.T) {
	f := newAuthorizationFixture(t)
	want := f.solution
	want.Grants = append([]string(nil), want.Grants...)
	want.Effective = append([]string(nil), want.Effective...)
	calls := 0
	f.config.Clock = func() time.Time {
		calls++
		if calls == 2 {
			// This callback runs after Verify. It deterministically models the
			// caller reusing its candidate buffers before issuance completes.
			f.solution.Grants[0] = testBroadGrant
			f.solution.Effective[0] = testAdminPermission
		}
		return f.now
	}
	capability, err := f.authorizer(t).Authorize(context.Background(), f.request, f.solution)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(capability.Claims.Solution, want) {
		t.Fatal("authorizer signed caller-mutated candidate contents after verification")
	}
	if err := lp.Verify(context.Background(), f.config.Problem, capability.Claims.Solution, 4); err != nil {
		t.Fatalf("issued candidate does not independently verify: %v", err)
	}
}

func TestAuthorizationInvalidInputsDoNotPanic(t *testing.T) {
	f := newAuthorizationFixture(t)
	var nilAuthorizer *lp.Authorizer
	capability, err := nilAuthorizer.Authorize(context.Background(), f.request, f.solution)
	requireAuthorizationError(t, err, lp.ErrInvalidMandate)
	requireNoCapability(t, capability)
	var zeroAuthorizer lp.Authorizer
	capability, err = zeroAuthorizer.Authorize(context.Background(), f.request, f.solution)
	requireAuthorizationError(t, err, lp.ErrInvalidMandate)
	requireNoCapability(t, capability)
	capability, err = f.authorizer(t).Authorize(nil, f.request, f.solution)
	requireAuthorizationError(t, err, lp.ErrInvalidMandate)
	requireNoCapability(t, capability)
	capability = f.issue(t)
	store, err := lp.NewMemoryUseStore(1)
	if err != nil {
		t.Fatal(err)
	}
	requireAuthorizationError(t, lp.ConsumeCapability(nil, capability, f.public, f.config.Mandate, f.request, f.now, store), lp.ErrInvalidCapability)
	requireAuthorizationError(t, lp.ConsumeCapability(context.Background(), capability, f.public, f.config.Mandate, f.request, f.now, nil), lp.ErrInvalidCapability)
	var nilStore *lp.MemoryUseStore
	requireAuthorizationError(t, nilStore.Use(context.Background(), "a", f.config.Mandate.ExpiresAt, f.now), lp.ErrInvalidCapability)
	for _, capacity := range []int{-1, 0, 1_000_001} {
		_, err := lp.NewMemoryUseStore(capacity)
		requireAuthorizationError(t, err, lp.ErrCapacity)
	}
	requireAuthorizationError(t, store.Use(nil, "a", f.config.Mandate.ExpiresAt, f.now), lp.ErrInvalidCapability)
	requireAuthorizationError(t, store.Use(context.Background(), "", f.config.Mandate.ExpiresAt, f.now), lp.ErrInvalidCapability)
	requireAuthorizationError(t, store.Use(context.Background(), "a", f.now, f.now), lp.ErrExpired)
}

func TestActionDigestPreservesExactBytes(t *testing.T) {
	f := newAuthorizationFixture(t)
	original := bytes.Clone(f.request.Action.Arguments)
	before, err := lp.DigestAction(f.request.Action)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, f.request.Action.Arguments) {
		t.Fatal("digest mutated caller arguments")
	}
	f.request.Action.Arguments[0] ^= 1
	after, err := lp.DigestAction(f.request.Action)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("digest failed to bind argument bytes")
	}
	for _, mutate := range []func(*lp.Action){
		func(a *lp.Action) { a.Operation = "" },
		func(a *lp.Action) { a.Resource = " resource" },
		func(a *lp.Action) { a.Arguments = make([]byte, (64<<10)+1) },
	} {
		action := f.request.Action
		mutate(&action)
		_, err := lp.DigestAction(action)
		requireAuthorizationError(t, err, lp.ErrBinding)
	}
}
