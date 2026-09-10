//go:build integration

// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package leastprivilegebinding

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/production"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

// TestDurableRedisDelegationRestart requires an isolated TLS/AUTH Redis fixture
// with AOF appendfsync=always and noeviction. The explicit executable restarts
// that fixture using its existing data directory. It must not target a service
// with other clients. No remote address or shell command string is accepted.
func TestDurableRedisDelegationRestart(t *testing.T) {
	durableBindingPlatform(t)
	address := os.Getenv("ASB_REDIS_TEST_ADDR")
	if address == "" {
		t.Skip("set ASB_REDIS_TEST_ADDR for isolated real Redis integration")
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		t.Fatal("Redis integration address must be an explicit loopback IP")
	}
	restart := os.Getenv("ASB_REDIS_TEST_RESTART")
	if !filepath.IsAbs(restart) {
		t.Fatal("ASB_REDIS_TEST_RESTART must name the absolute trusted fixture restart executable")
	}
	password, err := os.ReadFile(os.Getenv("ASB_REDIS_TEST_PASSWORD_FILE"))
	if err != nil {
		t.Fatal("read fixture password file: ", err)
	}
	caPEM, err := os.ReadFile(os.Getenv("ASB_REDIS_TEST_CA"))
	if err != nil {
		t.Fatal("read fixture CA: ", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("invalid fixture CA")
	}
	name := os.Getenv("ASB_REDIS_TEST_SERVER_NAME")
	if name == "" {
		name = "localhost"
	}
	namespace := make([]byte, 16)
	if _, err := rand.Read(namespace); err != nil {
		t.Fatal(err)
	}
	backend := &production.RedisTaskCoordStore{
		RedisSetNXStore: production.RedisSetNXStore{
			Address: address, Password: strings.TrimSpace(string(password)), KeyPrefix: "asb:test:leastprivilege:" + hex.EncodeToString(namespace) + ":",
			TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: name}, OperationTimeout: 5 * time.Second,
		},
		MaxInteractionHistoryBytes: 1 << 20, MaxOutboxBatch: 8, MaxOutboxLease: time.Minute,
	}
	if err := backend.Validate(); err != nil {
		t.Fatal(err)
	}
	f := newBindingFixture(t)
	in, _ := taskCoordInput(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	persistRedisParentFixture(t, ctx, backend, in, f)
	directory := filepath.Join(t.TempDir(), "journal")
	journal, err := lp.CreateDurableStore(directory, 4)
	if err != nil {
		t.Fatal(err)
	}
	uncertain := &uncertainCommitStore{Store: backend}
	r, err := DelegateAndCommit(ctx, in, f.capability, f.key, f.mandate, f.now, journal, uncertain)
	if !errors.Is(err, lp.ErrOutcomeUnknown) || r.State != lp.ExecutionUnknown || uncertain.commits != 1 {
		t.Fatalf("real committed effect did not preserve lost acknowledgment: %+v %d %v", r, uncertain.commits, err)
	}
	if _, err := backend.LoadDelegation(ctx, in.Event.ID); err != nil {
		t.Fatalf("effect was not actually committed before restart: %v", err)
	}
	command := exec.CommandContext(ctx, restart)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("isolated Redis restart failed: %v %s", err, output)
	}
	journal, err = lp.OpenDurableStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DelegateAndCommit(ctx, in, f.capability, f.key, f.mandate, f.now, journal, uncertain); !errors.Is(err, lp.ErrOutcomeUnknown) || uncertain.commits != 1 {
		t.Fatalf("restart retried effect: %d %v", uncertain.commits, err)
	}
	action, err := Action(f.delegation)
	if err != nil {
		t.Fatal(err)
	}
	request := lp.Request{ActorID: f.mandate.ActorID, TaskID: f.mandate.TaskID, Action: action}
	r, err = ReconcileDelegation(ctx, in.Event.ID, f.mandate, request, journal, backend)
	if err != nil || r.State != lp.ExecutionSucceeded || r.EvidenceDigest == "" {
		t.Fatalf("real restart readback failed: %+v %v", r, err)
	}
	parent, err := backend.LoadAssignment(ctx, in.Parent.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	child, err := backend.LoadAssignment(ctx, in.Child.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	if parent.Revision != in.Parent.Revision+1 || child.Revision != 1 || child.ParentAssignmentID != parent.AssignmentID || uncertain.commits != 1 {
		t.Fatalf("restart produced unexpected delegation state: parent=%+v child=%+v commits=%d", parent, child, uncertain.commits)
	}
}

func persistRedisParentFixture(t *testing.T, ctx context.Context, store taskcoord.Store, in Input, f bindingFixture) {
	t.Helper()
	for _, participant := range []taskcoord.Participant{in.Delegator, in.Target} {
		if err := store.RegisterParticipant(ctx, participant); err != nil {
			t.Fatal(err)
		}
	}
	definition := taskcoord.AssignmentDefinition{
		EventID: "offer-parent", AssignmentID: in.Parent.AssignmentID, TaskID: in.Parent.TaskID, ParticipantID: in.Delegator.ParticipantID,
		Role: taskcoord.RoleAssignee, AuthorityDigest: in.Parent.AuthorityDigest, OfferedAt: in.Parent.CreatedAt,
	}
	offerAuth := fixtureAuth(taskcoord.OperationOffer, "owner:1", "service:orchestrator", definition.TaskID, definition.AssignmentID, definition.OfferedAt)
	offerAuth.TargetParticipantID = in.Delegator.ParticipantID
	offer, err := taskcoord.Offer(definition, in.Delegator, offerAuth)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitAssignment(ctx, 0, offer.Assignment, offer.Record); err != nil {
		t.Fatal(err)
	}
	at := definition.OfferedAt.Add(time.Minute)
	accepted, err := taskcoord.Apply(offer.Assignment, taskcoord.Event{
		ID: "accept-parent", Kind: taskcoord.OperationAccept, ExpectedRevision: 1, At: at,
		Auth: fixtureAuth(taskcoord.OperationAccept, in.Delegator.ParticipantID, f.mandate.ActorID, definition.TaskID, definition.AssignmentID, at),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitAssignment(ctx, 1, accepted.Assignment, accepted.Record); err != nil {
		t.Fatal(err)
	}
}
