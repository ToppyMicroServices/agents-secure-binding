// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package production

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

const (
	testRedisWaitCommand = "WAIT"
)

func TestRedisTaskCoordLuaScriptsParseWhenLuaIsAvailable(t *testing.T) {
	t.Parallel()
	lua, err := exec.LookPath("lua")
	if err != nil {
		t.Skip("Lua interpreter is unavailable")
	}
	scripts := []string{
		redisTaskRegisterParticipantScript, redisTaskLookupScript, redisTaskCommitAssignmentScript,
		redisTaskCommitDelegationScript, redisTaskAppendInteractionScript, redisTaskListInteractionsScript,
		redisTaskPollOutboxScript, redisTaskAcknowledgeOutboxScript,
	}
	for index, script := range scripts {
		path := filepath.Join(t.TempDir(), fmt.Sprintf("taskcoord-script-%d.lua", index))
		if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
			t.Fatal(err)
		}
		command := exec.Command(lua, "-e", "assert(loadfile(arg[1])); os.exit(0)", path)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("Lua script %d does not parse: %v: %s", index, err, output)
		}
	}
}

func TestRedisTaskCoordStoreRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()
	validTLS := &tls.Config{ServerName: "redis.test", MinVersion: tls.VersionTLS13}
	tests := []RedisTaskCoordStore{
		{},
		{RedisSetNXStore: RedisSetNXStore{Address: "redis.test:6379", Password: "secret", KeyPrefix: "asb:taskcoord:", TLSConfig: validTLS, OperationTimeout: time.Second}},
		{RedisSetNXStore: RedisSetNXStore{Address: "redis.test:6379", Password: "secret", KeyPrefix: "asb:{unsafe}:", TLSConfig: validTLS, OperationTimeout: time.Second}, MaxInteractionHistoryBytes: 1 << 20, MaxOutboxBatch: 8, MaxOutboxLease: time.Minute},
		{RedisSetNXStore: RedisSetNXStore{Address: "redis.test:6379", KeyPrefix: "asb:taskcoord:", TLSConfig: validTLS, OperationTimeout: time.Second}, MaxInteractionHistoryBytes: 1 << 20, MaxOutboxBatch: 8, MaxOutboxLease: time.Minute},
		{RedisSetNXStore: RedisSetNXStore{Address: "redis.test:6379", Password: "secret", KeyPrefix: "asb:taskcoord:", TLSConfig: validTLS, OperationTimeout: time.Second}, MaxInteractionHistoryBytes: hardMaxInteractionHistoryBytes + 1, MaxOutboxBatch: 8, MaxOutboxLease: time.Minute},
	}
	for index := range tests {
		if err := tests[index].Validate(); !errors.Is(err, taskcoord.ErrStoreUnavailable) {
			t.Fatalf("case %d Validate() error = %v", index, err)
		}
	}
}

func TestRedisTaskCoordKeysShareSlotAndHideIdentifiers(t *testing.T) {
	t.Parallel()
	store := RedisTaskCoordStore{RedisSetNXStore: RedisSetNXStore{KeyPrefix: "asb:taskcoord:"}}
	keys := []string{
		store.taskCoordKey("participant", "human:private"),
		store.taskCoordKey("assignment", "assignment:private"),
		store.taskCoordOutboxKey("data"), store.taskCoordOutboxKey("ready"),
		store.taskCoordReplicationBarrierKey(),
	}
	var slot string
	for _, key := range keys {
		open := strings.IndexByte(key, '{')
		close := strings.IndexByte(key, '}')
		if open < 0 || close <= open || strings.Contains(key, "private") {
			t.Fatalf("unsafe key %q", key)
		}
		if slot == "" {
			slot = key[open+1 : close]
		} else if key[open+1:close] != slot {
			t.Fatalf("keys do not share a cluster slot: %q", keys)
		}
	}
}

func TestTaskOutboxJSONRoundTripPreservesPayloadDigest(t *testing.T) {
	t.Parallel()
	payload := struct {
		Value string `json:"value"`
	}{Value: "bounded"}
	// The helper correctly rejects an unknown payload kind rather than storing
	// an envelope that cannot be verified by consumers.
	if _, _, err := makeTaskOutbox(taskcoord.OutboxEventKind("UNKNOWN"), "event:1", "task:1", "assignment:1", "human:1", time.Now().UTC(), payload); !errors.Is(err, taskcoord.ErrInvalidEvent) {
		t.Fatalf("makeTaskOutbox() error = %v", err)
	}

	raw := `{"delivery_id":"d","lease_id":"l","event_json":"{\"schema\":\"asb.taskcoord-outbox-event/v1\"}"}`
	var delivery redisOutboxDelivery
	if err := decodeTaskValue([]byte(raw), 4096, &delivery); err != nil {
		t.Fatal(err)
	}
	if delivery.EventJSON != `{"schema":"asb.taskcoord-outbox-event/v1"}` {
		t.Fatalf("event_json = %q", delivery.EventJSON)
	}
	encoded, err := json.Marshal(delivery)
	if err != nil || !bytes.Contains(encoded, []byte(`event_json`)) {
		t.Fatalf("encoded delivery = %s, %v", encoded, err)
	}
}

func TestRedisTaskCoordAssignmentAndOutboxOverTLS(t *testing.T) {
	t.Parallel()
	backend := startTaskCoordRedisTLS(t)
	first := backend.store()
	second := backend.store()
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Minute)
	human := taskcoord.Participant{
		Schema: taskcoord.ParticipantSchemaV1, ParticipantID: "human:redis",
		Kind: taskcoord.ParticipantHuman, IdentityRef: "identity:human:redis",
		Status: taskcoord.ParticipantActive, RegisteredAt: base,
	}
	if err := first.RegisterParticipant(ctx, human); err != nil {
		t.Fatal(err)
	}
	if err := second.RegisterParticipant(ctx, human); err != nil {
		t.Fatalf("idempotent RegisterParticipant() error = %v", err)
	}

	offerAt := base.Add(time.Second)
	definition := taskcoord.AssignmentDefinition{
		EventID: "offer:redis", AssignmentID: "assignment:redis", TaskID: "task:redis",
		ParticipantID: human.ParticipantID, Role: taskcoord.RoleAssignee,
		AuthorityDigest: taskRedisDigest("authority"), OfferedAt: offerAt,
	}
	offerAuth := taskRedisAuthorization(taskcoord.OperationOffer, "owner:redis", "gateway:redis", definition.TaskID, definition.AssignmentID, offerAt)
	offerAuth.TargetParticipantID = human.ParticipantID
	offer, err := taskcoord.Offer(definition, human, offerAuth)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.CommitAssignment(ctx, 0, offer.Assignment, offer.Record); err != nil {
		t.Fatal(err)
	}
	if err := second.CommitAssignment(ctx, 0, offer.Assignment, offer.Record); err != nil {
		t.Fatalf("exact CommitAssignment() retry error = %v", err)
	}
	loaded, err := second.LoadAssignment(ctx, definition.AssignmentID)
	if err != nil || !reflect.DeepEqual(loaded, offer.Assignment) {
		t.Fatalf("LoadAssignment() = (%+v, %v)", loaded, err)
	}

	acceptAt := offerAt.Add(time.Second)
	firstAccept, err := taskcoord.Apply(offer.Assignment, taskcoord.Event{
		ID: "accept:redis:first", Kind: taskcoord.OperationAccept, ExpectedRevision: 1, At: acceptAt,
		Auth: taskRedisAuthorization(taskcoord.OperationAccept, human.ParticipantID, "gateway:human", definition.TaskID, definition.AssignmentID, acceptAt),
	})
	if err != nil {
		t.Fatal(err)
	}
	secondAccept, err := taskcoord.Apply(offer.Assignment, taskcoord.Event{
		ID: "accept:redis:second", Kind: taskcoord.OperationAccept, ExpectedRevision: 1, At: acceptAt,
		Auth: taskRedisAuthorization(taskcoord.OperationAccept, human.ParticipantID, "gateway:human", definition.TaskID, definition.AssignmentID, acceptAt),
	})
	if err != nil {
		t.Fatal(err)
	}

	results := make(chan error, 2)
	go func() { results <- first.CommitAssignment(ctx, 1, firstAccept.Assignment, firstAccept.Record) }()
	go func() { results <- second.CommitAssignment(ctx, 1, secondAccept.Assignment, secondAccept.Record) }()
	var successes, conflicts int
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, taskcoord.ErrRevisionConflict):
			conflicts++
		default:
			t.Fatalf("concurrent CommitAssignment() error = %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent commits = %d successes, %d conflicts", successes, conflicts)
	}
	accepted, err := first.LoadAssignment(ctx, definition.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.CommitAssignment(ctx, offer.Assignment.Revision, accepted, accepted.LastTransition); err != nil {
		t.Fatalf("exact non-initial CommitAssignment() retry error = %v", err)
	}
	releaseAt := acceptAt.Add(time.Second)
	release, err := taskcoord.Apply(accepted, taskcoord.Event{
		ID: "release:redis:rewritten", Kind: taskcoord.OperationRelease, ExpectedRevision: accepted.Revision, At: releaseAt,
		Auth: taskRedisAuthorization(taskcoord.OperationRelease, human.ParticipantID, "gateway:human", accepted.TaskID, accepted.AssignmentID, releaseAt),
	})
	if err != nil {
		t.Fatal(err)
	}
	release.Assignment.AuthorityDigest = taskRedisDigest("rewritten-authority")
	if err := first.CommitAssignment(ctx, accepted.Revision, release.Assignment, release.Record); !errors.Is(err, taskcoord.ErrInvalidTransition) {
		t.Fatalf("CommitAssignment(snapshot rewrite) error = %v, want ErrInvalidTransition", err)
	}
	unchanged, err := second.LoadAssignment(ctx, accepted.AssignmentID)
	if err != nil || !reflect.DeepEqual(unchanged, accepted) {
		t.Fatalf("rejected rewrite changed Assignment: (%+v, %v)", unchanged, err)
	}

	deliveries, err := first.PollOutbox(ctx, taskcoord.OutboxPoll{
		ConsumerID: "publisher:redis", LeaseID: "lease:redis:one", Limit: 8, LeaseDuration: time.Minute,
	})
	if err != nil || len(deliveries) != 2 {
		t.Fatalf("PollOutbox() = (%d, %v), want two unique commits", len(deliveries), err)
	}
	seen := make(map[string]struct{}, len(deliveries))
	for _, delivery := range deliveries {
		if err := delivery.Event.Validate(); err != nil {
			t.Fatal(err)
		}
		if _, exists := seen[delivery.Event.EventID]; exists {
			t.Fatalf("duplicate outbox event %q", delivery.Event.EventID)
		}
		seen[delivery.Event.EventID] = struct{}{}
		if err := second.AcknowledgeOutbox(ctx, taskcoord.OutboxAcknowledgement{DeliveryID: delivery.DeliveryID, ConsumerID: "publisher:redis", LeaseID: delivery.LeaseID}); err != nil {
			t.Fatal(err)
		}
	}
	empty, err := second.PollOutbox(ctx, taskcoord.OutboxPoll{
		ConsumerID: "publisher:redis", LeaseID: "lease:redis:two", Limit: 8, LeaseDuration: time.Minute,
	})
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty PollOutbox() = (%d, %v)", len(empty), err)
	}
	backend.assertSingleSlot(t)
}

func TestRedisTaskCoordDelegationAndInteractionOverTLS(t *testing.T) {
	t.Parallel()
	backend := startTaskCoordRedisTLS(t)
	store := backend.store()
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Minute)
	agent := taskcoord.Participant{
		Schema: taskcoord.ParticipantSchemaV1, ParticipantID: "agent:delegator", Kind: taskcoord.ParticipantAgent,
		IdentityRef: "identity:agent:delegator", Status: taskcoord.ParticipantActive, MayDelegate: true, RegisteredAt: base,
	}
	human := taskcoord.Participant{
		Schema: taskcoord.ParticipantSchemaV1, ParticipantID: "human:delegate", Kind: taskcoord.ParticipantHuman,
		IdentityRef: "identity:human:delegate", Status: taskcoord.ParticipantActive, RegisteredAt: base,
	}
	for _, participant := range []taskcoord.Participant{agent, human} {
		if err := store.RegisterParticipant(ctx, participant); err != nil {
			t.Fatal(err)
		}
	}

	offerAt := base.Add(time.Second)
	parentDefinition := taskcoord.AssignmentDefinition{
		EventID: "offer:parent", AssignmentID: "assignment:parent", TaskID: "task:parent",
		ParticipantID: agent.ParticipantID, Role: taskcoord.RoleAssignee,
		AuthorityDigest: taskRedisDigest("parent-authority"), OfferedAt: offerAt,
	}
	offerAuth := taskRedisAuthorization(taskcoord.OperationOffer, "owner:delegation", "gateway:orchestrator", parentDefinition.TaskID, parentDefinition.AssignmentID, offerAt)
	offerAuth.TargetParticipantID = agent.ParticipantID
	parentOffer, err := taskcoord.Offer(parentDefinition, agent, offerAuth)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitAssignment(ctx, 0, parentOffer.Assignment, parentOffer.Record); err != nil {
		t.Fatal(err)
	}
	acceptAt := offerAt.Add(time.Second)
	parentAccept, err := taskcoord.Apply(parentOffer.Assignment, taskcoord.Event{
		ID: "accept:parent", Kind: taskcoord.OperationAccept, ExpectedRevision: 1, At: acceptAt,
		Auth: taskRedisAuthorization(taskcoord.OperationAccept, agent.ParticipantID, "runtime:agent", parentDefinition.TaskID, parentDefinition.AssignmentID, acceptAt),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitAssignment(ctx, 1, parentAccept.Assignment, parentAccept.Record); err != nil {
		t.Fatal(err)
	}

	delegatedAt := acceptAt.Add(time.Second)
	childDefinition := taskcoord.AssignmentDefinition{
		EventID: "offer:child", AssignmentID: "assignment:child", TaskID: "task:child",
		ParticipantID: human.ParticipantID, Role: taskcoord.RoleAssignee,
		AuthorityDigest: taskRedisDigest("child-authority"), ParentAssignmentID: parentAccept.Assignment.AssignmentID,
		OfferedAt: delegatedAt,
	}
	delegateAuth := taskRedisAuthorization(taskcoord.OperationDelegate, agent.ParticipantID, "runtime:agent", parentAccept.Assignment.TaskID, parentAccept.Assignment.AssignmentID, delegatedAt)
	delegateAuth.TargetTaskID = childDefinition.TaskID
	delegateAuth.TargetAssignmentID = childDefinition.AssignmentID
	delegateAuth.TargetParticipantID = childDefinition.ParticipantID
	delegateAuth.Assurance = taskcoord.GatewayAssertedForHumanProvenance()
	delegation, err := taskcoord.Delegate(parentAccept.Assignment, agent, human, childDefinition,
		taskcoord.Event{ID: "delegate:parent-child", Kind: taskcoord.OperationDelegate, ExpectedRevision: parentAccept.Assignment.Revision, At: delegatedAt, Auth: delegateAuth},
		taskcoord.VerifiedDelegation{
			DecisionID: "decision:delegation", ParentAssignmentID: parentAccept.Assignment.AssignmentID,
			ChildAssignmentID: childDefinition.AssignmentID, FromParticipantID: agent.ParticipantID,
			ToParticipantID: human.ParticipantID, ParentAuthorityDigest: parentAccept.Assignment.AuthorityDigest,
			ChildAuthorityDigest: childDefinition.AuthorityDigest, PolicyRef: "policy:delegation",
			EvidenceRef: "evidence:delegation", VerifiedAt: delegatedAt,
		})
	if err != nil {
		t.Fatal(err)
	}
	forgedDelegation := delegation
	forgedDelegation.Parent.AuthorityDigest = taskRedisDigest("forged-parent-authority")
	forgedDelegation.Delegation.ParentAuthorityDigest = forgedDelegation.Parent.AuthorityDigest
	if err := store.CommitDelegation(ctx, parentAccept.Assignment.Revision, forgedDelegation); !errors.Is(err, taskcoord.ErrInvalidTransition) {
		t.Fatalf("CommitDelegation(parent rewrite) error = %v, want ErrInvalidTransition", err)
	}
	if err := store.CommitDelegation(ctx, parentAccept.Assignment.Revision, delegation); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitDelegation(ctx, parentAccept.Assignment.Revision, delegation); err != nil {
		t.Fatalf("exact CommitDelegation() retry error = %v", err)
	}
	child, err := store.LoadAssignment(ctx, childDefinition.AssignmentID)
	if err != nil || child.ParentAssignmentID != parentDefinition.AssignmentID {
		t.Fatalf("LoadAssignment(child) = (%+v, %v)", child, err)
	}
	storedDelegation, err := store.LoadDelegation(ctx, delegation.Delegation.EventID)
	if err != nil || !reflect.DeepEqual(storedDelegation, delegation.Delegation) {
		t.Fatalf("LoadDelegation() = (%+v, %v)", storedDelegation, err)
	}
	if storedDelegation.Assurance == nil ||
		storedDelegation.Assurance.AssuranceLevel != taskcoord.HumanAssuranceGatewayAssertedForHuman {
		t.Fatalf("LoadDelegation() assurance = %#v", storedDelegation.Assurance)
	}
	storedDelegation.Assurance.AssuranceLevel = taskcoord.HumanAssuranceAuthenticatedHumanEvidence
	reloadedDelegation, err := store.LoadDelegation(ctx, delegation.Delegation.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if reloadedDelegation.Assurance == nil ||
		reloadedDelegation.Assurance.AssuranceLevel != taskcoord.HumanAssuranceGatewayAssertedForHuman {
		t.Fatalf("reloaded delegation assurance = %#v", reloadedDelegation.Assurance)
	}

	questionAt := delegatedAt.Add(time.Second)
	questionDef := taskcoord.InteractionEventDefinition{
		EventID: "question:child", InteractionID: "interaction:child", TaskID: child.TaskID,
		AssignmentID: child.AssignmentID, Kind: taskcoord.InteractionQuestion,
		ContentRef: "urn:content:question", ContentDigest: taskRedisDigest("question"), At: questionAt,
	}
	question, err := taskcoord.NewInteractionEvent(questionDef, taskRedisInteractionAuthorization(questionDef, agent.ParticipantID, "runtime:agent"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AppendInteractionEvent(ctx, question); err != nil {
		t.Fatal(err)
	}
	responseAt := questionAt.Add(time.Second)
	responseDef := taskcoord.InteractionEventDefinition{
		EventID: "response:child", InteractionID: question.InteractionID, TaskID: child.TaskID,
		AssignmentID: child.AssignmentID, Kind: taskcoord.InteractionResponse, InReplyTo: question.EventID,
		Finality: taskcoord.ResponseFinal, ContentRef: "urn:content:response", ContentDigest: taskRedisDigest("response"), At: responseAt,
	}
	response, err := taskcoord.NewInteractionEvent(responseDef, taskRedisInteractionAuthorization(responseDef, human.ParticipantID, "gateway:human"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AppendInteractionEvent(ctx, response); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendInteractionEvent(ctx, response); err != nil {
		t.Fatalf("exact AppendInteractionEvent() retry error = %v", err)
	}
	history, err := store.ListInteractionEvents(ctx, question.InteractionID)
	if err != nil || len(history) != 2 || history[0].EventID != question.EventID || history[1].EventID != response.EventID {
		t.Fatalf("ListInteractionEvents() = (%+v, %v)", history, err)
	}
	backend.assertOutboxCount(t, 5)
}

func TestRedisTaskCoordOutboxReclaimsExpiredLeaseAndRejectsStaleAck(t *testing.T) {
	t.Parallel()
	backend := startTaskCoordRedisTLS(t)
	store := backend.store()
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Minute)
	human := taskcoord.Participant{
		Schema: taskcoord.ParticipantSchemaV1, ParticipantID: "human:lease", Kind: taskcoord.ParticipantHuman,
		IdentityRef: "identity:human:lease", Status: taskcoord.ParticipantActive, RegisteredAt: base,
	}
	if err := store.RegisterParticipant(ctx, human); err != nil {
		t.Fatal(err)
	}
	definition := taskcoord.AssignmentDefinition{
		EventID: "offer:lease", AssignmentID: "assignment:lease", TaskID: "task:lease",
		ParticipantID: human.ParticipantID, Role: taskcoord.RoleAssignee,
		AuthorityDigest: taskRedisDigest("lease-authority"), OfferedAt: base.Add(time.Second),
	}
	authorization := taskRedisAuthorization(taskcoord.OperationOffer, "owner:lease", "gateway:lease", definition.TaskID, definition.AssignmentID, definition.OfferedAt)
	authorization.TargetParticipantID = human.ParticipantID
	offer, err := taskcoord.Offer(definition, human, authorization)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitAssignment(ctx, 0, offer.Assignment, offer.Record); err != nil {
		t.Fatal(err)
	}
	first, err := store.PollOutbox(ctx, taskcoord.OutboxPoll{
		ConsumerID: "publisher:first", LeaseID: "lease:first", Limit: 1, LeaseDuration: time.Millisecond,
	})
	if err != nil || len(first) != 1 {
		t.Fatalf("first PollOutbox() = (%+v, %v)", first, err)
	}
	wrongConsumer := taskcoord.OutboxAcknowledgement{
		DeliveryID: first[0].DeliveryID, ConsumerID: "publisher:other", LeaseID: first[0].LeaseID,
	}
	if err := store.AcknowledgeOutbox(ctx, wrongConsumer); !errors.Is(err, taskcoord.ErrOutboxConflict) {
		t.Fatalf("cross-consumer AcknowledgeOutbox() error = %v, want ErrOutboxConflict", err)
	}
	backend.assertOutboxCount(t, 1)
	backend.advance(2 * time.Millisecond)
	oldAck := taskcoord.OutboxAcknowledgement{DeliveryID: first[0].DeliveryID, ConsumerID: "publisher:first", LeaseID: first[0].LeaseID}
	if err := store.AcknowledgeOutbox(ctx, oldAck); !errors.Is(err, taskcoord.ErrOutboxLeaseExpired) {
		t.Fatalf("expired AcknowledgeOutbox() error = %v", err)
	}
	second, err := store.PollOutbox(ctx, taskcoord.OutboxPoll{
		ConsumerID: "publisher:second", LeaseID: "lease:second", Limit: 1, LeaseDuration: time.Minute,
	})
	if err != nil || len(second) != 1 || second[0].DeliveryID != first[0].DeliveryID || second[0].Event.EventID != first[0].Event.EventID {
		t.Fatalf("reclaimed PollOutbox() = (%+v, %v)", second, err)
	}
	if err := store.AcknowledgeOutbox(ctx, oldAck); !errors.Is(err, taskcoord.ErrOutboxConflict) {
		t.Fatalf("stale AcknowledgeOutbox() error = %v", err)
	}
	if err := store.AcknowledgeOutbox(ctx, taskcoord.OutboxAcknowledgement{DeliveryID: second[0].DeliveryID, ConsumerID: "publisher:second", LeaseID: second[0].LeaseID}); err != nil {
		t.Fatal(err)
	}
}

func TestRedisTaskCoordUnknownWAITOutcomeRecoversWithoutDuplicateOutbox(t *testing.T) {
	t.Parallel()
	backend := startTaskCoordRedisTLS(t)
	store := backend.store()
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Minute)
	human := taskcoord.Participant{
		Schema: taskcoord.ParticipantSchemaV1, ParticipantID: "human:wait", Kind: taskcoord.ParticipantHuman,
		IdentityRef: "identity:human:wait", Status: taskcoord.ParticipantActive, RegisteredAt: base,
	}
	if err := store.RegisterParticipant(ctx, human); err != nil {
		t.Fatal(err)
	}
	definition := taskcoord.AssignmentDefinition{
		EventID: "offer:wait", AssignmentID: "assignment:wait", TaskID: "task:wait",
		ParticipantID: human.ParticipantID, Role: taskcoord.RoleAssignee,
		AuthorityDigest: taskRedisDigest("wait-authority"), OfferedAt: base.Add(time.Second),
	}
	authorization := taskRedisAuthorization(taskcoord.OperationOffer, "owner:wait", "gateway:wait", definition.TaskID, definition.AssignmentID, definition.OfferedAt)
	authorization.TargetParticipantID = human.ParticipantID
	offer, err := taskcoord.Offer(definition, human, authorization)
	if err != nil {
		t.Fatal(err)
	}
	backend.setAcknowledgements(0)
	waitsBeforeCommit := backend.waitCount()
	if err := store.CommitAssignment(ctx, 0, offer.Assignment, offer.Record); !errors.Is(err, taskcoord.ErrStoreUnavailable) || !errors.Is(err, ErrRedisReplication) {
		t.Fatalf("CommitAssignment() WAIT error = %v", err)
	}
	if got := backend.waitCount(); got != waitsBeforeCommit+1 {
		t.Fatalf("first commit WAIT count = %d, want %d", got, waitsBeforeCommit+1)
	}
	backend.setAcknowledgements(1)
	if loaded, err := store.LoadAssignment(ctx, offer.Assignment.AssignmentID); err != nil || !reflect.DeepEqual(loaded, offer.Assignment) {
		t.Fatalf("recovery LoadAssignment() = (%+v, %v)", loaded, err)
	}
	if err := store.CommitAssignment(ctx, 0, offer.Assignment, offer.Record); err != nil {
		t.Fatalf("exact recovery CommitAssignment() error = %v", err)
	}
	if got := backend.waitCount(); got != waitsBeforeCommit+2 {
		t.Fatalf("idempotent barrier WAIT count = %d, want %d", got, waitsBeforeCommit+2)
	}
	backend.assertOutboxCount(t, 1)
}

func taskRedisAuthorization(kind taskcoord.OperationKind, participantID, actorID, taskID, assignmentID string, at time.Time) taskcoord.AuthenticatedOperation {
	return taskcoord.AuthenticatedOperation{
		ActorID: actorID, ParticipantID: participantID, AuthorizationID: "authorization:redis",
		ProofID: "proof:redis", Operation: kind, TaskID: taskID, AssignmentID: assignmentID,
		VerifierNonce: "nonce:redis", IssuedAt: at.Add(-time.Second), ExpiresAt: at.Add(time.Minute),
	}
}

func taskRedisDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func taskRedisInteractionAuthorization(def taskcoord.InteractionEventDefinition, participantID, actorID string) taskcoord.AuthenticatedInteraction {
	return taskcoord.AuthenticatedInteraction{
		ActorID: actorID, ParticipantID: participantID, AuthorizationID: "authorization:interaction",
		ProofID: "proof:interaction", EventID: def.EventID, InteractionID: def.InteractionID,
		TaskID: def.TaskID, AssignmentID: def.AssignmentID, Kind: def.Kind, InReplyTo: def.InReplyTo,
		Supersedes: def.Supersedes, Finality: def.Finality, ContentRef: def.ContentRef,
		ContentDigest: def.ContentDigest, EvidenceRef: def.EvidenceRef, At: def.At,
		VerifierNonce: "nonce:interaction", IssuedAt: def.At.Add(-time.Second), ExpiresAt: def.At.Add(time.Minute),
	}
}

type taskCoordRedisLease struct {
	owner    string
	consumer string
	until    time.Time
}

type taskCoordRedisBackend struct {
	t        *testing.T
	listener net.Listener
	tls      *tls.Config
	done     chan struct{}
	wg       sync.WaitGroup

	mu       sync.Mutex
	values   map[string]string
	outbox   map[string]string
	ready    []string
	leases   map[string]taskCoordRedisLease
	lists    map[string][]string
	keys     []string
	serveErr error
	now      time.Time
	acks     int
	waits    int
}

func startTaskCoordRedisTLS(t *testing.T) *taskCoordRedisBackend {
	t.Helper()
	certificate, roots := testRedisCertificate(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	backend := &taskCoordRedisBackend{
		t: t, listener: listener, tls: &tls.Config{RootCAs: roots, ServerName: "redis.test", MinVersion: tls.VersionTLS13},
		done: make(chan struct{}), values: make(map[string]string), outbox: make(map[string]string),
		leases: make(map[string]taskCoordRedisLease), lists: make(map[string][]string), now: time.Now().UTC(), acks: 1,
	}
	go backend.serve()
	t.Cleanup(func() {
		_ = listener.Close()
		<-backend.done
		backend.mu.Lock()
		defer backend.mu.Unlock()
		if backend.serveErr != nil {
			t.Errorf("TaskCoord Redis test server: %v", backend.serveErr)
		}
	})
	return backend
}

func (b *taskCoordRedisBackend) store() *RedisTaskCoordStore {
	return &RedisTaskCoordStore{
		RedisSetNXStore: RedisSetNXStore{
			Address: b.listener.Addr().String(), Password: "taskcoord-secret", KeyPrefix: "asb:test:taskcoord:",
			TLSConfig: b.tls.Clone(), OperationTimeout: 5 * time.Second,
			RequiredReplicaAcknowledgements: 1, ReplicationTimeout: time.Second,
		},
		MaxInteractionHistoryBytes: 1 << 20, MaxOutboxBatch: 8, MaxOutboxLease: time.Hour,
	}
}

func (b *taskCoordRedisBackend) serve() {
	defer close(b.done)
	for {
		connection, err := b.listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				b.recordError(err)
			}
			break
		}
		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			defer connection.Close()
			if err := b.handle(connection); err != nil {
				b.recordError(err)
			}
		}()
	}
	b.wg.Wait()
}

func (b *taskCoordRedisBackend) handle(connection net.Conn) error {
	reader := bufio.NewReader(connection)
	authentication, err := readTaskCoordRESPArray(reader)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(authentication, []string{"AUTH", "taskcoord-secret"}) {
		return fmt.Errorf("unexpected AUTH: %q", authentication)
	}
	if _, err := io.WriteString(connection, "+OK\r\n"); err != nil {
		return err
	}
	command, err := readTaskCoordRESPArray(reader)
	if err != nil {
		return err
	}
	response, wrote, err := b.evaluate(command)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(connection, "$%d\r\n%s\r\n", len(response), response); err != nil {
		return err
	}
	if !wrote {
		return nil
	}
	wait, err := readTaskCoordRESPArray(reader)
	if err != nil {
		return err
	}
	if len(wait) != 3 || wait[0] != testRedisWaitCommand || wait[1] != "1" {
		return fmt.Errorf("unexpected WAIT: %q", wait)
	}
	b.mu.Lock()
	acknowledgements := b.acks
	b.waits++
	b.mu.Unlock()
	_, err = fmt.Fprintf(connection, ":%d\r\n", acknowledgements)
	return err
}

func (b *taskCoordRedisBackend) evaluate(command []string) (string, bool, error) {
	if len(command) < 4 || command[0] != "EVAL" {
		return "", false, fmt.Errorf("unexpected command: %q", command)
	}
	keyCount, err := strconv.Atoi(command[2])
	if err != nil || keyCount < 1 || 3+keyCount > len(command) {
		return "", false, fmt.Errorf("invalid EVAL command: %q", command)
	}
	keys := command[3 : 3+keyCount]
	arguments := command[3+keyCount:]
	b.mu.Lock()
	defer b.mu.Unlock()
	b.keys = append(b.keys, keys...)
	switch command[1] {
	case redisTaskRegisterParticipantScript:
		return b.register(keys, arguments)
	case redisTaskLookupScript:
		return b.lookup(keys)
	case redisTaskCommitAssignmentScript:
		return b.commitAssignment(keys, arguments)
	case redisTaskCommitDelegationScript:
		return b.commitDelegation(keys, arguments)
	case redisTaskAppendInteractionScript:
		return b.appendInteraction(keys, arguments)
	case redisTaskListInteractionsScript:
		return b.listInteractions(keys, arguments)
	case redisTaskPollOutboxScript:
		return b.poll(arguments)
	case redisTaskAcknowledgeOutboxScript:
		return b.acknowledge(arguments)
	default:
		return "", false, errors.New("unsupported TaskCoord test script")
	}
}

func (b *taskCoordRedisBackend) register(keys, arguments []string) (string, bool, error) {
	if len(keys) != 2 || len(arguments) != 1 {
		return "", false, errors.New("invalid register")
	}
	if existing, ok := b.values[keys[0]]; ok {
		if existing == arguments[0] {
			b.values[keys[1]] = strconv.FormatInt(b.now.UnixMilli(), 10)
			return redisTaskStatusIdempotentBarrier, true, nil
		}
		return redisTaskStatusAlreadyExists, false, nil
	}
	b.values[keys[0]] = arguments[0]
	return redisTaskStatusRegistered, true, nil
}

func (b *taskCoordRedisBackend) lookup(keys []string) (string, bool, error) {
	if len(keys) != 1 {
		return "", false, errors.New("invalid lookup")
	}
	value, ok := b.values[keys[0]]
	if !ok {
		return redisTaskStatusNotFound, false, nil
	}
	return "FOUND\n" + value, false, nil
}

func (b *taskCoordRedisBackend) commitAssignment(keys, arguments []string) (string, bool, error) {
	if len(keys) != 5 || len(arguments) != 6 {
		return "", false, errors.New("invalid assignment commit")
	}
	if existing, ok := b.values[keys[1]]; ok {
		if existing == arguments[2] {
			b.values[keys[4]] = strconv.FormatInt(b.now.UnixMilli(), 10)
			return redisTaskStatusIdempotentBarrier, true, nil
		}
		return redisTaskStatusEventConflict, false, nil
	}
	expected, err := strconv.ParseUint(arguments[0], 10, 64)
	if err != nil {
		return redisJournalStatusCorrupt, false, nil
	}
	var next taskcoord.Assignment
	if err := json.Unmarshal([]byte(arguments[1]), &next); err != nil || next.Revision != expected+1 {
		return redisJournalStatusCorrupt, false, nil
	}
	currentRaw, exists := b.values[keys[0]]
	if expected == 0 {
		if exists {
			return redisTaskStatusAlreadyExists, false, nil
		}
	} else {
		var current taskcoord.Assignment
		if !exists || json.Unmarshal([]byte(currentRaw), &current) != nil || current.Revision != expected {
			return redisTaskStatusRevisionConflict, false, nil
		}
		if currentRaw != arguments[5] {
			return redisTaskStatusRevisionConflict, false, nil
		}
	}
	b.values[keys[0]] = arguments[1]
	b.values[keys[1]] = arguments[2]
	b.outbox[arguments[3]] = arguments[4]
	b.ready = append(b.ready, arguments[3])
	return redisJournalStatusCreated, true, nil
}

func (b *taskCoordRedisBackend) commitDelegation(keys, arguments []string) (string, bool, error) {
	if len(keys) != 8 || len(arguments) != 9 {
		return "", false, errors.New("invalid delegation commit")
	}
	parentEvent, parentSeen := b.values[keys[2]]
	childEvent, childSeen := b.values[keys[3]]
	if parentSeen || childSeen {
		if parentEvent == arguments[3] && childEvent == arguments[4] && b.values[keys[4]] == arguments[5] {
			b.values[keys[7]] = strconv.FormatInt(b.now.UnixMilli(), 10)
			return redisTaskStatusIdempotentBarrier, true, nil
		}
		return redisTaskStatusEventConflict, false, nil
	}
	expected, err := strconv.ParseUint(arguments[0], 10, 64)
	if err != nil {
		return redisJournalStatusCorrupt, false, nil
	}
	var parent, child taskcoord.Assignment
	if json.Unmarshal([]byte(arguments[1]), &parent) != nil || json.Unmarshal([]byte(arguments[2]), &child) != nil ||
		parent.Revision != expected+1 || child.Revision != 1 {
		return redisJournalStatusCorrupt, false, nil
	}
	currentRaw := b.values[keys[0]]
	var current taskcoord.Assignment
	if json.Unmarshal([]byte(currentRaw), &current) != nil || current.Revision != expected {
		return redisTaskStatusRevisionConflict, false, nil
	}
	if currentRaw != arguments[8] {
		return redisTaskStatusRevisionConflict, false, nil
	}
	if _, exists := b.values[keys[1]]; exists {
		return redisTaskStatusAlreadyExists, false, nil
	}
	if _, exists := b.values[keys[4]]; exists {
		return redisTaskStatusAlreadyExists, false, nil
	}
	b.values[keys[0]] = arguments[1]
	b.values[keys[1]] = arguments[2]
	b.values[keys[2]] = arguments[3]
	b.values[keys[3]] = arguments[4]
	b.values[keys[4]] = arguments[5]
	b.outbox[arguments[6]] = arguments[7]
	b.ready = append(b.ready, arguments[6])
	return redisJournalStatusCreated, true, nil
}

func (b *taskCoordRedisBackend) appendInteraction(keys, arguments []string) (string, bool, error) {
	if len(keys) != 11 || len(arguments) != 5 {
		return "", false, errors.New("invalid interaction append")
	}
	if existing, ok := b.values[keys[2]]; ok {
		if existing == arguments[1] {
			b.values[keys[10]] = strconv.FormatInt(b.now.UnixMilli(), 10)
			return redisTaskStatusIdempotentBarrier, true, nil
		}
		return redisTaskStatusEventConflict, false, nil
	}
	var event taskcoord.InteractionEvent
	var assignment taskcoord.Assignment
	var participant taskcoord.Participant
	if json.Unmarshal([]byte(arguments[0]), &event) != nil || json.Unmarshal([]byte(b.values[keys[0]]), &assignment) != nil ||
		json.Unmarshal([]byte(b.values[keys[1]]), &participant) != nil {
		return redisTaskStatusNotFound, false, nil
	}
	var reply, superseded *taskcoord.InteractionEvent
	if event.InReplyTo != "" {
		var loaded taskcoord.InteractionEvent
		if json.Unmarshal([]byte(b.values[keys[4]]), &loaded) != nil {
			return redisTaskStatusInvalidInteraction, false, nil
		}
		reply = &loaded
	}
	if event.Supersedes != "" {
		var loaded taskcoord.InteractionEvent
		if json.Unmarshal([]byte(b.values[keys[5]]), &loaded) != nil {
			return redisTaskStatusInvalidInteraction, false, nil
		}
		superseded = &loaded
	}
	if err := taskcoord.ValidateInteractionAppend(event, assignment, participant, reply, superseded); err != nil {
		return redisTaskStatusInvalidInteraction, false, nil
	}
	if event.Kind == taskcoord.InteractionQuestion && event.InReplyTo == "" && len(b.lists[keys[6]]) != 0 {
		return redisTaskStatusInvalidInteraction, false, nil
	}
	maxBytes, _ := strconv.Atoi(arguments[4])
	currentBytes, _ := strconv.Atoi(b.values[keys[7]])
	if currentBytes+len(arguments[0]) > maxBytes {
		return redisTaskStatusLimitReached, false, nil
	}
	b.values[keys[2]] = arguments[1]
	b.values[keys[3]] = arguments[0]
	b.values[keys[7]] = strconv.Itoa(currentBytes + len(arguments[0]))
	b.lists[keys[6]] = append(b.lists[keys[6]], keys[3])
	b.outbox[arguments[2]] = arguments[3]
	b.ready = append(b.ready, arguments[2])
	return redisTaskStatusAppended, true, nil
}

func (b *taskCoordRedisBackend) listInteractions(keys, arguments []string) (string, bool, error) {
	if len(keys) != 1 || len(arguments) != 1 {
		return "", false, errors.New("invalid interaction list")
	}
	ids := b.lists[keys[0]]
	if len(ids) == 0 {
		return redisTaskStatusNotFound, false, nil
	}
	maxBytes, _ := strconv.Atoi(arguments[0])
	total := 0
	events := make([]json.RawMessage, 0, len(ids))
	for _, id := range ids {
		raw, ok := b.values[id]
		if !ok {
			return redisJournalStatusCorrupt, false, nil
		}
		total += len(raw)
		if total > maxBytes {
			return redisTaskStatusLimitReached, false, nil
		}
		events = append(events, json.RawMessage(raw))
	}
	raw, err := json.Marshal(events)
	if err != nil {
		return "", false, err
	}
	return "FOUND\n" + string(raw), false, nil
}

func (b *taskCoordRedisBackend) poll(arguments []string) (string, bool, error) {
	if len(arguments) != 4 {
		return "", false, errors.New("invalid poll")
	}
	limit, err := strconv.Atoi(arguments[2])
	if err != nil || limit < 1 {
		return redisJournalStatusCorrupt, false, nil
	}
	leaseMillis, err := strconv.ParseInt(arguments[3], 10, 64)
	if err != nil || leaseMillis < 1 {
		return redisJournalStatusCorrupt, false, nil
	}
	now := b.now
	for deliveryID, lease := range b.leases {
		if !lease.until.After(now) {
			delete(b.leases, deliveryID)
			b.ready = append(b.ready, deliveryID)
		}
	}
	if len(b.ready) == 0 {
		return redisTaskStatusEmpty, false, nil
	}
	if limit > len(b.ready) {
		limit = len(b.ready)
	}
	selected := append([]string(nil), b.ready[:limit]...)
	b.ready = append([]string(nil), b.ready[limit:]...)
	deliveries := make([]redisOutboxDelivery, 0, len(selected))
	for _, deliveryID := range selected {
		raw, ok := b.outbox[deliveryID]
		if !ok {
			return redisJournalStatusCorrupt, false, nil
		}
		b.leases[deliveryID] = taskCoordRedisLease{
			owner: arguments[0], consumer: arguments[1], until: now.Add(time.Duration(leaseMillis) * time.Millisecond),
		}
		deliveries = append(deliveries, redisOutboxDelivery{DeliveryID: deliveryID, LeaseID: arguments[0], EventJSON: raw})
	}
	raw, err := json.Marshal(deliveries)
	if err != nil {
		return "", false, err
	}
	return "CLAIMED\n" + string(raw), true, nil
}

func (b *taskCoordRedisBackend) acknowledge(arguments []string) (string, bool, error) {
	if len(arguments) != 3 {
		return "", false, errors.New("invalid acknowledgement")
	}
	lease, ok := b.leases[arguments[0]]
	if !ok || lease.owner != arguments[1] || lease.consumer != arguments[2] {
		return "OUTBOX_CONFLICT", false, nil
	}
	if !lease.until.After(b.now) {
		return "LEASE_EXPIRED", false, nil
	}
	delete(b.leases, arguments[0])
	delete(b.outbox, arguments[0])
	return redisTaskStatusAcked, true, nil
}

func (b *taskCoordRedisBackend) assertSingleSlot(t *testing.T) {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	var slot string
	for _, key := range b.keys {
		open := strings.IndexByte(key, '{')
		close := strings.IndexByte(key, '}')
		if open < 0 || close <= open {
			t.Fatalf("key lacks hash slot: %q", key)
		}
		if slot == "" {
			slot = key[open+1 : close]
		} else if key[open+1:close] != slot {
			t.Fatalf("keys use different hash slots")
		}
	}
}

func (b *taskCoordRedisBackend) assertOutboxCount(t *testing.T, want int) {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if got := len(b.outbox); got != want {
		t.Fatalf("outbox entries = %d, want %d", got, want)
	}
}

func (b *taskCoordRedisBackend) advance(duration time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.now = b.now.Add(duration)
}

func (b *taskCoordRedisBackend) setAcknowledgements(value int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.acks = value
}

func (b *taskCoordRedisBackend) waitCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.waits
}

func (b *taskCoordRedisBackend) recordError(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.serveErr == nil {
		b.serveErr = err
	}
}

func readTaskCoordRESPArray(reader *bufio.Reader) ([]string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if len(line) < 4 || line[0] != '*' || !strings.HasSuffix(line, "\r\n") {
		return nil, errors.New("invalid array")
	}
	count, err := strconv.Atoi(strings.TrimSuffix(line[1:], "\r\n"))
	if err != nil || count < 1 || count > 64 {
		return nil, errors.New("invalid array count")
	}
	values := make([]string, count)
	for index := range values {
		lengthLine, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if len(lengthLine) < 4 || lengthLine[0] != '$' || !strings.HasSuffix(lengthLine, "\r\n") {
			return nil, errors.New("invalid bulk length")
		}
		length, err := strconv.Atoi(strings.TrimSuffix(lengthLine[1:], "\r\n"))
		if err != nil || length < 0 || length > 4<<20 {
			return nil, errors.New("invalid bulk length")
		}
		payload := make([]byte, length+2)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return nil, err
		}
		if payload[length] != '\r' || payload[length+1] != '\n' {
			return nil, errors.New("invalid bulk terminator")
		}
		values[index] = string(payload[:length])
	}
	return values, nil
}
