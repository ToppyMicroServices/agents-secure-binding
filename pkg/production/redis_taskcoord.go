// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package production

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

const (
	redisTaskEventSchema                  = "urn:asb:taskcoord:redis:event:v1"
	maxRedisTaskValueBytes                = taskcoord.MaxDocumentBytes
	hardMaxInteractionHistoryBytes        = 16 << 20
	hardMaxOutboxBatch             uint16 = 32
	hardMaxOutboxLease                    = 24 * time.Hour
	maxRedisTaskReplyOverhead             = 64 << 10
)

// RedisTaskCoordStore is a shared Redis/Valkey TaskCoord Store with a
// transactional domain-event outbox. Each mutation and its outbox insert run
// in one Lua execution, and every key shares one namespace hash slot.
//
// Durable keys do not expire. Deployments must use noeviction and an explicit
// archival policy. WAIT acknowledgement reduces failover loss but does not
// make asynchronous Redis replication linearizable or zero-loss.
type RedisTaskCoordStore struct {
	RedisSetNXStore
	MaxInteractionHistoryBytes int
	MaxOutboxBatch             uint16
	MaxOutboxLease             time.Duration
}

var (
	_ taskcoord.Store       = (*RedisTaskCoordStore)(nil)
	_ taskcoord.OutboxStore = (*RedisTaskCoordStore)(nil)
)

type redisTaskEvent struct {
	Schema        string                    `json:"schema"`
	Kind          taskcoord.OutboxEventKind `json:"kind"`
	AssignmentID  string                    `json:"assignment_id"`
	Revision      uint64                    `json:"revision"`
	PayloadDigest string                    `json:"payload_digest"`
}

type redisTaskReply struct {
	status  string
	payload string
}

type redisOutboxDelivery struct {
	DeliveryID string `json:"delivery_id"`
	LeaseID    string `json:"lease_id"`
	EventJSON  string `json:"event_json"`
}

// Validate checks local safety and resource-bound configuration without
// dialing Redis.
func (s *RedisTaskCoordStore) Validate() error {
	return s.validateTaskCoordConfig()
}

func (s *RedisTaskCoordStore) RegisterParticipant(ctx context.Context, participant taskcoord.Participant) error {
	if err := participant.Validate(); err != nil {
		return err
	}
	raw, err := marshalTaskValue(participant)
	if err != nil {
		return err
	}
	reply, err := s.runTaskCoordScript(ctx, redisTaskRegisterParticipantScript,
		[]string{
			s.taskCoordKey("participant", participant.ParticipantID),
			s.taskCoordReplicationBarrierKey(),
		}, []string{string(raw)}, maxRedisTaskValueBytes+128)
	if err != nil {
		return err
	}
	return taskCoordStatusError(reply.status)
}

func (s *RedisTaskCoordStore) LoadParticipant(ctx context.Context, participantID string) (taskcoord.Participant, error) {
	var participant taskcoord.Participant
	if err := s.loadTaskValue(ctx, "participant", participantID, &participant); err != nil {
		return taskcoord.Participant{}, err
	}
	if participant.ParticipantID != participantID {
		return taskcoord.Participant{}, taskcoord.ErrStoreUnavailable
	}
	if err := participant.Validate(); err != nil {
		return taskcoord.Participant{}, fmt.Errorf("%w: invalid stored participant", taskcoord.ErrStoreUnavailable)
	}
	return participant, nil
}

func (s *RedisTaskCoordStore) LoadAssignment(ctx context.Context, assignmentID string) (taskcoord.Assignment, error) {
	var assignment taskcoord.Assignment
	if err := s.loadTaskValue(ctx, "assignment", assignmentID, &assignment); err != nil {
		return taskcoord.Assignment{}, err
	}
	if assignment.AssignmentID != assignmentID {
		return taskcoord.Assignment{}, taskcoord.ErrStoreUnavailable
	}
	if err := assignment.Validate(); err != nil {
		return taskcoord.Assignment{}, fmt.Errorf("%w: invalid stored assignment", taskcoord.ErrStoreUnavailable)
	}
	return assignment, nil
}

func (s *RedisTaskCoordStore) LoadDelegation(ctx context.Context, eventID string) (taskcoord.DelegationRecord, error) {
	var delegation taskcoord.DelegationRecord
	if err := s.loadTaskValue(ctx, "delegation", eventID, &delegation); err != nil {
		return taskcoord.DelegationRecord{}, err
	}
	if delegation.EventID != eventID {
		return taskcoord.DelegationRecord{}, taskcoord.ErrStoreUnavailable
	}
	if err := delegation.Validate(); err != nil {
		return taskcoord.DelegationRecord{}, fmt.Errorf("%w: invalid stored delegation", taskcoord.ErrStoreUnavailable)
	}
	return delegation, nil
}

func (s *RedisTaskCoordStore) LoadInteractionEvent(ctx context.Context, eventID string) (taskcoord.InteractionEvent, error) {
	var event taskcoord.InteractionEvent
	if err := s.loadTaskValue(ctx, "interaction", eventID, &event); err != nil {
		return taskcoord.InteractionEvent{}, err
	}
	if event.EventID != eventID {
		return taskcoord.InteractionEvent{}, taskcoord.ErrStoreUnavailable
	}
	if err := event.Validate(); err != nil {
		return taskcoord.InteractionEvent{}, fmt.Errorf("%w: invalid stored interaction", taskcoord.ErrStoreUnavailable)
	}
	return event, nil
}

func (s *RedisTaskCoordStore) ListInteractionEvents(ctx context.Context, interactionID string) ([]taskcoord.InteractionEvent, error) {
	if strings.TrimSpace(interactionID) == "" || len(interactionID) > 256 {
		return nil, taskcoord.ErrInvalidInteraction
	}
	maxReply := s.MaxInteractionHistoryBytes + maxRedisTaskReplyOverhead
	reply, err := s.runTaskCoordScript(ctx, redisTaskListInteractionsScript,
		[]string{s.taskCoordKey("interaction-order", interactionID)},
		[]string{strconv.Itoa(s.MaxInteractionHistoryBytes)}, maxReply)
	if err != nil {
		return nil, err
	}
	if err := taskCoordStatusError(reply.status); err != nil {
		return nil, err
	}
	var events []taskcoord.InteractionEvent
	if err := decodeTaskValue([]byte(reply.payload), maxReply, &events); err != nil || len(events) == 0 {
		return nil, taskcoord.ErrStoreUnavailable
	}
	for _, event := range events {
		if event.InteractionID != interactionID || event.Validate() != nil {
			return nil, taskcoord.ErrStoreUnavailable
		}
	}
	return events, nil
}

func (s *RedisTaskCoordStore) CommitAssignment(ctx context.Context, expectedRevision uint64, next taskcoord.Assignment, record taskcoord.TransitionRecord) error {
	if expectedRevision > maxSafeJSONInteger || next.Revision > maxSafeJSONInteger {
		return taskcoord.ErrInvalidTransition
	}
	if err := taskcoord.ValidateAssignmentCommit(expectedRevision, next, record); err != nil {
		return err
	}
	if expectedRevision != 0 && record.Kind == taskcoord.OperationDelegate {
		return fmt.Errorf("%w: delegation requires CommitDelegation", taskcoord.ErrInvalidTransition)
	}
	var expectedCurrentRaw []byte
	if expectedRevision != 0 {
		current, err := s.LoadAssignment(ctx, next.AssignmentID)
		switch {
		case err == nil && current.Revision == expectedRevision:
			if err := taskcoord.ValidateAssignmentTransition(current, next, record); err != nil {
				return err
			}
			expectedCurrentRaw, err = marshalTaskValue(current)
			if err != nil {
				return err
			}
		case err == nil:
			// Preserve exact event-id retries. The Lua transaction checks the
			// committed event before returning a revision conflict.
		case errors.Is(err, taskcoord.ErrNotFound):
			// The Lua transaction returns a revision conflict unless this is an
			// exact retry of an already committed event.
		default:
			return err
		}
	}
	payload := taskcoord.Transition{Assignment: next, Record: record}
	outbox, outboxRaw, err := makeTaskOutbox(taskcoord.OutboxAssignmentTransition, record.EventID,
		next.TaskID, next.AssignmentID, next.ParticipantID, record.At, payload)
	if err != nil {
		return err
	}
	nextRaw, err := marshalTaskValue(next)
	if err != nil {
		return err
	}
	eventRaw, err := marshalTaskValue(redisTaskEvent{
		Schema: redisTaskEventSchema, Kind: outbox.Kind, AssignmentID: next.AssignmentID,
		Revision: next.Revision, PayloadDigest: outbox.PayloadDigest,
	})
	if err != nil {
		return err
	}
	deliveryID := taskOutboxDeliveryID(record.EventID)
	reply, err := s.runTaskCoordScript(ctx, redisTaskCommitAssignmentScript,
		[]string{
			s.taskCoordKey("assignment", next.AssignmentID), s.taskCoordKey("event", record.EventID),
			s.taskCoordOutboxKey("data"), s.taskCoordOutboxKey("ready"), s.taskCoordReplicationBarrierKey(),
		},
		[]string{strconv.FormatUint(expectedRevision, 10), string(nextRaw), string(eventRaw), deliveryID, string(outboxRaw), string(expectedCurrentRaw)},
		maxRedisTaskValueBytes+128)
	if err != nil {
		return err
	}
	return taskCoordStatusError(reply.status)
}

func (s *RedisTaskCoordStore) CommitDelegation(ctx context.Context, expectedParentRevision uint64, transition taskcoord.DelegationTransition) error {
	if expectedParentRevision > maxSafeJSONInteger || transition.Parent.Revision > maxSafeJSONInteger || transition.Child.Revision > maxSafeJSONInteger {
		return taskcoord.ErrInvalidTransition
	}
	if err := taskcoord.ValidateDelegationCommit(expectedParentRevision, transition); err != nil {
		return err
	}
	var expectedParentRaw []byte
	currentParent, err := s.LoadAssignment(ctx, transition.Parent.AssignmentID)
	switch {
	case err == nil && currentParent.Revision == expectedParentRevision:
		if err := taskcoord.ValidateAssignmentTransition(currentParent, transition.Parent, transition.ParentRecord); err != nil {
			return err
		}
		expectedParentRaw, err = marshalTaskValue(currentParent)
		if err != nil {
			return err
		}
	case err == nil:
		// Preserve exact retries; Lua verifies both event records and the
		// delegation edge before acknowledging them.
	case errors.Is(err, taskcoord.ErrNotFound):
		// Lua reports a revision conflict unless an exact event retry exists.
	default:
		return err
	}
	outbox, outboxRaw, err := makeTaskOutbox(taskcoord.OutboxDelegationCommitted, transition.Delegation.EventID,
		transition.Child.TaskID, transition.Child.AssignmentID, transition.Child.ParticipantID,
		transition.Delegation.At, transition)
	if err != nil {
		return err
	}
	parentRaw, err := marshalTaskValue(transition.Parent)
	if err != nil {
		return err
	}
	childRaw, err := marshalTaskValue(transition.Child)
	if err != nil {
		return err
	}
	delegationRaw, err := marshalTaskValue(transition.Delegation)
	if err != nil {
		return err
	}
	parentEventRaw, err := marshalTaskValue(redisTaskEvent{
		Schema: redisTaskEventSchema, Kind: outbox.Kind, AssignmentID: transition.Parent.AssignmentID,
		Revision: transition.Parent.Revision, PayloadDigest: outbox.PayloadDigest,
	})
	if err != nil {
		return err
	}
	childPayload, err := json.Marshal(taskcoord.Transition{Assignment: transition.Child, Record: transition.ChildRecord})
	if err != nil {
		return fmt.Errorf("%w: encode child transition", taskcoord.ErrStoreUnavailable)
	}
	childDigest := sha256.Sum256(childPayload)
	childEventRaw, err := marshalTaskValue(redisTaskEvent{
		Schema: redisTaskEventSchema, Kind: taskcoord.OutboxAssignmentTransition,
		AssignmentID: transition.Child.AssignmentID, Revision: transition.Child.Revision,
		PayloadDigest: hex.EncodeToString(childDigest[:]),
	})
	if err != nil {
		return err
	}
	reply, err := s.runTaskCoordScript(ctx, redisTaskCommitDelegationScript,
		[]string{
			s.taskCoordKey("assignment", transition.Parent.AssignmentID),
			s.taskCoordKey("assignment", transition.Child.AssignmentID),
			s.taskCoordKey("event", transition.ParentRecord.EventID),
			s.taskCoordKey("event", transition.ChildRecord.EventID),
			s.taskCoordKey("delegation", transition.Delegation.EventID),
			s.taskCoordOutboxKey("data"), s.taskCoordOutboxKey("ready"), s.taskCoordReplicationBarrierKey(),
		},
		[]string{
			strconv.FormatUint(expectedParentRevision, 10), string(parentRaw), string(childRaw), string(parentEventRaw),
			string(childEventRaw), string(delegationRaw), taskOutboxDeliveryID(transition.Delegation.EventID), string(outboxRaw), string(expectedParentRaw),
		}, maxRedisTaskValueBytes+128)
	if err != nil {
		return err
	}
	return taskCoordStatusError(reply.status)
}

func (s *RedisTaskCoordStore) AppendInteractionEvent(ctx context.Context, event taskcoord.InteractionEvent) error {
	if err := event.Validate(); err != nil {
		return err
	}
	assignment, err := s.LoadAssignment(ctx, event.AssignmentID)
	if err != nil {
		return err
	}
	participant, err := s.LoadParticipant(ctx, event.ParticipantID)
	if err != nil {
		return err
	}
	var replyTarget, superseded *taskcoord.InteractionEvent
	if event.InReplyTo != "" {
		loaded, err := s.LoadInteractionEvent(ctx, event.InReplyTo)
		if err != nil {
			return err
		}
		replyTarget = &loaded
	}
	if event.Supersedes != "" {
		loaded, err := s.LoadInteractionEvent(ctx, event.Supersedes)
		if err != nil {
			return err
		}
		superseded = &loaded
	}
	if err := taskcoord.ValidateInteractionAppend(event, assignment, participant, replyTarget, superseded); err != nil {
		return err
	}
	outbox, outboxRaw, err := makeTaskOutbox(taskcoord.OutboxInteractionAppended, event.EventID,
		event.TaskID, event.AssignmentID, event.ParticipantID, event.At, event)
	if err != nil {
		return err
	}
	eventRaw, err := marshalTaskValue(event)
	if err != nil {
		return err
	}
	commitRaw, err := marshalTaskValue(redisTaskEvent{
		Schema: redisTaskEventSchema, Kind: outbox.Kind, AssignmentID: event.AssignmentID,
		PayloadDigest: outbox.PayloadDigest,
	})
	if err != nil {
		return err
	}
	replyKey := s.taskCoordKey("none", "reply")
	if event.InReplyTo != "" {
		replyKey = s.taskCoordKey("interaction", event.InReplyTo)
	}
	supersededKey := s.taskCoordKey("none", "superseded")
	if event.Supersedes != "" {
		supersededKey = s.taskCoordKey("interaction", event.Supersedes)
	}
	reply, err := s.runTaskCoordScript(ctx, redisTaskAppendInteractionScript,
		[]string{
			s.taskCoordKey("assignment", event.AssignmentID), s.taskCoordKey("participant", event.ParticipantID),
			s.taskCoordKey("event", event.EventID), s.taskCoordKey("interaction", event.EventID),
			replyKey, supersededKey, s.taskCoordKey("interaction-order", event.InteractionID),
			s.taskCoordKey("interaction-bytes", event.InteractionID),
			s.taskCoordOutboxKey("data"), s.taskCoordOutboxKey("ready"),
			s.taskCoordReplicationBarrierKey(),
		},
		[]string{string(eventRaw), string(commitRaw), taskOutboxDeliveryID(event.EventID), string(outboxRaw), strconv.Itoa(s.MaxInteractionHistoryBytes)},
		maxRedisTaskValueBytes+128)
	if err != nil {
		return err
	}
	return taskCoordStatusError(reply.status)
}

func (s *RedisTaskCoordStore) PollOutbox(ctx context.Context, poll taskcoord.OutboxPoll) ([]taskcoord.OutboxDelivery, error) {
	if err := poll.Validate(); err != nil {
		return nil, err
	}
	if poll.Limit > s.MaxOutboxBatch || poll.LeaseDuration > s.MaxOutboxLease {
		return nil, fmt.Errorf("%w: outbox poll exceeds store bounds", taskcoord.ErrInvalidEvent)
	}
	maxReply := int(poll.Limit)*(taskcoord.MaxOutboxPayloadBytes+maxRedisTaskReplyOverhead) + maxRedisTaskReplyOverhead
	reply, err := s.runTaskCoordScript(ctx, redisTaskPollOutboxScript,
		[]string{
			s.taskCoordOutboxKey("data"), s.taskCoordOutboxKey("ready"), s.taskCoordOutboxKey("leased"),
			s.taskCoordOutboxKey("lease-owner"), s.taskCoordOutboxKey("lease-consumer"),
		},
		[]string{poll.LeaseID, poll.ConsumerID, strconv.Itoa(int(poll.Limit)), strconv.FormatInt(poll.LeaseDuration.Milliseconds(), 10)},
		maxReply)
	if err != nil {
		return nil, err
	}
	if err := taskCoordStatusError(reply.status); err != nil {
		return nil, err
	}
	if reply.status == "EMPTY" {
		return []taskcoord.OutboxDelivery{}, nil
	}
	var stored []redisOutboxDelivery
	if err := decodeTaskValue([]byte(reply.payload), maxReply, &stored); err != nil || len(stored) == 0 || len(stored) > int(poll.Limit) {
		return nil, taskcoord.ErrStoreUnavailable
	}
	deliveries := make([]taskcoord.OutboxDelivery, 0, len(stored))
	for _, item := range stored {
		var event taskcoord.OutboxEvent
		if item.LeaseID != poll.LeaseID || decodeTaskValue([]byte(item.EventJSON), taskcoord.MaxOutboxPayloadBytes+maxRedisTaskReplyOverhead, &event) != nil ||
			event.Validate() != nil || item.DeliveryID != taskOutboxDeliveryID(event.EventID) {
			return nil, taskcoord.ErrStoreUnavailable
		}
		deliveries = append(deliveries, taskcoord.OutboxDelivery{DeliveryID: item.DeliveryID, LeaseID: item.LeaseID, Event: event})
	}
	return deliveries, nil
}

func (s *RedisTaskCoordStore) AcknowledgeOutbox(ctx context.Context, acknowledgement taskcoord.OutboxAcknowledgement) error {
	if err := acknowledgement.Validate(); err != nil {
		return err
	}
	reply, err := s.runTaskCoordScript(ctx, redisTaskAcknowledgeOutboxScript,
		[]string{
			s.taskCoordOutboxKey("data"), s.taskCoordOutboxKey("ready"), s.taskCoordOutboxKey("leased"),
			s.taskCoordOutboxKey("lease-owner"), s.taskCoordOutboxKey("lease-consumer"),
		}, []string{acknowledgement.DeliveryID, acknowledgement.LeaseID, acknowledgement.ConsumerID}, 256)
	if err != nil {
		return err
	}
	return taskCoordStatusError(reply.status)
}

func (s *RedisTaskCoordStore) loadTaskValue(ctx context.Context, kind, id string, target any) error {
	if strings.TrimSpace(id) == "" || len(id) > 256 {
		return taskcoord.ErrNotFound
	}
	reply, err := s.runTaskCoordScript(ctx, redisTaskLookupScript,
		[]string{s.taskCoordKey(kind, id)}, nil, maxRedisTaskValueBytes+128)
	if err != nil {
		return err
	}
	if err := taskCoordStatusError(reply.status); err != nil {
		return err
	}
	return decodeTaskValue([]byte(reply.payload), maxRedisTaskValueBytes, target)
}

func (s *RedisTaskCoordStore) runTaskCoordScript(ctx context.Context, script string, keys, arguments []string, maxReply int) (redisTaskReply, error) {
	if ctx == nil {
		return redisTaskReply{}, fmt.Errorf("%w: missing context", taskcoord.ErrStoreUnavailable)
	}
	if err := s.validateTaskCoordConfig(); err != nil {
		return redisTaskReply{}, err
	}
	command := make([]string, 0, 3+len(keys)+len(arguments))
	command = append(command, "EVAL", script, strconv.Itoa(len(keys)))
	command = append(command, keys...)
	command = append(command, arguments...)
	session, err := s.RedisSetNXStore.openSession(ctx)
	if err != nil {
		return redisTaskReply{}, fmt.Errorf("%w: %v", taskcoord.ErrStoreUnavailable, err)
	}
	defer session.close()
	if err := writeRESPArray(session.conn, command); err != nil {
		return redisTaskReply{}, fmt.Errorf("%w: redis EVAL write: %v", taskcoord.ErrStoreUnavailable, err)
	}
	kind, payload, err := readRESPBounded(session.reader, maxReply)
	if err != nil || kind != '$' || payload == "" {
		return redisTaskReply{}, fmt.Errorf("%w: invalid Redis EVAL response", taskcoord.ErrStoreUnavailable)
	}
	reply, err := parseTaskCoordReply(payload)
	if err != nil {
		return redisTaskReply{}, err
	}
	if redisTaskCoordWriteStatus(reply.status) {
		if err := s.RedisSetNXStore.waitForReplication(session.conn, session.reader); err != nil {
			return redisTaskReply{}, fmt.Errorf("%w: Redis write may have committed: %w", taskcoord.ErrStoreUnavailable, err)
		}
	}
	return reply, nil
}

func (s *RedisTaskCoordStore) validateTaskCoordConfig() error {
	if s == nil {
		return taskcoord.ErrStoreUnavailable
	}
	if err := s.RedisSetNXStore.validate(); err != nil {
		return fmt.Errorf("%w: %v", taskcoord.ErrStoreUnavailable, err)
	}
	if _, _, err := net.SplitHostPort(s.Address); err != nil {
		return fmt.Errorf("%w: invalid Redis address", taskcoord.ErrStoreUnavailable)
	}
	if s.Password == "" && (s.TLSConfig == nil || len(s.TLSConfig.Certificates) == 0) {
		return fmt.Errorf("%w: Redis requires ACL authentication or a client certificate", taskcoord.ErrStoreUnavailable)
	}
	if !validRedisJournalPrefix(s.KeyPrefix) || s.MaxInteractionHistoryBytes < 1 ||
		s.MaxInteractionHistoryBytes > hardMaxInteractionHistoryBytes || s.MaxOutboxBatch < 1 ||
		s.MaxOutboxBatch > hardMaxOutboxBatch || s.MaxOutboxLease <= 0 ||
		s.MaxOutboxLease > hardMaxOutboxLease || s.MaxOutboxLease.Milliseconds() < 1 {
		return fmt.Errorf("%w: invalid TaskCoord Redis bounds", taskcoord.ErrStoreUnavailable)
	}
	return nil
}

func (s *RedisTaskCoordStore) taskCoordKey(kind, value string) string {
	if s == nil {
		return ""
	}
	namespace := sha256.Sum256([]byte(s.KeyPrefix))
	digest := sha256.Sum256([]byte(value))
	return s.KeyPrefix + "{" + hex.EncodeToString(namespace[:8]) + "}:taskcoord:" + kind + ":" + hex.EncodeToString(digest[:])
}

func (s *RedisTaskCoordStore) taskCoordOutboxKey(kind string) string {
	return s.taskCoordKey("outbox-"+kind, "v1")
}

func (s *RedisTaskCoordStore) taskCoordReplicationBarrierKey() string {
	return s.taskCoordKey("replication-barrier", "v1")
}

func makeTaskOutbox(kind taskcoord.OutboxEventKind, eventID, taskID, assignmentID, participantID string, occurredAt time.Time, payload any) (taskcoord.OutboxEvent, []byte, error) {
	payloadRaw, err := json.Marshal(payload)
	if err != nil {
		return taskcoord.OutboxEvent{}, nil, fmt.Errorf("%w: encode outbox payload", taskcoord.ErrStoreUnavailable)
	}
	digest := sha256.Sum256(payloadRaw)
	event := taskcoord.OutboxEvent{
		Schema: taskcoord.OutboxEventSchemaV1, EventID: eventID, Kind: kind,
		TaskID: taskID, AssignmentID: assignmentID, ParticipantID: participantID,
		Payload: payloadRaw, PayloadDigest: hex.EncodeToString(digest[:]), OccurredAt: occurredAt,
	}
	if err := event.Validate(); err != nil {
		return taskcoord.OutboxEvent{}, nil, err
	}
	raw, err := marshalTaskValue(event)
	return event, raw, err
}

func taskOutboxDeliveryID(eventID string) string {
	digest := sha256.Sum256([]byte("asb-taskcoord-outbox-v1\x00" + eventID))
	return hex.EncodeToString(digest[:])
}

func marshalTaskValue(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) == 0 || len(raw) > maxRedisTaskValueBytes {
		return nil, fmt.Errorf("%w: encode bounded TaskCoord value", taskcoord.ErrStoreUnavailable)
	}
	return raw, nil
}

func decodeTaskValue(raw []byte, limit int, target any) error {
	if len(raw) == 0 || len(raw) > limit || !json.Valid(raw) {
		return taskcoord.ErrStoreUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return taskcoord.ErrStoreUnavailable
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return taskcoord.ErrStoreUnavailable
	}
	return nil
}

func parseTaskCoordReply(payload string) (redisTaskReply, error) {
	parts := strings.SplitN(payload, "\n", 2)
	if len(parts) == 0 || parts[0] == "" {
		return redisTaskReply{}, taskcoord.ErrStoreUnavailable
	}
	reply := redisTaskReply{status: parts[0]}
	if len(parts) == 2 {
		if parts[1] == "" {
			return redisTaskReply{}, taskcoord.ErrStoreUnavailable
		}
		reply.payload = parts[1]
	}
	return reply, nil
}

func redisTaskCoordWriteStatus(status string) bool {
	switch status {
	case "REGISTERED", "CREATED", "APPENDED", "CLAIMED", "ACKED", "IDEMPOTENT_BARRIER":
		return true
	default:
		return false
	}
}

func taskCoordStatusError(status string) error {
	switch status {
	case "REGISTERED", "CREATED", "APPENDED", "IDEMPOTENT", "IDEMPOTENT_BARRIER", "FOUND", "CLAIMED", "EMPTY", "ACKED":
		return nil
	case "NOT_FOUND":
		return taskcoord.ErrNotFound
	case "ALREADY_EXISTS":
		return taskcoord.ErrAlreadyExists
	case "REVISION_CONFLICT":
		return taskcoord.ErrRevisionConflict
	case "EVENT_CONFLICT":
		return taskcoord.ErrEventConflict
	case "INVALID_INTERACTION":
		return taskcoord.ErrInvalidInteraction
	case "PARTICIPANT_UNAVAILABLE":
		return taskcoord.ErrParticipantUnavailable
	case "OUTBOX_CONFLICT":
		return taskcoord.ErrOutboxConflict
	case "LEASE_EXPIRED":
		return taskcoord.ErrOutboxLeaseExpired
	case "LIMIT_REACHED":
		return taskcoord.ErrStoreLimit
	default:
		return taskcoord.ErrStoreUnavailable
	}
}
