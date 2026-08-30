// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package production

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/operationjournal"
)

const (
	redisOperationRecordSchema          = "urn:asb:operation-journal:redis:v1"
	redisSealedResultSchema             = "urn:asb:sealed-result:redis:v1"
	maxRedisNamespaceBytes              = 128
	maxRedisRecordReplyBytes            = 16 << 10
	maxRedisResultReplyBytes            = 512 << 10
	maxRedisReplayTTL                   = 365 * 24 * time.Hour
	maxSafeJSONInteger                  = uint64(1<<53 - 1)
	maxUnixMillis                       = int64(253402300799999) // 9999-12-31T23:59:59.999Z
	redisJournalStatusCreated           = "CREATED"
	redisJournalStatusReplayReserved    = "REPLAY_RESERVED"
	redisJournalStatusUpdated           = "UPDATED"
	redisJournalStatusIdempotent        = "IDEMPOTENT"
	redisJournalStatusCompleted         = "COMPLETED"
	redisJournalStatusConflict          = "CONFLICT"
	redisJournalStatusInvalidTransition = "INVALID_TRANSITION"
	redisJournalStatusCorrupt           = "CORRUPT"
)

// RedisAcceptanceStore is a shared Redis/Valkey operation journal for Agent B
// replicas. Every state change uses one Lua script on a primary. Replay and
// operation keys share a namespace-derived Redis Cluster hash slot, so the
// replay reservation and exact operation reservation are one atomic command.
// Address must already route that slot to the writable primary; this adapter
// does not follow Redis Cluster MOVED/ASK replies or query Sentinel.
//
// Operation records and result tombstones do not expire. Expiring or evicting
// them would allow an old operation ID to execute again. Deployments therefore
// need noeviction plus an explicit, externally reviewed archival/GC policy.
// Optional WAIT acknowledgements reduce failover loss but do not make Redis
// replication linearizable or provide a zero-loss failover guarantee.
type RedisAcceptanceStore struct {
	RedisSetNXStore

	// MaxReplayTTL bounds verifier-controlled replay retention. The Lua script
	// compares the absolute retention time with Redis TIME, not a replica clock.
	MaxReplayTTL time.Duration
}

var (
	_ operationjournal.AcceptanceStore = (*RedisAcceptanceStore)(nil)
	_ operationjournal.ResultStore     = (*RedisAcceptanceStore)(nil)
)

// Validate checks the local Redis/Valkey safety configuration without dialing
// the backend.
func (s *RedisAcceptanceStore) Validate() error {
	return s.validateAcceptanceConfig()
}

type redisJournalRecord struct {
	Schema          string                 `json:"schema"`
	RequestDigest   string                 `json:"request_digest"`
	State           operationjournal.State `json:"state"`
	OutcomeDigest   string                 `json:"outcome_digest"`
	Revision        uint64                 `json:"revision"`
	CreatedAtMillis int64                  `json:"created_at_ms"`
	UpdatedAtMillis int64                  `json:"updated_at_ms"`
	StartedAtMillis int64                  `json:"started_at_ms"`
	CompletedMillis int64                  `json:"completed_at_ms"`
}

// redisSealedResult deliberately omits the operation ID and request digest.
// They are represented by the hashed key and are restored only after an exact
// lookup. Redis receives no plaintext application result.
type redisSealedResult struct {
	Schema        string `json:"schema"`
	OutcomeDigest string `json:"outcome_digest"`
	MediaType     string `json:"media_type"`
	Envelope      string `json:"envelope"`
	PlaintextSize uint32 `json:"plaintext_bytes"`
	Nonce         []byte `json:"nonce"`
	Ciphertext    []byte `json:"ciphertext"`
}

type redisJournalReply struct {
	status string
	parts  []string
}

func (s *RedisAcceptanceStore) Reserve(ctx context.Context, request operationjournal.Reservation) (operationjournal.Record, bool, error) {
	if err := operationjournal.ValidateReservation(request); err != nil {
		return operationjournal.Record{}, false, err
	}
	reply, err := s.runJournalScript(ctx, redisReserveOperationScript, []string{s.operationKey(request.OperationID)}, []string{request.RequestDigest}, maxRedisRecordReplyBytes)
	if err != nil {
		return operationjournal.Record{}, false, err
	}
	if err := journalStatusError(reply.status); err != nil {
		return operationjournal.Record{}, false, err
	}
	if reply.status != redisJournalStatusCreated && reply.status != "EXISTING" {
		return operationjournal.Record{}, false, operationjournal.ErrUnavailable
	}
	record, err := decodeRedisJournalRecord(reply.parts, request.OperationID, request.RequestDigest)
	return record, reply.status == redisJournalStatusCreated, err
}

func (s *RedisAcceptanceStore) ReserveAcceptance(ctx context.Context, request operationjournal.AcceptanceReservation) (operationjournal.Record, bool, error) {
	if err := operationjournal.ValidateAcceptanceReservation(request); err != nil {
		return operationjournal.Record{}, false, err
	}
	if request.ReplayRetainUntil.Year() < 1970 || request.ReplayRetainUntil.Year() > 9999 {
		return operationjournal.Record{}, false, operationjournal.ErrInvalidRecord
	}
	if s == nil {
		return operationjournal.Record{}, false, operationjournal.ErrUnavailable
	}
	reply, err := s.runJournalScript(
		ctx,
		redisReserveAcceptanceScript,
		[]string{s.operationKey(request.Operation.OperationID), s.replayKey(request.ReplayKey)},
		[]string{
			request.Operation.RequestDigest,
			strconv.FormatInt(request.ReplayRetainUntil.UTC().UnixMilli(), 10),
			strconv.FormatInt(s.MaxReplayTTL.Milliseconds(), 10),
		},
		maxRedisRecordReplyBytes,
	)
	if err != nil {
		return operationjournal.Record{}, false, err
	}
	if err := journalStatusError(reply.status); err != nil {
		return operationjournal.Record{}, false, err
	}
	if reply.status != redisJournalStatusCreated && reply.status != redisJournalStatusReplayReserved {
		return operationjournal.Record{}, false, operationjournal.ErrUnavailable
	}
	record, err := decodeRedisJournalRecord(reply.parts, request.Operation.OperationID, request.Operation.RequestDigest)
	return record, reply.status == redisJournalStatusCreated, err
}

func (s *RedisAcceptanceStore) Lookup(ctx context.Context, operationID, requestDigest string) (operationjournal.Record, error) {
	request := operationjournal.Reservation{OperationID: operationID, RequestDigest: requestDigest}
	if err := operationjournal.ValidateReservation(request); err != nil {
		return operationjournal.Record{}, err
	}
	reply, err := s.runJournalScript(ctx, redisLookupOperationScript, []string{s.operationKey(operationID)}, []string{requestDigest}, maxRedisRecordReplyBytes)
	if err != nil {
		return operationjournal.Record{}, err
	}
	if err := journalStatusError(reply.status); err != nil {
		return operationjournal.Record{}, err
	}
	if reply.status != "FOUND" {
		return operationjournal.Record{}, operationjournal.ErrUnavailable
	}
	return decodeRedisJournalRecord(reply.parts, operationID, requestDigest)
}

func (s *RedisAcceptanceStore) MarkRunning(ctx context.Context, operationID, requestDigest string) (operationjournal.Record, bool, error) {
	request := operationjournal.Reservation{OperationID: operationID, RequestDigest: requestDigest}
	if err := operationjournal.ValidateReservation(request); err != nil {
		return operationjournal.Record{}, false, err
	}
	reply, err := s.runJournalScript(ctx, redisMarkRunningScript, []string{s.operationKey(operationID)}, []string{requestDigest}, maxRedisRecordReplyBytes)
	if err != nil {
		return operationjournal.Record{}, false, err
	}
	if err := journalStatusError(reply.status); err != nil {
		return operationjournal.Record{}, false, err
	}
	if reply.status != redisJournalStatusUpdated && reply.status != redisJournalStatusIdempotent {
		return operationjournal.Record{}, false, operationjournal.ErrUnavailable
	}
	record, err := decodeRedisJournalRecord(reply.parts, operationID, requestDigest)
	if err != nil {
		return operationjournal.Record{}, false, err
	}
	if record.State != operationjournal.StateRunning {
		return operationjournal.Record{}, false, operationjournal.ErrUnavailable
	}
	return record, reply.status == redisJournalStatusUpdated, nil
}

func (s *RedisAcceptanceStore) MarkIndeterminate(ctx context.Context, operationID, requestDigest string) (operationjournal.Record, error) {
	request := operationjournal.Reservation{OperationID: operationID, RequestDigest: requestDigest}
	if err := operationjournal.ValidateReservation(request); err != nil {
		return operationjournal.Record{}, err
	}
	reply, err := s.runJournalScript(ctx, redisMarkIndeterminateScript, []string{s.operationKey(operationID)}, []string{requestDigest}, maxRedisRecordReplyBytes)
	if err != nil {
		return operationjournal.Record{}, err
	}
	if err := journalStatusError(reply.status); err != nil {
		return operationjournal.Record{}, err
	}
	if reply.status != redisJournalStatusUpdated && reply.status != redisJournalStatusIdempotent {
		return operationjournal.Record{}, operationjournal.ErrUnavailable
	}
	record, err := decodeRedisJournalRecord(reply.parts, operationID, requestDigest)
	if err != nil || record.State != operationjournal.StateIndeterminate {
		return operationjournal.Record{}, operationjournal.ErrUnavailable
	}
	return record, nil
}

func (s *RedisAcceptanceStore) Finalize(ctx context.Context, final operationjournal.Finalization) (operationjournal.Record, error) {
	if err := operationjournal.ValidateFinalization(final); err != nil {
		return operationjournal.Record{}, err
	}
	reply, err := s.runJournalScript(
		ctx,
		redisFinalizeOperationScript,
		[]string{s.operationKey(final.OperationID)},
		[]string{final.RequestDigest, string(final.State), final.OutcomeDigest},
		maxRedisRecordReplyBytes,
	)
	if err != nil {
		return operationjournal.Record{}, err
	}
	if err := journalStatusError(reply.status); err != nil {
		return operationjournal.Record{}, err
	}
	if reply.status != redisJournalStatusUpdated && reply.status != redisJournalStatusIdempotent {
		return operationjournal.Record{}, operationjournal.ErrUnavailable
	}
	record, err := decodeRedisJournalRecord(reply.parts, final.OperationID, final.RequestDigest)
	if err != nil || record.State != final.State || record.OutcomeDigest != final.OutcomeDigest {
		return operationjournal.Record{}, operationjournal.ErrUnavailable
	}
	return record, nil
}

// FinalizeWithResult commits SUCCEEDED and an opaque sealed result in one Lua
// execution. If the call or WAIT acknowledgement fails, callers must use
// LookupResult before releasing a response or attempting any recovery action.
func (s *RedisAcceptanceStore) FinalizeWithResult(ctx context.Context, final operationjournal.Finalization, result operationjournal.SealedResult) (operationjournal.Record, error) {
	if err := operationjournal.ValidateFinalization(final); err != nil {
		return operationjournal.Record{}, err
	}
	if final.State != operationjournal.StateSucceeded || final.OutcomeDigest == "" {
		return operationjournal.Record{}, operationjournal.ErrInvalidRecord
	}
	if err := operationjournal.ValidateSealedResult(result); err != nil {
		return operationjournal.Record{}, err
	}
	if result.OperationID != final.OperationID || result.RequestDigest != final.RequestDigest || result.OutcomeDigest != final.OutcomeDigest {
		return operationjournal.Record{}, operationjournal.ErrConflict
	}
	stored := redisSealedResult{
		Schema: redisSealedResultSchema, OutcomeDigest: result.OutcomeDigest,
		MediaType: result.MediaType, Envelope: result.Envelope, PlaintextSize: result.PlaintextBytes,
		Nonce: append([]byte(nil), result.Nonce...), Ciphertext: append([]byte(nil), result.Ciphertext...),
	}
	sealedJSON, err := json.Marshal(stored)
	if err != nil {
		return operationjournal.Record{}, fmt.Errorf("%w: encode sealed result", operationjournal.ErrUnavailable)
	}
	reply, err := s.runJournalScript(
		ctx,
		redisFinalizeResultScript,
		[]string{s.operationKey(final.OperationID), s.resultKey(final.OperationID)},
		[]string{final.RequestDigest, final.OutcomeDigest, string(sealedJSON)},
		maxRedisRecordReplyBytes,
	)
	if err != nil {
		return operationjournal.Record{}, err
	}
	if err := journalStatusError(reply.status); err != nil {
		return operationjournal.Record{}, err
	}
	if reply.status != redisJournalStatusCompleted && reply.status != redisJournalStatusIdempotent {
		return operationjournal.Record{}, operationjournal.ErrUnavailable
	}
	record, err := decodeRedisJournalRecord(reply.parts, final.OperationID, final.RequestDigest)
	if err != nil || record.State != operationjournal.StateSucceeded || record.OutcomeDigest != final.OutcomeDigest {
		return operationjournal.Record{}, operationjournal.ErrUnavailable
	}
	return record, nil
}

func (s *RedisAcceptanceStore) LookupResult(ctx context.Context, operationID, requestDigest string) (operationjournal.Record, operationjournal.SealedResult, error) {
	request := operationjournal.Reservation{OperationID: operationID, RequestDigest: requestDigest}
	if err := operationjournal.ValidateReservation(request); err != nil {
		return operationjournal.Record{}, operationjournal.SealedResult{}, err
	}
	reply, err := s.runJournalScript(
		ctx,
		redisLookupResultScript,
		[]string{s.operationKey(operationID), s.resultKey(operationID)},
		[]string{requestDigest},
		maxRedisResultReplyBytes,
	)
	if err != nil {
		return operationjournal.Record{}, operationjournal.SealedResult{}, err
	}
	if err := journalStatusError(reply.status); err != nil {
		return operationjournal.Record{}, operationjournal.SealedResult{}, err
	}
	if reply.status != "FOUND_RESULT" || len(reply.parts) != 2 {
		return operationjournal.Record{}, operationjournal.SealedResult{}, operationjournal.ErrUnavailable
	}
	record, err := decodeRedisJournalRecord(reply.parts[:1], operationID, requestDigest)
	if err != nil || record.State != operationjournal.StateSucceeded || record.OutcomeDigest == "" {
		return operationjournal.Record{}, operationjournal.SealedResult{}, operationjournal.ErrUnavailable
	}
	result, err := decodeRedisSealedResult(reply.parts[1], operationID, requestDigest, record.OutcomeDigest)
	if err != nil {
		return operationjournal.Record{}, operationjournal.SealedResult{}, err
	}
	return record, result, nil
}

func (s *RedisAcceptanceStore) runJournalScript(ctx context.Context, script string, keys, arguments []string, maxReply int) (redisJournalReply, error) {
	if ctx == nil {
		return redisJournalReply{}, operationjournal.ErrInvalidRecord
	}
	if err := s.validateAcceptanceConfig(); err != nil {
		return redisJournalReply{}, err
	}
	command := make([]string, 0, 3+len(keys)+len(arguments))
	command = append(command, "EVAL", script, strconv.Itoa(len(keys)))
	command = append(command, keys...)
	command = append(command, arguments...)
	session, err := s.RedisSetNXStore.openSession(ctx)
	if err != nil {
		return redisJournalReply{}, fmt.Errorf("%w: %v", operationjournal.ErrUnavailable, err)
	}
	defer session.close()
	if err := writeRESPArray(session.conn, command); err != nil {
		return redisJournalReply{}, fmt.Errorf("%w: redis EVAL write: %v", operationjournal.ErrUnavailable, err)
	}
	kind, payload, err := readRESPBounded(session.reader, maxReply)
	if err != nil || kind != '$' || payload == "" {
		return redisJournalReply{}, fmt.Errorf("%w: invalid Redis EVAL response", operationjournal.ErrUnavailable)
	}
	reply, err := parseRedisJournalReply(payload)
	if err != nil {
		return redisJournalReply{}, err
	}
	if redisJournalWriteStatus(reply.status) {
		if err := s.RedisSetNXStore.waitForReplication(session.conn, session.reader); err != nil {
			return redisJournalReply{}, fmt.Errorf("%w: Redis write may have committed: %w", operationjournal.ErrUnavailable, err)
		}
	}
	return reply, nil
}

func (s *RedisAcceptanceStore) validateAcceptanceConfig() error {
	if s == nil {
		return operationjournal.ErrUnavailable
	}
	if err := s.RedisSetNXStore.validate(); err != nil {
		return fmt.Errorf("%w: %v", operationjournal.ErrUnavailable, err)
	}
	if _, _, err := net.SplitHostPort(s.Address); err != nil {
		return fmt.Errorf("%w: invalid Redis address", operationjournal.ErrUnavailable)
	}
	if s.Password == "" && (s.TLSConfig == nil || len(s.TLSConfig.Certificates) == 0) {
		return fmt.Errorf("%w: Redis requires ACL authentication or a client certificate", operationjournal.ErrUnavailable)
	}
	if !validRedisJournalPrefix(s.KeyPrefix) {
		return fmt.Errorf("%w: invalid Redis journal key prefix", operationjournal.ErrUnavailable)
	}
	if s.MaxReplayTTL <= 0 || s.MaxReplayTTL > maxRedisReplayTTL || s.MaxReplayTTL.Milliseconds() < 1 {
		return fmt.Errorf("%w: invalid maximum replay TTL", operationjournal.ErrUnavailable)
	}
	return nil
}

func validRedisJournalPrefix(value string) bool {
	if value == "" || len(value) > maxRedisNamespaceBytes || strings.TrimSpace(value) != value || !strings.HasSuffix(value, ":") {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == ':' || character == '.' || character == '_' || character == '-') {
			return false
		}
	}
	return true
}

func (s *RedisAcceptanceStore) operationKey(operationID string) string {
	return s.journalKey("operation", operationID)
}

func (s *RedisAcceptanceStore) replayKey(replayKey string) string {
	return s.journalKey("replay", replayKey)
}

func (s *RedisAcceptanceStore) resultKey(operationID string) string {
	return s.journalKey("result", operationID)
}

func (s *RedisAcceptanceStore) journalKey(kind, value string) string {
	if s == nil {
		return ""
	}
	namespace := sha256.Sum256([]byte(s.KeyPrefix))
	digest := sha256.Sum256([]byte(value))
	return s.KeyPrefix + "{" + hex.EncodeToString(namespace[:8]) + "}:" + kind + ":" + hex.EncodeToString(digest[:])
}

func parseRedisJournalReply(payload string) (redisJournalReply, error) {
	parts := strings.Split(payload, "\n")
	if len(parts) == 0 || parts[0] == "" || len(parts) > 3 {
		return redisJournalReply{}, operationjournal.ErrUnavailable
	}
	for _, part := range parts {
		if part == "" {
			return redisJournalReply{}, operationjournal.ErrUnavailable
		}
	}
	return redisJournalReply{status: parts[0], parts: parts[1:]}, nil
}

func redisJournalWriteStatus(status string) bool {
	switch status {
	case redisJournalStatusCreated, redisJournalStatusReplayReserved, redisJournalStatusUpdated, redisJournalStatusCompleted:
		return true
	default:
		return false
	}
}

func journalStatusError(status string) error {
	switch status {
	case redisJournalStatusCreated, "EXISTING", redisJournalStatusReplayReserved, "FOUND", redisJournalStatusUpdated, redisJournalStatusIdempotent, redisJournalStatusCompleted, "FOUND_RESULT":
		return nil
	case "REPLAY":
		return operationjournal.ErrReplay
	case redisJournalStatusConflict:
		return operationjournal.ErrConflict
	case "NOT_FOUND", "NO_RESULT":
		return operationjournal.ErrNotFound
	case "INVALID", "EXPIRED", "TTL_TOO_LONG":
		return operationjournal.ErrInvalidRecord
	case redisJournalStatusInvalidTransition:
		return operationjournal.ErrInvalidTransition
	case redisJournalStatusCorrupt:
		return operationjournal.ErrUnavailable
	default:
		return operationjournal.ErrUnavailable
	}
}

func decodeRedisJournalRecord(parts []string, operationID, requestDigest string) (operationjournal.Record, error) {
	if len(parts) != 1 || len(parts[0]) > maxRedisRecordReplyBytes {
		return operationjournal.Record{}, operationjournal.ErrUnavailable
	}
	var stored redisJournalRecord
	decoder := json.NewDecoder(io.LimitReader(bytes.NewBufferString(parts[0]), maxRedisRecordReplyBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&stored); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return operationjournal.Record{}, operationjournal.ErrUnavailable
	}
	if stored.Schema != redisOperationRecordSchema || stored.RequestDigest != requestDigest || stored.Revision == 0 || stored.Revision > maxSafeJSONInteger {
		return operationjournal.Record{}, operationjournal.ErrUnavailable
	}
	if err := validateRedisMillis(stored.CreatedAtMillis, stored.UpdatedAtMillis, stored.StartedAtMillis, stored.CompletedMillis); err != nil {
		return operationjournal.Record{}, err
	}
	record := operationjournal.Record{
		OperationID: operationID, RequestDigest: stored.RequestDigest, State: stored.State,
		OutcomeDigest: stored.OutcomeDigest, Revision: stored.Revision,
		CreatedAt: time.UnixMilli(stored.CreatedAtMillis).UTC(), UpdatedAt: time.UnixMilli(stored.UpdatedAtMillis).UTC(),
	}
	if stored.StartedAtMillis != 0 {
		record.StartedAt = time.UnixMilli(stored.StartedAtMillis).UTC()
	}
	if stored.CompletedMillis != 0 {
		record.CompletedAt = time.UnixMilli(stored.CompletedMillis).UTC()
	}
	if err := validateRedisRecordState(record); err != nil {
		return operationjournal.Record{}, err
	}
	return record, nil
}

func validateRedisMillis(created, updated, started, completed int64) error {
	values := []int64{created, updated, started, completed}
	for index, value := range values {
		if (index < 2 && value < 1) || value < 0 || value > maxUnixMillis {
			return operationjournal.ErrUnavailable
		}
	}
	if updated < created || (started != 0 && (started < created || started > updated)) ||
		(completed != 0 && (completed < created || completed != updated)) {
		return operationjournal.ErrUnavailable
	}
	return nil
}

func validateRedisRecordState(record operationjournal.Record) error {
	switch record.State {
	case operationjournal.StateAccepted:
		if !record.StartedAt.IsZero() || !record.CompletedAt.IsZero() || record.OutcomeDigest != "" {
			return operationjournal.ErrUnavailable
		}
	case operationjournal.StateRunning, operationjournal.StateIndeterminate:
		if record.StartedAt.IsZero() || !record.CompletedAt.IsZero() || record.OutcomeDigest != "" {
			return operationjournal.ErrUnavailable
		}
	case operationjournal.StateSucceeded, operationjournal.StateFailed:
		if record.StartedAt.IsZero() || record.CompletedAt.IsZero() {
			return operationjournal.ErrUnavailable
		}
		if err := operationjournal.ValidateFinalization(operationjournal.Finalization{
			OperationID: record.OperationID, RequestDigest: record.RequestDigest,
			State: record.State, OutcomeDigest: record.OutcomeDigest,
		}); err != nil {
			return operationjournal.ErrUnavailable
		}
	case operationjournal.StateCanceled:
		if record.CompletedAt.IsZero() {
			return operationjournal.ErrUnavailable
		}
		if err := operationjournal.ValidateFinalization(operationjournal.Finalization{
			OperationID: record.OperationID, RequestDigest: record.RequestDigest,
			State: record.State, OutcomeDigest: record.OutcomeDigest,
		}); err != nil {
			return operationjournal.ErrUnavailable
		}
	default:
		return operationjournal.ErrUnavailable
	}
	return nil
}

func decodeRedisSealedResult(raw, operationID, requestDigest, outcomeDigest string) (operationjournal.SealedResult, error) {
	if raw == "" || len(raw) > maxRedisResultReplyBytes {
		return operationjournal.SealedResult{}, operationjournal.ErrUnavailable
	}
	var stored redisSealedResult
	decoder := json.NewDecoder(io.LimitReader(bytes.NewBufferString(raw), maxRedisResultReplyBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&stored); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return operationjournal.SealedResult{}, operationjournal.ErrUnavailable
	}
	if stored.Schema != redisSealedResultSchema || stored.OutcomeDigest != outcomeDigest {
		return operationjournal.SealedResult{}, operationjournal.ErrUnavailable
	}
	result := operationjournal.SealedResult{
		OperationID: operationID, RequestDigest: requestDigest, OutcomeDigest: outcomeDigest,
		MediaType: stored.MediaType, Envelope: stored.Envelope, PlaintextBytes: stored.PlaintextSize,
		Nonce: append([]byte(nil), stored.Nonce...), Ciphertext: append([]byte(nil), stored.Ciphertext...),
	}
	if err := operationjournal.ValidateSealedResult(result); err != nil {
		return operationjournal.SealedResult{}, fmt.Errorf("%w: invalid stored sealed result", operationjournal.ErrUnavailable)
	}
	return result, nil
}
