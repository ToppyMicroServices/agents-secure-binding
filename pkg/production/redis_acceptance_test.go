// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package production

import (
	"bufio"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/thinksyncs/agents-secure-binding/pkg/operationjournal"
)

func TestRedisAcceptanceStoreCoordinatesReplicasAndResultsOverTLS(t *testing.T) {
	t.Parallel()
	backend := startTestRedisJournalTLS(t, 1)
	first := backend.store()
	second := backend.store()
	now := time.Now().UTC()
	request := operationjournal.Reservation{
		OperationID:   "customer-visible-operation",
		RequestDigest: redisTestDigest("bound request"),
	}
	acceptance := operationjournal.AcceptanceReservation{
		ReplayKey: redisTestReplayKey("nonce-one"), ReplayRetainUntil: now.Add(time.Minute), Operation: request,
	}

	record, created, err := first.ReserveAcceptance(context.Background(), acceptance)
	if err != nil || !created || record.State != operationjournal.StateAccepted {
		t.Fatalf("ReserveAcceptance() = (%+v, %v, %v)", record, created, err)
	}

	replay := acceptance
	replay.Operation = operationjournal.Reservation{OperationID: "other-operation", RequestDigest: redisTestDigest("other request")}
	if _, _, err := second.ReserveAcceptance(context.Background(), replay); !errors.Is(err, operationjournal.ErrReplay) {
		t.Fatalf("replay ReserveAcceptance() error = %v, want %v", err, operationjournal.ErrReplay)
	}
	if _, err := first.Lookup(context.Background(), replay.Operation.OperationID, replay.Operation.RequestDigest); !errors.Is(err, operationjournal.ErrNotFound) {
		t.Fatalf("replayed operation was partially stored: %v", err)
	}

	exact := acceptance
	exact.ReplayKey = redisTestReplayKey("nonce-two")
	if retry, retryCreated, err := second.ReserveAcceptance(context.Background(), exact); err != nil || retryCreated || !reflect.DeepEqual(retry, record) {
		t.Fatalf("exact retry = (%+v, %v, %v), want existing %+v", retry, retryCreated, err, record)
	}

	const replicas = 24
	var started atomic.Int32
	errCh := make(chan error, replicas)
	var wait sync.WaitGroup
	for index := range replicas {
		wait.Add(1)
		go func() {
			defer wait.Done()
			store := first
			if index%2 != 0 {
				store = second
			}
			got, didStart, err := store.MarkRunning(context.Background(), request.OperationID, request.RequestDigest)
			if err != nil {
				errCh <- err
				return
			}
			if got.State != operationjournal.StateRunning {
				errCh <- fmt.Errorf("state = %s", got.State)
				return
			}
			if didStart {
				started.Add(1)
			}
		}()
	}
	wait.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent MarkRunning(): %v", err)
	}
	if got := started.Load(); got != 1 {
		t.Fatalf("MarkRunning() winners = %d, want 1", got)
	}

	if _, err := first.MarkIndeterminate(context.Background(), request.OperationID, request.RequestDigest); err != nil {
		t.Fatalf("MarkIndeterminate() error = %v", err)
	}
	result := redisTestSealedResult(request, "recoverable output")
	final := operationjournal.Finalization{
		OperationID: request.OperationID, RequestDigest: request.RequestDigest,
		State: operationjournal.StateSucceeded, OutcomeDigest: result.OutcomeDigest,
	}
	completed, err := second.FinalizeWithResult(context.Background(), final, result)
	if err != nil || completed.State != operationjournal.StateSucceeded {
		t.Fatalf("FinalizeWithResult() = (%+v, %v)", completed, err)
	}
	lookedUp, recovered, err := first.LookupResult(context.Background(), request.OperationID, request.RequestDigest)
	if err != nil || !reflect.DeepEqual(lookedUp, completed) || !reflect.DeepEqual(recovered, result) {
		t.Fatalf("LookupResult() = (%+v, %+v, %v)", lookedUp, recovered, err)
	}
	if retry, err := first.FinalizeWithResult(context.Background(), final, result); err != nil || !reflect.DeepEqual(retry, completed) {
		t.Fatalf("exact FinalizeWithResult() = (%+v, %v)", retry, err)
	}
	conflict := result
	conflict.Ciphertext = append([]byte(nil), result.Ciphertext...)
	conflict.Ciphertext[0] ^= 1
	if _, err := first.FinalizeWithResult(context.Background(), final, conflict); !errors.Is(err, operationjournal.ErrConflict) {
		t.Fatalf("conflicting result error = %v, want %v", err, operationjournal.ErrConflict)
	}

	backend.assertHashedSameSlotKeys(t, request.OperationID, acceptance.ReplayKey)
}

func TestRedisAcceptanceStoreReportsUnknownCommitAfterWAITFailure(t *testing.T) {
	t.Parallel()
	backend := startTestRedisJournalTLS(t, 0)
	store := backend.store()
	request := operationjournal.AcceptanceReservation{
		ReplayKey: redisTestReplayKey("wait-failure"), ReplayRetainUntil: time.Now().UTC().Add(time.Minute),
		Operation: operationjournal.Reservation{OperationID: "wait-failure-operation", RequestDigest: redisTestDigest("request")},
	}
	_, _, err := store.ReserveAcceptance(context.Background(), request)
	if !errors.Is(err, operationjournal.ErrUnavailable) || !errors.Is(err, ErrRedisReplication) {
		t.Fatalf("ReserveAcceptance() error = %v, want unavailable and replication error", err)
	}

	backend.setAcknowledgements(1)
	record, lookupErr := store.Lookup(context.Background(), request.Operation.OperationID, request.Operation.RequestDigest)
	if lookupErr != nil || record.State != operationjournal.StateAccepted {
		t.Fatalf("Lookup() after uncertain acknowledgement = (%+v, %v)", record, lookupErr)
	}
	if _, _, err := store.ReserveAcceptance(context.Background(), request); !errors.Is(err, operationjournal.ErrReplay) {
		t.Fatalf("retry after uncertain acknowledgement = %v, want replay", err)
	}
}

func TestRedisAcceptanceStoreRejectsUnsafeConfigurationBeforeDial(t *testing.T) {
	t.Parallel()
	request := operationjournal.Reservation{OperationID: "operation", RequestDigest: redisTestDigest("request")}
	baseTLS := &tls.Config{ServerName: "redis.test", MinVersion: tls.VersionTLS13}
	tests := []RedisAcceptanceStore{
		{},
		{RedisSetNXStore: RedisSetNXStore{Address: "redis.test:6379", KeyPrefix: "asb:journal:", TLSConfig: baseTLS, OperationTimeout: time.Second, Password: "secret"}},
		{RedisSetNXStore: RedisSetNXStore{Address: "redis.test:6379", KeyPrefix: "asb:{unsafe}:", TLSConfig: baseTLS, OperationTimeout: time.Second, Password: "secret"}, MaxReplayTTL: time.Hour},
		{RedisSetNXStore: RedisSetNXStore{Address: "redis.test:6379", KeyPrefix: "asb:journal", TLSConfig: baseTLS, OperationTimeout: time.Second, Password: "secret"}, MaxReplayTTL: time.Hour},
		{RedisSetNXStore: RedisSetNXStore{Address: "redis.test:6379", KeyPrefix: "asb:journal:", TLSConfig: baseTLS, OperationTimeout: time.Second}, MaxReplayTTL: time.Hour},
		{RedisSetNXStore: RedisSetNXStore{Address: "not-a-host-port", KeyPrefix: "asb:journal:", TLSConfig: baseTLS, OperationTimeout: time.Second, Password: "secret"}, MaxReplayTTL: time.Hour},
		{RedisSetNXStore: RedisSetNXStore{Address: "redis.test:6379", KeyPrefix: "asb:journal:", TLSConfig: baseTLS, OperationTimeout: time.Second, Password: "secret"}, MaxReplayTTL: maxRedisReplayTTL + time.Millisecond},
	}
	for index := range tests {
		if _, _, err := tests[index].Reserve(context.Background(), request); !errors.Is(err, operationjournal.ErrUnavailable) {
			t.Fatalf("case %d error = %v, want unavailable", index, err)
		}
	}
	if _, _, err := (&RedisAcceptanceStore{}).Reserve(nil, request); !errors.Is(err, operationjournal.ErrInvalidRecord) {
		t.Fatalf("nil context error = %v, want invalid record", err)
	}
}

func TestRedisAcceptanceLuaScriptsParseWhenLuaIsAvailable(t *testing.T) {
	t.Parallel()
	lua, err := exec.LookPath("lua")
	if err != nil {
		t.Skip("Lua interpreter is unavailable; Redis protocol tests still run")
	}
	scripts := []string{
		redisReserveOperationScript, redisReserveAcceptanceScript, redisLookupOperationScript,
		redisMarkRunningScript, redisMarkIndeterminateScript, redisFinalizeOperationScript,
		redisFinalizeResultScript, redisLookupResultScript,
	}
	for index, script := range scripts {
		path := filepath.Join(t.TempDir(), fmt.Sprintf("redis-script-%d.lua", index))
		if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
			t.Fatal(err)
		}
		command := exec.Command(lua, "-e", "assert(loadfile(arg[1])); os.exit(0)", path)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("Lua script %d does not parse: %v: %s", index, err, output)
		}
	}
}

func redisTestDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func redisTestReplayKey(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sbaip-replay-v2:" + hex.EncodeToString(digest[:])
}

func redisTestSealedResult(request operationjournal.Reservation, value string) operationjournal.SealedResult {
	outcome := redisTestDigest(value)
	return operationjournal.SealedResult{
		OperationID: request.OperationID, RequestDigest: request.RequestDigest, OutcomeDigest: outcome,
		MediaType: "text/plain; charset=utf-8", Envelope: operationjournal.SealedResultEnvelopeV1,
		PlaintextBytes: uint32(len(value)), Nonce: []byte("123456789012"),
		Ciphertext: append(append([]byte(nil), []byte(value)...), make([]byte, 16)...),
	}
}

type testRedisJournalBackend struct {
	t           *testing.T
	listener    net.Listener
	tlsConfig   *tls.Config
	done        chan struct{}
	mu          sync.Mutex
	values      map[string]string
	expires     map[string]time.Time
	keys        []string
	err         error
	waitGroup   sync.WaitGroup
	acknowledge int
}

func startTestRedisJournalTLS(t *testing.T, acknowledgements int) *testRedisJournalBackend {
	t.Helper()
	certificate, roots := testRedisCertificate(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	backend := &testRedisJournalBackend{
		t: t, listener: listener, tlsConfig: &tls.Config{RootCAs: roots, ServerName: "redis.test", MinVersion: tls.VersionTLS13},
		done: make(chan struct{}), values: make(map[string]string), expires: make(map[string]time.Time), acknowledge: acknowledgements,
	}
	go backend.serve()
	t.Cleanup(func() {
		_ = listener.Close()
		<-backend.done
		backend.mu.Lock()
		defer backend.mu.Unlock()
		if backend.err != nil {
			t.Errorf("test Redis journal server: %v", backend.err)
		}
	})
	return backend
}

func (b *testRedisJournalBackend) store() *RedisAcceptanceStore {
	return &RedisAcceptanceStore{
		RedisSetNXStore: RedisSetNXStore{
			Address: b.listener.Addr().String(), Password: "journal-secret", KeyPrefix: "asb:test:journal:",
			TLSConfig: b.tlsConfig.Clone(), OperationTimeout: 5 * time.Second,
			RequiredReplicaAcknowledgements: 1, ReplicationTimeout: time.Second,
		},
		MaxReplayTTL: time.Hour,
	}
}

func (b *testRedisJournalBackend) setAcknowledgements(value int) {
	b.mu.Lock()
	b.acknowledge = value
	b.mu.Unlock()
}

func (b *testRedisJournalBackend) serve() {
	defer close(b.done)
	for {
		connection, err := b.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}
			b.recordError(err)
			break
		}
		b.waitGroup.Add(1)
		go func() {
			defer b.waitGroup.Done()
			defer connection.Close()
			if err := b.handle(connection); err != nil {
				b.recordError(err)
			}
		}()
	}
	b.waitGroup.Wait()
}

func (b *testRedisJournalBackend) handle(connection net.Conn) error {
	reader := bufio.NewReader(connection)
	auth, err := readTestRESPArray(reader)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(auth, []string{"AUTH", "journal-secret"}) {
		return fmt.Errorf("unexpected AUTH: %q", auth)
	}
	if _, err := io.WriteString(connection, "+OK\r\n"); err != nil {
		return err
	}
	command, err := readTestRESPArray(reader)
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
	wait, err := readTestRESPArray(reader)
	if err != nil {
		return err
	}
	if len(wait) != 3 || wait[0] != "WAIT" || wait[1] != "1" {
		return fmt.Errorf("unexpected WAIT: %q", wait)
	}
	b.mu.Lock()
	acknowledged := b.acknowledge
	b.mu.Unlock()
	_, err = fmt.Fprintf(connection, ":%d\r\n", acknowledged)
	return err
}

func (b *testRedisJournalBackend) evaluate(command []string) (string, bool, error) {
	if len(command) < 4 || command[0] != "EVAL" {
		return "", false, fmt.Errorf("unexpected command: %q", command)
	}
	keyCount, err := strconv.Atoi(command[2])
	if err != nil || keyCount < 1 || 3+keyCount > len(command) {
		return "", false, fmt.Errorf("invalid EVAL keys: %q", command)
	}
	keys := command[3 : 3+keyCount]
	arguments := command[3+keyCount:]
	b.mu.Lock()
	defer b.mu.Unlock()
	b.keys = append(b.keys, keys...)
	b.expireReplayKeys()
	switch command[1] {
	case redisReserveOperationScript:
		return b.reserve(keys, arguments)
	case redisReserveAcceptanceScript:
		return b.reserveAcceptance(keys, arguments)
	case redisLookupOperationScript:
		return b.lookup(keys, arguments)
	case redisMarkRunningScript:
		return b.transition(keys, arguments, operationjournal.StateAccepted, operationjournal.StateRunning)
	case redisMarkIndeterminateScript:
		return b.transition(keys, arguments, operationjournal.StateRunning, operationjournal.StateIndeterminate)
	case redisFinalizeOperationScript:
		return b.finalize(keys, arguments)
	case redisFinalizeResultScript:
		return b.finalizeResult(keys, arguments)
	case redisLookupResultScript:
		return b.lookupResult(keys, arguments)
	default:
		return "", false, errors.New("unknown Lua script")
	}
}

func (b *testRedisJournalBackend) reserve(keys, args []string) (string, bool, error) {
	if len(keys) != 1 || len(args) != 1 {
		return "", false, errors.New("invalid reserve arguments")
	}
	if raw, ok := b.values[keys[0]]; ok {
		record, err := testDecodeRedisRecord(raw)
		if err != nil {
			return redisJournalStatusCorrupt, false, nil
		}
		if record.RequestDigest != args[0] {
			return redisJournalStatusConflict, false, nil
		}
		return "EXISTING\n" + raw, false, nil
	}
	raw := b.newRecord(args[0])
	b.values[keys[0]] = raw
	return "CREATED\n" + raw, true, nil
}

func (b *testRedisJournalBackend) reserveAcceptance(keys, args []string) (string, bool, error) {
	if len(keys) != 2 || len(args) != 3 {
		return "", false, errors.New("invalid acceptance arguments")
	}
	if _, ok := b.values[keys[1]]; ok {
		return "REPLAY", false, nil
	}
	retainMillis, retainErr := strconv.ParseInt(args[1], 10, 64)
	maxTTL, maxErr := strconv.ParseInt(args[2], 10, 64)
	now := time.Now().UTC()
	ttl := time.UnixMilli(retainMillis).Sub(now)
	if retainErr != nil || maxErr != nil || ttl <= 0 {
		return "EXPIRED", false, nil
	}
	if ttl > time.Duration(maxTTL)*time.Millisecond {
		return "TTL_TOO_LONG", false, nil
	}
	raw, exists := b.values[keys[0]]
	if exists {
		record, err := testDecodeRedisRecord(raw)
		if err != nil {
			return redisJournalStatusCorrupt, false, nil
		}
		if record.RequestDigest != args[0] {
			return redisJournalStatusConflict, false, nil
		}
	} else {
		raw = b.newRecord(args[0])
	}
	b.values[keys[1]] = "1"
	b.expires[keys[1]] = now.Add(ttl)
	if !exists {
		b.values[keys[0]] = raw
		return "CREATED\n" + raw, true, nil
	}
	return "REPLAY_RESERVED\n" + raw, true, nil
}

func (b *testRedisJournalBackend) lookup(keys, args []string) (string, bool, error) {
	record, raw, status := b.exact(keys, args)
	if status != "" {
		return status, false, nil
	}
	_ = record
	return "FOUND\n" + raw, false, nil
}

func (b *testRedisJournalBackend) transition(keys, args []string, from, to operationjournal.State) (string, bool, error) {
	record, raw, status := b.exact(keys, args)
	if status != "" {
		return status, false, nil
	}
	if record.State == to {
		return "IDEMPOTENT\n" + raw, false, nil
	}
	if record.State != from {
		return redisJournalStatusInvalidTransition, false, nil
	}
	now := time.Now().UTC().UnixMilli()
	if now < record.UpdatedAtMillis {
		now = record.UpdatedAtMillis
	}
	record.State = to
	record.Revision++
	record.UpdatedAtMillis = now
	if to == operationjournal.StateRunning {
		record.StartedAtMillis = now
	}
	raw = testEncodeRedisRecord(record)
	b.values[keys[0]] = raw
	return "UPDATED\n" + raw, true, nil
}

func (b *testRedisJournalBackend) finalize(keys, args []string) (string, bool, error) {
	if len(args) != 3 {
		return "", false, errors.New("invalid finalization arguments")
	}
	record, raw, status := b.exact(keys, args[:1])
	if status != "" {
		return status, false, nil
	}
	state := operationjournal.State(args[1])
	if record.State.Terminal() {
		if record.State == state && record.OutcomeDigest == args[2] {
			return "IDEMPOTENT\n" + raw, false, nil
		}
		return redisJournalStatusConflict, false, nil
	}
	if record.State == operationjournal.StateAccepted && state != operationjournal.StateCanceled {
		return redisJournalStatusInvalidTransition, false, nil
	}
	return b.completeRecord(keys[0], record, state, args[2], redisJournalStatusUpdated)
}

func (b *testRedisJournalBackend) finalizeResult(keys, args []string) (string, bool, error) {
	if len(keys) != 2 || len(args) != 3 {
		return "", false, errors.New("invalid result finalization arguments")
	}
	record, raw, status := b.exact(keys[:1], args[:1])
	if status != "" {
		return status, false, nil
	}
	existingResult, hasResult := b.values[keys[1]]
	if record.State == operationjournal.StateSucceeded {
		if record.OutcomeDigest == args[1] && hasResult && existingResult == args[2] {
			return "IDEMPOTENT\n" + raw, false, nil
		}
		return redisJournalStatusConflict, false, nil
	}
	if record.State.Terminal() {
		return redisJournalStatusConflict, false, nil
	}
	if hasResult {
		return redisJournalStatusCorrupt, false, nil
	}
	if record.State != operationjournal.StateRunning && record.State != operationjournal.StateIndeterminate {
		return redisJournalStatusInvalidTransition, false, nil
	}
	b.values[keys[1]] = args[2]
	response, _, err := b.completeRecord(keys[0], record, operationjournal.StateSucceeded, args[1], "COMPLETED")
	return response, true, err
}

func (b *testRedisJournalBackend) lookupResult(keys, args []string) (string, bool, error) {
	record, raw, status := b.exact(keys[:1], args)
	if status != "" {
		return status, false, nil
	}
	if record.State != operationjournal.StateSucceeded || record.OutcomeDigest == "" {
		return redisJournalStatusInvalidTransition, false, nil
	}
	result, ok := b.values[keys[1]]
	if !ok {
		return "NO_RESULT", false, nil
	}
	return "FOUND_RESULT\n" + raw + "\n" + result, false, nil
}

func (b *testRedisJournalBackend) exact(keys, args []string) (redisJournalRecord, string, string) {
	if len(keys) != 1 || len(args) != 1 {
		return redisJournalRecord{}, "", redisJournalStatusCorrupt
	}
	raw, ok := b.values[keys[0]]
	if !ok {
		return redisJournalRecord{}, "", "NOT_FOUND"
	}
	record, err := testDecodeRedisRecord(raw)
	if err != nil {
		return redisJournalRecord{}, "", redisJournalStatusCorrupt
	}
	if record.RequestDigest != args[0] {
		return redisJournalRecord{}, "", redisJournalStatusConflict
	}
	return record, raw, ""
}

func (b *testRedisJournalBackend) completeRecord(key string, record redisJournalRecord, state operationjournal.State, outcome, status string) (string, bool, error) {
	now := time.Now().UTC().UnixMilli()
	if now < record.UpdatedAtMillis {
		now = record.UpdatedAtMillis
	}
	record.State = state
	record.OutcomeDigest = outcome
	record.Revision++
	record.UpdatedAtMillis = now
	record.CompletedMillis = now
	raw := testEncodeRedisRecord(record)
	b.values[key] = raw
	return status + "\n" + raw, true, nil
}

func (b *testRedisJournalBackend) newRecord(requestDigest string) string {
	now := time.Now().UTC().UnixMilli()
	return testEncodeRedisRecord(redisJournalRecord{
		Schema: redisOperationRecordSchema, RequestDigest: requestDigest, State: operationjournal.StateAccepted,
		Revision: 1, CreatedAtMillis: now, UpdatedAtMillis: now,
	})
}

func (b *testRedisJournalBackend) expireReplayKeys() {
	now := time.Now().UTC()
	for key, expires := range b.expires {
		if !now.Before(expires) {
			delete(b.expires, key)
			delete(b.values, key)
		}
	}
}

func (b *testRedisJournalBackend) recordError(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err == nil {
		b.err = err
	}
}

func (b *testRedisJournalBackend) assertHashedSameSlotKeys(t *testing.T, operationID, replayKey string) {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.keys) == 0 {
		t.Fatal("no Redis keys were observed")
	}
	wantTag := ""
	for _, key := range b.keys {
		if strings.Contains(key, operationID) || strings.Contains(key, replayKey) {
			t.Fatalf("Redis key contains unhashed application material: %q", key)
		}
		start := strings.IndexByte(key, '{')
		end := strings.IndexByte(key, '}')
		if start < 0 || end <= start+1 {
			t.Fatalf("Redis key has no hash slot: %q", key)
		}
		tag := key[start+1 : end]
		if wantTag == "" {
			wantTag = tag
		} else if tag != wantTag {
			t.Fatalf("Redis keys use different hash slots: %q and %q", wantTag, tag)
		}
		if _, hasTTL := b.expires[key]; hasTTL && !strings.Contains(key, ":replay:") {
			t.Fatalf("operation or result key unexpectedly expires: %q", key)
		}
	}
}

func testEncodeRedisRecord(record redisJournalRecord) string {
	payload, err := json.Marshal(record)
	if err != nil {
		panic(err)
	}
	return string(payload)
}

func testDecodeRedisRecord(raw string) (redisJournalRecord, error) {
	var record redisJournalRecord
	err := json.Unmarshal([]byte(raw), &record)
	return record, err
}
