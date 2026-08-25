// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/thinksyncs/agents-secure-binding/pkg/atls/identitypolicy"
	"github.com/thinksyncs/agents-secure-binding/pkg/operationjournal"
)

const (
	acceptanceStateFileV2        = "acceptance-v2-state.json"
	acceptancePathV2             = "/acceptance-v2"
	operationRunningPathV2       = "/operations-v2/mark-running"
	operationIndeterminatePathV2 = "/operations-v2/mark-indeterminate"
	operationFinalizePathV2      = "/operations-v2/finalize"
	operationCompletePathV2      = "/operations-v2/complete"
	operationResultPathV2        = "/operations-v2/result"
	operationTransitionTimeoutV2 = 5 * time.Second
	operationStoreMaxBodySizeV2  = 512 * 1024
)

var errOperationAcceptanceExpiredV2 = errors.New("accepted assertion expired before operation start")

type acceptanceRequestV2 struct {
	ReplayKey         string                       `json:"replay_key"`
	ReplayRetainUntil time.Time                    `json:"replay_retain_until"`
	Operation         operationjournal.Reservation `json:"operation"`
}

type acceptanceResponseV2 struct {
	Record           operationjournal.Record `json:"record"`
	OperationCreated bool                    `json:"operation_created"`
}

type operationRequestV2 struct {
	OperationID   string `json:"operation_id"`
	RequestDigest string `json:"request_digest"`
}

type operationRunningResponseV2 struct {
	Record  operationjournal.Record `json:"record"`
	Started bool                    `json:"started"`
}

type operationRecordResponseV2 struct {
	Record operationjournal.Record `json:"record"`
}

type operationFinalizationRequestV2 struct {
	OperationID   string                 `json:"operation_id"`
	RequestDigest string                 `json:"request_digest"`
	State         operationjournal.State `json:"state"`
	OutcomeDigest string                 `json:"outcome_digest,omitempty"`
}

type operationCompletionRequestV2 struct {
	Finalization operationFinalizationRequestV2 `json:"finalization"`
	Result       operationjournal.SealedResult  `json:"sealed_result"`
}

type operationResultResponseV2 struct {
	Record operationjournal.Record       `json:"record"`
	Result operationjournal.SealedResult `json:"sealed_result"`
}

type httpOperationJournalClientV2 struct {
	client *http.Client
	url    string
	sealer *resultSealerV2
}

// operationSessionV2 is request-scoped. Its ReplayCache method is the commit
// point used by the identity verifier; execution state is updated only after
// that commit succeeds.
type operationSessionV2 struct {
	mu          sync.Mutex
	ctx         context.Context
	client      *httpOperationJournalClientV2
	reservation operationjournal.Reservation
	committed   bool
}

type operationStateErrorV2 struct {
	Record operationjournal.Record
}

func (e *operationStateErrorV2) Error() string {
	return fmt.Sprintf("operation is already in state %s", e.Record.State)
}

type operationExecutionErrorV2 struct {
	Err error
}

func (e *operationExecutionErrorV2) Error() string {
	return fmt.Sprintf("accepted operation execution failed: %v", e.Err)
}

func (e *operationExecutionErrorV2) Unwrap() error { return e.Err }

func newOperationSessionV2(ctx context.Context, client *httpOperationJournalClientV2, reservation operationjournal.Reservation) *operationSessionV2 {
	return &operationSessionV2{ctx: ctx, client: client, reservation: reservation}
}

func (s *operationSessionV2) MarkUsed(key string, retainUntil time.Time) error {
	if s == nil || s.client == nil || s.ctx == nil {
		return operationjournal.ErrUnavailable
	}
	_, _, err := s.client.reserveAcceptance(s.ctx, operationjournal.AcceptanceReservation{
		ReplayKey: key, ReplayRetainUntil: retainUntil, Operation: s.reservation,
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.committed = true
	s.mu.Unlock()
	return nil
}

func (s *operationSessionV2) executeOnce(ctx context.Context, acceptedUntil time.Time, clock func() time.Time, execute func(context.Context) (operationResultV2, error)) (operationResultV2, error) {
	if s == nil || s.client == nil || clock == nil || execute == nil {
		return operationResultV2{}, operationjournal.ErrUnavailable
	}
	s.mu.Lock()
	committed := s.committed
	s.mu.Unlock()
	if !committed {
		return operationResultV2{}, operationjournal.ErrUnavailable
	}
	now := clock()
	if now.IsZero() || acceptedUntil.IsZero() || !now.Before(acceptedUntil) {
		return operationResultV2{}, errOperationAcceptanceExpiredV2
	}

	record, started, err := s.client.markRunning(ctx, s.reservation)
	if err != nil {
		return operationResultV2{}, err
	}
	if !started {
		if record.State == operationjournal.StateSucceeded {
			result, err := s.client.recoverResult(ctx, s.reservation)
			if err != nil {
				return operationResultV2{}, err
			}
			return result, nil
		}
		return operationResultV2{}, &operationStateErrorV2{Record: record}
	}
	now = clock()
	if now.IsZero() || !now.Before(acceptedUntil) {
		transitionCtx, cancel := context.WithTimeout(context.Background(), operationTransitionTimeoutV2)
		defer cancel()
		if _, err := s.client.finalize(transitionCtx, operationjournal.Finalization{
			OperationID: s.reservation.OperationID, RequestDigest: s.reservation.RequestDigest,
			State: operationjournal.StateCanceled,
		}); err != nil {
			return operationResultV2{}, fmt.Errorf("%w: cancel operation after acceptance expiry: %v", operationjournal.ErrUnavailable, err)
		}
		return operationResultV2{}, errOperationAcceptanceExpiredV2
	}

	result, executionErr := execute(ctx)
	if executionErr != nil {
		transitionCtx, cancel := context.WithTimeout(context.Background(), operationTransitionTimeoutV2)
		defer cancel()
		if _, err := s.client.markIndeterminate(transitionCtx, s.reservation); err != nil {
			return operationResultV2{}, fmt.Errorf("%w: record indeterminate operation: %v", operationjournal.ErrUnavailable, err)
		}
		return operationResultV2{}, &operationExecutionErrorV2{Err: executionErr}
	}
	sealed, err := s.client.sealResult(s.reservation, result)
	if err != nil {
		transitionCtx, cancel := context.WithTimeout(context.Background(), operationTransitionTimeoutV2)
		defer cancel()
		if _, transitionErr := s.client.markIndeterminate(transitionCtx, s.reservation); transitionErr != nil {
			return operationResultV2{}, fmt.Errorf("%w: seal result: %v; record indeterminate operation: %v", operationjournal.ErrUnavailable, err, transitionErr)
		}
		return operationResultV2{}, &operationExecutionErrorV2{Err: err}
	}

	transitionCtx, cancel := context.WithTimeout(context.Background(), operationTransitionTimeoutV2)
	defer cancel()
	if _, err := s.client.complete(transitionCtx, operationjournal.Finalization{
		OperationID: s.reservation.OperationID, RequestDigest: s.reservation.RequestDigest,
		State: operationjournal.StateSucceeded, OutcomeDigest: sealed.OutcomeDigest,
	}, sealed); err != nil {
		// The atomic commit can have succeeded even when the response was lost.
		// Never release an unconfirmed result; a fresh authenticated retry uses
		// the exact operation tuple to recover it.
		return operationResultV2{}, err
	}
	return result, nil
}

// applicationOperationV2 derives an idempotency identity from application
// fields only. Grant, proof, nonce, TLS, and attestation metadata are absent.
func applicationOperationV2(request a2aSendMessageRequest, contexts requestContextsV2) (operationjournal.Reservation, error) {
	operationIdentity := append([]byte(nil), []byte("ASB-A2A-OPERATION-ID-v2\x00")...)
	var err error
	operationIdentity, err = appendFieldV2(operationIdentity, "task_id", []byte(request.Message.TaskID))
	if err != nil {
		return operationjournal.Reservation{}, err
	}
	operationIdentity, err = appendFieldV2(operationIdentity, "context_id", []byte(request.Message.ContextID))
	if err != nil {
		return operationjournal.Reservation{}, err
	}
	operationIdentity, err = appendFieldV2(operationIdentity, "message_id", []byte(request.Message.MessageID))
	if err != nil {
		return operationjournal.Reservation{}, err
	}
	idHash := sha256.Sum256(operationIdentity)

	applicationRequest := append([]byte(nil), []byte("ASB-A2A-APPLICATION-REQUEST-v2\x00")...)
	applicationRequest, err = appendFieldV2(applicationRequest, "task_context", contexts.Task)
	if err != nil {
		return operationjournal.Reservation{}, err
	}
	applicationRequest, err = appendFieldV2(applicationRequest, "target_context", contexts.Target)
	if err != nil {
		return operationjournal.Reservation{}, err
	}
	return operationjournal.Reservation{
		OperationID:   "a2a-v2:" + hex.EncodeToString(idHash[:]),
		RequestDigest: sha256String(applicationRequest),
	}, nil
}

func (c *httpOperationJournalClientV2) reserveAcceptance(ctx context.Context, request operationjournal.AcceptanceReservation) (operationjournal.Record, bool, error) {
	var response acceptanceResponseV2
	err := c.post(ctx, acceptancePathV2, acceptanceRequestV2{
		ReplayKey: request.ReplayKey, ReplayRetainUntil: request.ReplayRetainUntil, Operation: request.Operation,
	}, &response)
	if err != nil {
		return operationjournal.Record{}, false, err
	}
	if response.Record.OperationID != request.Operation.OperationID || response.Record.RequestDigest != request.Operation.RequestDigest ||
		(response.OperationCreated && response.Record.State != operationjournal.StateAccepted) {
		return operationjournal.Record{}, false, operationjournal.ErrUnavailable
	}
	return response.Record, response.OperationCreated, nil
}

func (c *httpOperationJournalClientV2) markRunning(ctx context.Context, request operationjournal.Reservation) (operationjournal.Record, bool, error) {
	var response operationRunningResponseV2
	if err := c.post(ctx, operationRunningPathV2, operationRequestV2(request), &response); err != nil {
		return operationjournal.Record{}, false, err
	}
	if response.Record.OperationID != request.OperationID || response.Record.RequestDigest != request.RequestDigest ||
		(response.Started && response.Record.State != operationjournal.StateRunning) {
		return operationjournal.Record{}, false, operationjournal.ErrUnavailable
	}
	return response.Record, response.Started, nil
}

func (c *httpOperationJournalClientV2) markIndeterminate(ctx context.Context, request operationjournal.Reservation) (operationjournal.Record, error) {
	var response operationRecordResponseV2
	if err := c.post(ctx, operationIndeterminatePathV2, operationRequestV2(request), &response); err != nil {
		return operationjournal.Record{}, err
	}
	if response.Record.OperationID != request.OperationID || response.Record.RequestDigest != request.RequestDigest || response.Record.State != operationjournal.StateIndeterminate {
		return operationjournal.Record{}, operationjournal.ErrUnavailable
	}
	return response.Record, nil
}

func (c *httpOperationJournalClientV2) finalize(ctx context.Context, final operationjournal.Finalization) (operationjournal.Record, error) {
	var response operationRecordResponseV2
	if err := c.post(ctx, operationFinalizePathV2, operationFinalizationRequestV2(final), &response); err != nil {
		return operationjournal.Record{}, err
	}
	if response.Record.OperationID != final.OperationID || response.Record.RequestDigest != final.RequestDigest ||
		response.Record.State != final.State || response.Record.OutcomeDigest != final.OutcomeDigest {
		return operationjournal.Record{}, operationjournal.ErrUnavailable
	}
	return response.Record, nil
}

func (c *httpOperationJournalClientV2) sealResult(reservation operationjournal.Reservation, result operationResultV2) (operationjournal.SealedResult, error) {
	if c == nil || c.sealer == nil {
		return operationjournal.SealedResult{}, operationjournal.ErrUnavailable
	}
	return c.sealer.seal(reservation, result)
}

func (c *httpOperationJournalClientV2) complete(ctx context.Context, final operationjournal.Finalization, result operationjournal.SealedResult) (operationjournal.Record, error) {
	var response operationRecordResponseV2
	request := operationCompletionRequestV2{
		Finalization: operationFinalizationRequestV2(final),
		Result:       result,
	}
	if err := c.post(ctx, operationCompletePathV2, request, &response); err != nil {
		return operationjournal.Record{}, err
	}
	if response.Record.OperationID != final.OperationID || response.Record.RequestDigest != final.RequestDigest ||
		response.Record.State != operationjournal.StateSucceeded || response.Record.OutcomeDigest != final.OutcomeDigest {
		return operationjournal.Record{}, operationjournal.ErrUnavailable
	}
	return response.Record, nil
}

func (c *httpOperationJournalClientV2) lookupResult(ctx context.Context, request operationjournal.Reservation) (operationjournal.Record, operationjournal.SealedResult, error) {
	var response operationResultResponseV2
	if err := c.post(ctx, operationResultPathV2, operationRequestV2(request), &response); err != nil {
		return operationjournal.Record{}, operationjournal.SealedResult{}, err
	}
	if response.Record.OperationID != request.OperationID || response.Record.RequestDigest != request.RequestDigest ||
		response.Record.State != operationjournal.StateSucceeded || response.Record.OutcomeDigest == "" ||
		response.Result.OperationID != request.OperationID || response.Result.RequestDigest != request.RequestDigest ||
		response.Result.OutcomeDigest != response.Record.OutcomeDigest {
		return operationjournal.Record{}, operationjournal.SealedResult{}, operationjournal.ErrUnavailable
	}
	return response.Record, response.Result, nil
}

func (c *httpOperationJournalClientV2) recoverResult(ctx context.Context, request operationjournal.Reservation) (operationResultV2, error) {
	if c == nil || c.sealer == nil {
		return operationResultV2{}, operationjournal.ErrUnavailable
	}
	record, sealed, err := c.lookupResult(ctx, request)
	if err != nil {
		return operationResultV2{}, err
	}
	result, err := c.sealer.open(record, sealed)
	if err != nil {
		return operationResultV2{}, fmt.Errorf("%w: verify recovered result: %v", operationjournal.ErrUnavailable, err)
	}
	return result, nil
}

func (c *httpOperationJournalClientV2) post(ctx context.Context, path string, input, output any) error {
	if c == nil || c.client == nil || strings.TrimSpace(c.url) == "" || ctx == nil {
		return operationjournal.ErrUnavailable
	}
	payload, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("%w: encode operation request: %v", operationjournal.ErrUnavailable, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.url, "/")+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("%w: create operation request: %v", operationjournal.ErrUnavailable, err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("%w: send operation request: %v", operationjournal.ErrUnavailable, err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var remote problem
		_ = json.NewDecoder(io.LimitReader(response.Body, operationStoreMaxBodySizeV2)).Decode(&remote)
		switch remote.Reason {
		case "replay-detected":
			return identitypolicy.ErrReplayDetected
		case "operation-conflict":
			return operationjournal.ErrConflict
		case "operation-not-found":
			return operationjournal.ErrNotFound
		case "invalid-operation":
			return operationjournal.ErrInvalidRecord
		default:
			return operationjournal.ErrUnavailable
		}
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, operationStoreMaxBodySizeV2+1))
	if err != nil || len(raw) > operationStoreMaxBodySizeV2 {
		return fmt.Errorf("%w: operation response exceeds its size limit", operationjournal.ErrUnavailable)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("%w: decode operation response: %v", operationjournal.ErrUnavailable, err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("%w: trailing operation response", operationjournal.ErrUnavailable)
	}
	return nil
}

func registerOperationJournalV2(mux *http.ServeMux, store operationjournal.ResultStore) {
	mux.HandleFunc("POST "+acceptancePathV2, func(w http.ResponseWriter, r *http.Request) {
		if !requireOperationStorePeerV2(w, r) {
			return
		}
		var request acceptanceRequestV2
		if !decodeJSON(w, r, &request) {
			return
		}
		record, created, err := store.ReserveAcceptance(r.Context(), operationjournal.AcceptanceReservation{
			ReplayKey: request.ReplayKey, ReplayRetainUntil: request.ReplayRetainUntil, Operation: request.Operation,
		})
		if err != nil {
			writeOperationStoreErrorV2(w, err)
			return
		}
		writeJSON(w, http.StatusOK, "application/json", acceptanceResponseV2{Record: record, OperationCreated: created})
	})
	mux.HandleFunc("POST "+operationRunningPathV2, func(w http.ResponseWriter, r *http.Request) {
		if !requireOperationStorePeerV2(w, r) {
			return
		}
		var request operationRequestV2
		if !decodeJSON(w, r, &request) {
			return
		}
		reservation := operationjournal.Reservation(request)
		record, started, err := store.MarkRunning(r.Context(), reservation.OperationID, reservation.RequestDigest)
		if errors.Is(err, operationjournal.ErrInvalidTransition) {
			record, err = store.Lookup(r.Context(), reservation.OperationID, reservation.RequestDigest)
		}
		if err != nil {
			writeOperationStoreErrorV2(w, err)
			return
		}
		writeJSON(w, http.StatusOK, "application/json", operationRunningResponseV2{Record: record, Started: started})
	})
	mux.HandleFunc("POST "+operationIndeterminatePathV2, func(w http.ResponseWriter, r *http.Request) {
		if !requireOperationStorePeerV2(w, r) {
			return
		}
		var request operationRequestV2
		if !decodeJSON(w, r, &request) {
			return
		}
		record, err := store.MarkIndeterminate(r.Context(), request.OperationID, request.RequestDigest)
		if err != nil {
			writeOperationStoreErrorV2(w, err)
			return
		}
		writeJSON(w, http.StatusOK, "application/json", operationRecordResponseV2{Record: record})
	})
	mux.HandleFunc("POST "+operationFinalizePathV2, func(w http.ResponseWriter, r *http.Request) {
		if !requireOperationStorePeerV2(w, r) {
			return
		}
		var request operationFinalizationRequestV2
		if !decodeJSON(w, r, &request) {
			return
		}
		record, err := store.Finalize(r.Context(), operationjournal.Finalization(request))
		if err != nil {
			writeOperationStoreErrorV2(w, err)
			return
		}
		writeJSON(w, http.StatusOK, "application/json", operationRecordResponseV2{Record: record})
	})
	mux.HandleFunc("POST "+operationCompletePathV2, func(w http.ResponseWriter, r *http.Request) {
		if !requireOperationStorePeerV2(w, r) {
			return
		}
		var request operationCompletionRequestV2
		if !decodeOperationStoreJSONV2(w, r, &request) {
			return
		}
		record, err := store.FinalizeWithResult(r.Context(), operationjournal.Finalization(request.Finalization), request.Result)
		if err != nil {
			writeOperationStoreErrorV2(w, err)
			return
		}
		writeJSON(w, http.StatusOK, "application/json", operationRecordResponseV2{Record: record})
	})
	mux.HandleFunc("POST "+operationResultPathV2, func(w http.ResponseWriter, r *http.Request) {
		if !requireOperationStorePeerV2(w, r) {
			return
		}
		var request operationRequestV2
		if !decodeJSON(w, r, &request) {
			return
		}
		record, result, err := store.LookupResult(r.Context(), request.OperationID, request.RequestDigest)
		if err != nil {
			writeOperationStoreErrorV2(w, err)
			return
		}
		writeJSON(w, http.StatusOK, "application/json", operationResultResponseV2{Record: record, Result: result})
	})
}

func decodeOperationStoreJSONV2(w http.ResponseWriter, r *http.Request, target any) bool {
	raw, err := io.ReadAll(io.LimitReader(r.Body, operationStoreMaxBodySizeV2+1))
	if err != nil || len(raw) > operationStoreMaxBodySizeV2 {
		writeProblem(w, http.StatusBadRequest, "invalid-request", "Invalid request", "operation request exceeds its size limit")
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeProblem(w, http.StatusBadRequest, "invalid-request", "Invalid request", "operation request is not valid for this endpoint")
		return false
	}
	return true
}

func requireOperationStorePeerV2(w http.ResponseWriter, r *http.Request) bool {
	if err := requirePeer(r, demoAudience); err != nil {
		writeProblem(w, http.StatusForbidden, "client-identity", "Client identity rejected", err.Error())
		return false
	}
	return true
}

func writeOperationStoreErrorV2(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, operationjournal.ErrReplay):
		writeProblem(w, http.StatusConflict, "replay-detected", "Replay detected", "the verifier nonce is already reserved")
	case errors.Is(err, operationjournal.ErrConflict):
		writeProblem(w, http.StatusConflict, "operation-conflict", "Operation conflict", "the operation ID is bound to another request")
	case errors.Is(err, operationjournal.ErrNotFound):
		writeProblem(w, http.StatusNotFound, "operation-not-found", "Operation not found", "the exact operation reservation does not exist")
	case errors.Is(err, operationjournal.ErrInvalidRecord), errors.Is(err, operationjournal.ErrInvalidTransition):
		writeProblem(w, http.StatusBadRequest, "invalid-operation", "Invalid operation", "the operation record or transition is invalid")
	default:
		writeProblem(w, http.StatusServiceUnavailable, "operation-store", "Operation store unavailable", "durable operation state could not be committed")
	}
}
