// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/thinksyncs/agents-secure-binding/pkg/operationjournal"
)

func TestResultSealerV2BindsExactOperationAndResponse(t *testing.T) {
	sealer, err := newResultSealerV2(bytes.Repeat([]byte{0x31}, resultSealingKeyBytesV2), bytes.NewReader(bytes.Repeat([]byte{0x52}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	reservation := operationjournal.Reservation{
		OperationID: "a2a-v2:" + strings.Repeat("2", 64), RequestDigest: "sha256:" + strings.Repeat("3", 64),
	}
	want := testOperationResultV2(t, "recoverable output")
	sealed, err := sealer.seal(reservation, want)
	if err != nil {
		t.Fatal(err)
	}
	record := operationjournal.Record{
		OperationID: reservation.OperationID, RequestDigest: reservation.RequestDigest,
		State: operationjournal.StateSucceeded, OutcomeDigest: sealed.OutcomeDigest,
	}
	got, err := sealer.open(record, sealed)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("open() = (%+v, %v)", got, err)
	}

	tests := []operationjournal.SealedResult{
		func() operationjournal.SealedResult {
			value := cloneTestSealedResultV2(sealed)
			value.OperationID = "a2a-v2:" + strings.Repeat("4", 64)
			return value
		}(),
		func() operationjournal.SealedResult {
			value := cloneTestSealedResultV2(sealed)
			value.OutcomeDigest = "sha256:" + strings.Repeat("5", 64)
			return value
		}(),
		func() operationjournal.SealedResult {
			value := cloneTestSealedResultV2(sealed)
			value.MediaType = problemMediaType
			return value
		}(),
		func() operationjournal.SealedResult {
			value := cloneTestSealedResultV2(sealed)
			value.Ciphertext[0] ^= 0xff
			return value
		}(),
	}
	for i, value := range tests {
		if _, err := sealer.open(record, value); err == nil {
			t.Errorf("tamper case %d was accepted", i)
		}
	}
}

func TestLoadResultSealerV2RequiresOwnerOnlyRegularKey(t *testing.T) {
	directory := t.TempDir()
	validPath := filepath.Join(directory, "valid.key")
	if err := os.WriteFile(validPath, bytes.Repeat([]byte{0x77}, resultSealingKeyBytesV2), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadResultSealerV2(validPath); err != nil {
		t.Fatalf("loadResultSealerV2(valid) error = %v", err)
	}
	if err := os.Chmod(validPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadResultSealerV2(validPath); err == nil {
		t.Fatal("group-readable key was accepted")
	}
	shortPath := filepath.Join(directory, "short.key")
	if err := os.WriteFile(shortPath, bytes.Repeat([]byte{0x11}, resultSealingKeyBytesV2-1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadResultSealerV2(shortPath); err == nil {
		t.Fatal("short key was accepted")
	}
	linkPath := filepath.Join(directory, "link.key")
	if err := os.Symlink(shortPath, linkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := loadResultSealerV2(linkPath); err == nil {
		t.Fatal("symlinked key was accepted")
	}
}

func TestBootstrapCreatesAgentBOnlyResultSealingKey(t *testing.T) {
	stateDir := t.TempDir()
	if err := bootstrapState(stateDir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(roleDirectory(stateDir, "agent-b"), resultSealingKeyFileV2)
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != resultSealingKeyBytesV2 {
		t.Fatalf("result sealing key = mode %v size %d", info.Mode(), info.Size())
	}
	if _, err := os.Lstat(filepath.Join(roleDirectory(stateDir, "replay"), resultSealingKeyFileV2)); !os.IsNotExist(err) {
		t.Fatalf("replay role received result sealing key: %v", err)
	}
}

func TestOperationResultLookupRequiresAuthenticatedAgentB(t *testing.T) {
	store := openOperationAcceptanceTestStore(t)
	reservation := operationjournal.Reservation{
		OperationID: "a2a-v2:" + strings.Repeat("6", 64), RequestDigest: "sha256:" + strings.Repeat("7", 64),
	}
	if _, _, err := store.Reserve(context.Background(), reservation); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.MarkRunning(context.Background(), reservation.OperationID, reservation.RequestDigest); err != nil {
		t.Fatal(err)
	}
	sealer, err := newResultSealerV2(bytes.Repeat([]byte{0x42}, resultSealingKeyBytesV2), bytes.NewReader(bytes.Repeat([]byte{0x19}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	result, err := sealer.seal(reservation, testOperationResultV2(t, "protected result"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.FinalizeWithResult(context.Background(), operationjournal.Finalization{
		OperationID: reservation.OperationID, RequestDigest: reservation.RequestDigest,
		State: operationjournal.StateSucceeded, OutcomeDigest: result.OutcomeDigest,
	}, result); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerOperationJournalV2(mux, store)
	payload, err := json.Marshal(operationRequestV2(reservation))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, operationResultPathV2, bytes.NewReader(payload))
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("unauthenticated lookup status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
}

func cloneTestSealedResultV2(result operationjournal.SealedResult) operationjournal.SealedResult {
	result.Nonce = append([]byte(nil), result.Nonce...)
	result.Ciphertext = append([]byte(nil), result.Ciphertext...)
	return result
}

func TestCompletedOperationResultV2ReturnsExactStoredBytes(t *testing.T) {
	completedAt := time.Date(2026, 8, 25, 12, 34, 56, 123, time.UTC)
	result, err := completedOperationResultV2(newTaskRequestV2(), "exact bytes", completedAt)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	writeOperationResultV2(recorder, result)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != a2aMediaType || !bytes.Equal(recorder.Body.Bytes(), result.Body) {
		t.Fatalf("written response differs from stored bytes")
	}
}
