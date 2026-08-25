// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package operationjournal

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileStoreFinalizesAndRecoversSealedResultAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.json")
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	reservation := Reservation{OperationID: "sealed-result", RequestDigest: testDigest("request")}
	if _, _, err := store.Reserve(context.Background(), reservation); err != nil {
		t.Fatal(err)
	}
	if _, started, err := store.MarkRunning(context.Background(), reservation.OperationID, reservation.RequestDigest); err != nil || !started {
		t.Fatalf("MarkRunning() = (_, %v, %v)", started, err)
	}
	result := testSealedResult(reservation, testDigest("result"), 7)
	final := Finalization{
		OperationID: reservation.OperationID, RequestDigest: reservation.RequestDigest,
		State: StateSucceeded, OutcomeDigest: result.OutcomeDigest,
	}
	record, err := store.FinalizeWithResult(context.Background(), final, result)
	if err != nil || record.State != StateSucceeded || record.OutcomeDigest != result.OutcomeDigest {
		t.Fatalf("FinalizeWithResult() = (%+v, %v)", record, err)
	}

	gotRecord, got, err := store.LookupResult(context.Background(), reservation.OperationID, reservation.RequestDigest)
	if err != nil || gotRecord != record || !sealedResultsEqual(got, result) {
		t.Fatalf("LookupResult() = (%+v, %+v, %v)", gotRecord, got, err)
	}
	got.Nonce[0] ^= 0xff
	got.Ciphertext[0] ^= 0xff
	_, again, err := store.LookupResult(context.Background(), reservation.OperationID, reservation.RequestDigest)
	if err != nil || !sealedResultsEqual(again, result) {
		t.Fatal("LookupResult returned mutable store-owned bytes")
	}
	if _, _, err := store.LookupResult(context.Background(), reservation.OperationID, testDigest("other request")); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong-digest LookupResult() error = %v, want %v", err, ErrConflict)
	}

	restarted, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	_, recovered, err := restarted.LookupResult(context.Background(), reservation.OperationID, reservation.RequestDigest)
	if err != nil || !sealedResultsEqual(recovered, result) {
		t.Fatalf("restart LookupResult() = (%+v, %v)", recovered, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("plaintext model response")) {
		t.Fatal("journal contains plaintext result")
	}
}

func TestFileStoreCompletionFailureDoesNotPublishTerminalStateOrResult(t *testing.T) {
	store, err := OpenFileStore(filepath.Join(t.TempDir(), "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	reservation := Reservation{OperationID: "sealed-result-failure", RequestDigest: testDigest("request")}
	if _, _, err := store.Reserve(context.Background(), reservation); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.MarkRunning(context.Background(), reservation.OperationID, reservation.RequestDigest); err != nil {
		t.Fatal(err)
	}
	store.beforeCommit = func() error { return errors.New("injected commit failure") }
	result := testSealedResult(reservation, testDigest("result"), 11)
	_, err = store.FinalizeWithResult(context.Background(), Finalization{
		OperationID: reservation.OperationID, RequestDigest: reservation.RequestDigest,
		State: StateSucceeded, OutcomeDigest: result.OutcomeDigest,
	}, result)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("FinalizeWithResult() error = %v, want %v", err, ErrUnavailable)
	}
	store.beforeCommit = nil
	record, err := store.Lookup(context.Background(), reservation.OperationID, reservation.RequestDigest)
	if err != nil || record.State.Terminal() || record.State != StateRunning {
		t.Fatalf("record after failed atomic completion = (%+v, %v)", record, err)
	}
	if _, _, err := store.LookupResult(context.Background(), reservation.OperationID, reservation.RequestDigest); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("LookupResult() after failed completion = %v, want %v", err, ErrInvalidTransition)
	}
}

func TestValidateSealedResultRejectsUnboundedOrAmbiguousEnvelope(t *testing.T) {
	reservation := Reservation{OperationID: "sealed-result-validation", RequestDigest: testDigest("request")}
	valid := testSealedResult(reservation, testDigest("result"), 3)
	tests := []SealedResult{
		func() SealedResult { value := cloneSealedResult(valid); value.Envelope = "AES-GCM"; return value }(),
		func() SealedResult { value := cloneSealedResult(valid); value.MediaType = "TEXT/PLAIN"; return value }(),
		func() SealedResult { value := cloneSealedResult(valid); value.Nonce = value.Nonce[:11]; return value }(),
		func() SealedResult {
			value := cloneSealedResult(valid)
			value.Ciphertext = value.Ciphertext[:18]
			return value
		}(),
		func() SealedResult {
			value := cloneSealedResult(valid)
			value.PlaintextBytes = 256<<10 + 1
			return value
		}(),
		func() SealedResult {
			value := cloneSealedResult(valid)
			value.OutcomeDigest = strings.ToUpper(value.OutcomeDigest)
			return value
		}(),
	}
	for i, value := range tests {
		if err := ValidateSealedResult(value); !errors.Is(err, ErrInvalidRecord) {
			t.Errorf("case %d error = %v, want %v", i, err, ErrInvalidRecord)
		}
	}
}

func testSealedResult(reservation Reservation, outcomeDigest string, plaintextBytes uint32) SealedResult {
	return SealedResult{
		OperationID: reservation.OperationID, RequestDigest: reservation.RequestDigest,
		OutcomeDigest: outcomeDigest, MediaType: "application/a2a+json",
		Envelope: SealedResultEnvelopeV1, PlaintextBytes: plaintextBytes,
		Nonce: bytes.Repeat([]byte{0x11}, aesGCMNonceBytes), Ciphertext: bytes.Repeat([]byte{0x22}, int(plaintextBytes)+aesGCMTagBytes),
	}
}
