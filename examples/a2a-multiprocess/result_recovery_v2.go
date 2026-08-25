// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/thinksyncs/agents-secure-binding/pkg/operationjournal"
)

const resultSealingKeyBytesV2 = 32

type operationResultV2 struct {
	MediaType string
	Body      []byte
}

// resultSealerV2 is owned by Agent B. The operation store receives only an
// authenticated ciphertext and cannot read model or task output.
type resultSealerV2 struct {
	aead       cipher.AEAD
	randomness io.Reader
}

func loadResultSealerV2(path string) (*resultSealerV2, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect result sealing key: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() != resultSealingKeyBytesV2 {
		return nil, fmt.Errorf("result sealing key must be a regular, owner-only 32-byte file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open result sealing key: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) || openedInfo.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("result sealing key changed while opening")
	}
	key, err := io.ReadAll(io.LimitReader(file, resultSealingKeyBytesV2+1))
	if err != nil || len(key) != resultSealingKeyBytesV2 {
		return nil, fmt.Errorf("read result sealing key: expected exactly 32 bytes")
	}
	defer clear(key)
	return newResultSealerV2(key, rand.Reader)
}

func newResultSealerV2(key []byte, randomness io.Reader) (*resultSealerV2, error) {
	if len(key) != resultSealingKeyBytesV2 || randomness == nil {
		return nil, fmt.Errorf("invalid result sealing configuration")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create result cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create result AEAD: %w", err)
	}
	return &resultSealerV2{aead: aead, randomness: randomness}, nil
}

func (s *resultSealerV2) seal(reservation operationjournal.Reservation, result operationResultV2) (operationjournal.SealedResult, error) {
	if s == nil || s.aead == nil || s.randomness == nil {
		return operationjournal.SealedResult{}, fmt.Errorf("result sealer is unavailable")
	}
	if err := validateOperationResultV2(result); err != nil {
		return operationjournal.SealedResult{}, err
	}
	sealed := operationjournal.SealedResult{
		OperationID: reservation.OperationID, RequestDigest: reservation.RequestDigest,
		OutcomeDigest: operationOutcomeDigestV2(result), MediaType: result.MediaType,
		Envelope: operationjournal.SealedResultEnvelopeV1, PlaintextBytes: uint32(len(result.Body)),
		Nonce: make([]byte, s.aead.NonceSize()),
	}
	if _, err := io.ReadFull(s.randomness, sealed.Nonce); err != nil {
		return operationjournal.SealedResult{}, fmt.Errorf("generate result nonce: %w", err)
	}
	aad, err := sealedResultAADV2(sealed)
	if err != nil {
		return operationjournal.SealedResult{}, err
	}
	sealed.Ciphertext = s.aead.Seal(nil, sealed.Nonce, result.Body, aad)
	if err := operationjournal.ValidateSealedResult(sealed); err != nil {
		return operationjournal.SealedResult{}, err
	}
	return sealed, nil
}

func (s *resultSealerV2) open(record operationjournal.Record, sealed operationjournal.SealedResult) (operationResultV2, error) {
	if s == nil || s.aead == nil {
		return operationResultV2{}, fmt.Errorf("result sealer is unavailable")
	}
	if err := operationjournal.ValidateSealedResult(sealed); err != nil {
		return operationResultV2{}, err
	}
	if record.State != operationjournal.StateSucceeded || record.OperationID != sealed.OperationID ||
		record.RequestDigest != sealed.RequestDigest || record.OutcomeDigest != sealed.OutcomeDigest {
		return operationResultV2{}, fmt.Errorf("sealed result does not match the successful operation")
	}
	aad, err := sealedResultAADV2(sealed)
	if err != nil {
		return operationResultV2{}, err
	}
	body, err := s.aead.Open(nil, sealed.Nonce, sealed.Ciphertext, aad)
	if err != nil {
		return operationResultV2{}, fmt.Errorf("open sealed result: authenticated decryption failed")
	}
	if len(body) != int(sealed.PlaintextBytes) {
		return operationResultV2{}, fmt.Errorf("opened result length does not match its envelope")
	}
	result := operationResultV2{MediaType: sealed.MediaType, Body: body}
	if err := validateOperationResultV2(result); err != nil {
		return operationResultV2{}, err
	}
	if operationOutcomeDigestV2(result) != sealed.OutcomeDigest {
		return operationResultV2{}, fmt.Errorf("opened result digest does not match its operation")
	}
	return result, nil
}

func sealedResultAADV2(result operationjournal.SealedResult) ([]byte, error) {
	aad := append([]byte(nil), []byte("ASB-A2A-SEALED-RESULT-AAD-v1\x00")...)
	fields := []struct {
		name  string
		value []byte
	}{
		{"envelope", []byte(result.Envelope)},
		{"operation_id", []byte(result.OperationID)},
		{"request_digest", []byte(result.RequestDigest)},
		{"outcome_digest", []byte(result.OutcomeDigest)},
		{"media_type", []byte(result.MediaType)},
	}
	var err error
	for _, field := range fields {
		aad, err = appendFieldV2(aad, field.name, field.value)
		if err != nil {
			return nil, err
		}
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], result.PlaintextBytes)
	return appendFieldV2(aad, "plaintext_bytes", length[:])
}

func completedOperationResultV2(request a2aSendMessageRequest, text string, completedAt time.Time) (operationResultV2, error) {
	if completedAt.IsZero() || !validConversationText(text) {
		return operationResultV2{}, fmt.Errorf("completed operation result is invalid")
	}
	response := a2aTaskResponse{Task: a2aTask{
		ID: request.Message.TaskID, ContextID: request.Message.ContextID,
		Status:    a2aTaskStatus{State: "TASK_STATE_COMPLETED", Timestamp: completedAt.UTC().Format(time.RFC3339Nano)},
		Artifacts: []a2aArtifact{{ArtifactID: "artifact-summary-v2", Name: "Demonstration result", Parts: []a2aPart{{Text: text, MediaType: "text/plain"}}}},
	}}
	payload, err := json.Marshal(response)
	if err != nil {
		return operationResultV2{}, fmt.Errorf("encode completed operation result: %w", err)
	}
	result := operationResultV2{MediaType: a2aMediaType, Body: append(payload, '\n')}
	if err := validateOperationResultV2(result); err != nil {
		return operationResultV2{}, err
	}
	return result, nil
}

func validateOperationResultV2(result operationResultV2) error {
	if result.MediaType != a2aMediaType || len(result.Body) == 0 || len(result.Body) > maxBodySize {
		return fmt.Errorf("operation result is outside the bounded A2A response contract")
	}
	decoder := json.NewDecoder(bytes.NewReader(result.Body))
	decoder.DisallowUnknownFields()
	var response a2aTaskResponse
	if err := decoder.Decode(&response); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("operation result is not one exact A2A Task response")
	}
	if _, err := completedConversationTextV2(response); err != nil {
		return err
	}
	if _, err := time.Parse(time.RFC3339Nano, response.Task.Status.Timestamp); err != nil {
		return fmt.Errorf("operation result has an invalid completion timestamp")
	}
	return nil
}

func operationOutcomeDigestV2(result operationResultV2) string {
	value := append([]byte(nil), []byte("ASB-A2A-OPERATION-OUTCOME-v2\x00")...)
	value, _ = appendFieldV2(value, "media_type", []byte(result.MediaType))
	value, _ = appendFieldV2(value, "body", result.Body)
	return sha256String(value)
}

func writeOperationResultV2(w http.ResponseWriter, result operationResultV2) {
	w.Header().Set("Content-Type", result.MediaType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(result.Body)
}
