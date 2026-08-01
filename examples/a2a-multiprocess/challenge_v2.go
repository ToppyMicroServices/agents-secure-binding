// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

const (
	challengeLifetimeV2       = 30 * time.Second
	maxChallengesV2           = 1024
	challengeRandomAttemptsV2 = 16
)

type challengeStateV2 uint8

const (
	challengeIssuedV2 challengeStateV2 = iota + 1
	challengeInFlightV2
	challengeConsumedV2
)

type challengeRecordV2 struct {
	attemptID string
	channel   string
	peerSPKI  string
	expiresAt time.Time
	state     challengeStateV2
}

type challengeStoreV2 struct {
	mu      sync.Mutex
	records map[string]challengeRecordV2
	random  func(int) (string, error)
}

func newChallengeStoreV2() *challengeStoreV2 {
	return &challengeStoreV2{records: make(map[string]challengeRecordV2), random: randomBase64URLV2}
}

func (s *challengeStoreV2) issue(state *tls.ConnectionState, now time.Time) (challengeResponseV2, error) {
	if s == nil {
		return challengeResponseV2{}, fmt.Errorf("challenge state is unavailable")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	channel, err := channelTagV2At(state, now)
	if err != nil {
		return challengeResponseV2{}, err
	}
	peerSPKI, err := currentPeerSPKIHashV2At(state, now)
	if err != nil {
		return challengeResponseV2{}, err
	}
	return s.issueForBindingV2(channel, peerSPKI, now)
}

func (s *challengeStoreV2) issueForBindingV2(channel, peerSPKI string, now time.Time) (challengeResponseV2, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	if len(s.records) >= maxChallengesV2 {
		return challengeResponseV2{}, fmt.Errorf("challenge capacity is exhausted")
	}
	random := s.random
	if random == nil {
		random = randomBase64URLV2
	}
	for generationAttempt := 0; generationAttempt < challengeRandomAttemptsV2; generationAttempt++ {
		nonce, err := random(32)
		if err != nil {
			return challengeResponseV2{}, err
		}
		attempt, err := random(16)
		if err != nil {
			return challengeResponseV2{}, err
		}
		if _, exists := s.records[nonce]; exists || s.attemptIDExistsLocked(attempt) {
			continue
		}
		expiresAt := now.Add(challengeLifetimeV2)
		s.records[nonce] = challengeRecordV2{
			attemptID: attempt, channel: channel, peerSPKI: peerSPKI,
			expiresAt: expiresAt, state: challengeIssuedV2,
		}
		return challengeResponseV2{VerifierNonce: nonce, AttemptID: attempt, ExpiresAt: expiresAt.Unix()}, nil
	}
	return challengeResponseV2{}, fmt.Errorf("challenge randomness collided with live state")
}

func (s *challengeStoreV2) attemptIDExistsLocked(attemptID string) bool {
	for _, record := range s.records {
		if record.attemptID == attemptID {
			return true
		}
	}
	return false
}

func (s *challengeStoreV2) begin(nonce, attemptID, channel, peerSPKI string, now time.Time) (challengeRecordV2, error) {
	if s == nil {
		return challengeRecordV2{}, fmt.Errorf("challenge state is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[nonce]
	if !ok || record.state != challengeIssuedV2 || !now.Before(record.expiresAt) {
		return challengeRecordV2{}, fmt.Errorf("challenge is unknown, expired, in flight, or consumed")
	}
	if record.attemptID != attemptID || record.channel != channel || record.peerSPKI != peerSPKI {
		return challengeRecordV2{}, fmt.Errorf("challenge does not belong to this TLS endpoint attempt")
	}
	record.state = challengeInFlightV2
	s.records[nonce] = record
	return record, nil
}

func (s *challengeStoreV2) release(nonce string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[nonce]
	if ok && record.state == challengeInFlightV2 {
		record.state = challengeIssuedV2
		s.records[nonce] = record
	}
}

func (s *challengeStoreV2) consume(nonce string) error {
	if s == nil {
		return fmt.Errorf("challenge state is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[nonce]
	if !ok || record.state != challengeInFlightV2 {
		return fmt.Errorf("challenge is not in flight")
	}
	record.state = challengeConsumedV2
	s.records[nonce] = record
	return nil
}

func (s *challengeStoreV2) pruneLocked(now time.Time) {
	for nonce, record := range s.records {
		if !now.Before(record.expiresAt) {
			delete(s.records, nonce)
		}
	}
}

func currentPeerSPKIHashV2(state *tls.ConnectionState) (string, error) {
	return currentPeerSPKIHashV2At(state, time.Now().UTC())
}

func currentPeerSPKIHashV2At(state *tls.ConnectionState, now time.Time) (string, error) {
	if err := validateTLSSessionAtV2(state, now); err != nil {
		return "", err
	}
	return hashBytesV2(state.PeerCertificates[0].RawSubjectPublicKeyInfo), nil
}

func randomBase64URLV2(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate challenge randomness: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func decodeChallengeRequestV2(raw []byte) (challengeRequestV2, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeStrictJSONValueV2(decoder); err != nil {
		return challengeRequestV2{}, err
	}
	if token, err := decoder.Token(); err != io.EOF || token != nil {
		return challengeRequestV2{}, fmt.Errorf("challenge request contains trailing JSON")
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || len(members) != 0 {
		return challengeRequestV2{}, fmt.Errorf("challenge request must be the empty object")
	}
	var request challengeRequestV2
	typed := json.NewDecoder(bytes.NewReader(raw))
	typed.DisallowUnknownFields()
	if err := typed.Decode(&request); err != nil || typed.Decode(&struct{}{}) != io.EOF {
		return challengeRequestV2{}, fmt.Errorf("challenge request is malformed")
	}
	return request, nil
}
