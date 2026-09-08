// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanrelay

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// LocalGatewaySink is a Mac/CI-safe Human gateway inbox. It records only the
// opaque relay session and content reference; it has no Human/contact fields.
type LocalGatewaySink struct {
	mu       sync.RWMutex
	now      func() time.Time
	requests map[string]DispatchRequest
	acks     map[string]ProviderAck
}

func NewLocalGatewaySink(now func() time.Time) *LocalGatewaySink {
	if now == nil {
		now = time.Now
	}
	return &LocalGatewaySink{now: now, requests: make(map[string]DispatchRequest), acks: make(map[string]ProviderAck)}
}

func (s *LocalGatewaySink) Dispatch(_ context.Context, request DispatchRequest) (ProviderAck, error) {
	if err := validateID("intent_id", request.IntentID); err != nil {
		return ProviderAck{}, invalidRequest(err.Error())
	}
	if err := validateHTTPSReference("relay_session_ref", request.RelaySessionRef); err != nil {
		return ProviderAck{}, invalidRequest(err.Error())
	}
	if !validChannel(request.Channel) {
		return ProviderAck{}, invalidRequest("unsupported relay channel")
	}
	if err := validateHTTPSReference("content_ref", request.ContentRef); err != nil {
		return ProviderAck{}, invalidRequest(err.Error())
	}
	if err := validateDigest("content_digest", request.ContentDigest); err != nil {
		return ProviderAck{}, invalidRequest(err.Error())
	}
	ackRef, err := localGatewayAckRef(request.IntentID)
	if err != nil {
		return ProviderAck{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.requests[request.IntentID]; ok {
		if !sameJSON(existing, request) {
			return ProviderAck{}, ErrDispatchConflict
		}
		return s.acks[request.IntentID], nil
	}
	ack := ProviderAck{IntentID: request.IntentID, AckRef: ackRef, At: s.now().UTC()}
	s.requests[request.IntentID] = request
	s.acks[request.IntentID] = ack
	return ack, nil
}

// Load returns one detached local gateway request.
func (s *LocalGatewaySink) Load(intentID string) (DispatchRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	request, ok := s.requests[intentID]
	if !ok {
		return DispatchRequest{}, fmt.Errorf("%w: %s", ErrNotFound, intentID)
	}
	return request, nil
}
