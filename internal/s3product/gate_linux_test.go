// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package s3product

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestGateBoundsWorkAndDrainsBeforeRelease(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	gate := &requestGate{slots: make(chan struct{}, 1), handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusNoContent)
	})}
	firstDone := make(chan struct{})
	go func() {
		gate.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/execute", http.NoBody))
		close(firstDone)
	}()
	<-entered
	busy := httptest.NewRecorder()
	gate.ServeHTTP(busy, httptest.NewRequest(http.MethodPost, "/execute", http.NoBody))
	if busy.Code != http.StatusServiceUnavailable {
		t.Fatal("concurrent work was not bounded")
	}
	drained := make(chan struct{})
	go func() { gate.stopAndWait(); close(drained) }()
	select {
	case <-drained:
		t.Fatal("active handler lost its authority lease")
	default:
	}
	close(release)
	<-firstDone
	<-drained
	closed := httptest.NewRecorder()
	gate.ServeHTTP(closed, httptest.NewRequest(http.MethodPost, "/execute", http.NoBody))
	if closed.Code != http.StatusServiceUnavailable {
		t.Fatal("work admitted after shutdown")
	}
}
