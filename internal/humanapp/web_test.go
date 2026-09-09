// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	protectedchange "github.com/ToppyMicroServices/agents-secure-binding/v2/examples/protected-change-consumer"
	"github.com/google/uuid"
)

const testWebOrigin = "http://127.0.0.1:43117"
const testWebLoginToken = "test-only-private-token-000000000000000000000000"

func TestWebSessionsCoexistOnDifferentLocalPorts(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	origins := []string{testWebOrigin, "http://127.0.0.1:43118"}
	handlers := make([]http.Handler, len(origins))
	for i, origin := range origins {
		handlers[i], err = NewWebHandler(WebConfig{Origin: origin, LoginToken: testWebLoginToken, Execute: func(context.Context, Command) ([]byte, error) { return []byte(`{}`), nil }})
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(origin)
		req := httptest.NewRequest("POST", origin+"/api/session", strings.NewReader(`{"token":"`+testWebLoginToken+`"}`))
		req.RemoteAddr = "127.0.0.1:52111"
		req.Header.Set("Origin", origin)
		req.Header.Set("Content-Type", "application/json")
		for _, cookie := range jar.Cookies(u) {
			req.AddCookie(cookie)
		}
		res := httptest.NewRecorder()
		handlers[i].ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("instance %d login: %d", i, res.Code)
		}
		jar.SetCookies(u, res.Result().Cookies())
	}
	for i, origin := range origins {
		u, _ := url.Parse(origin)
		req := httptest.NewRequest("GET", origin+"/api/session", nil)
		req.RemoteAddr = "127.0.0.1:52111"
		for _, cookie := range jar.Cookies(u) {
			req.AddCookie(cookie)
		}
		res := httptest.NewRecorder()
		handlers[i].ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("instance %d lost its session after the other instance logged in", i)
		}
	}
}

type testWebSession struct {
	cookie *http.Cookie
	csrf   string
}

func newTestWebHandler(t *testing.T, execute func(context.Context, Command) ([]byte, error)) *webHandler {
	t.Helper()
	handler, err := NewWebHandler(WebConfig{Origin: testWebOrigin, LoginToken: testWebLoginToken, Execute: execute})
	if err != nil {
		t.Fatal(err)
	}
	return handler.(*webHandler)
}

func webTestRequest(t *testing.T, handler http.Handler, method, path string, input any, session testWebSession) *httptest.ResponseRecorder {
	t.Helper()
	var body []byte
	if input != nil {
		var err error
		body, err = json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, testWebOrigin+path, bytes.NewReader(body))
	request.RemoteAddr = "127.0.0.1:52111"
	if method == http.MethodPost {
		request.Header.Set("Origin", testWebOrigin)
		request.Header.Set("Content-Type", "application/json")
	}
	if session.cookie != nil {
		request.AddCookie(session.cookie)
	}
	if session.csrf != "" {
		request.Header.Set("X-CSRF-Token", session.csrf)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func loginWebTest(t *testing.T, handler http.Handler) testWebSession {
	t.Helper()
	response := webTestRequest(t, handler, http.MethodPost, "/api/session", map[string]string{"token": testWebLoginToken}, testWebSession{})
	if response.Code != http.StatusOK {
		t.Fatalf("login: %d %s", response.Code, response.Body.String())
	}
	var session struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || session.CSRF == "" {
		t.Fatal("missing session cookie or CSRF token")
	}
	return testWebSession{cookie: cookies[0], csrf: session.CSRF}
}

func TestWebSessionInboxDecisionAndLogout(t *testing.T) {
	var commands []Command
	op := Operation{OperationID: "change-1", ProposalDigest: "sha256:" + strings.Repeat("a", 64),
		Change: protectedchange.ChangeRequest{ChangeID: "change-1", Tenant: Tenant, Setting: SettingName, Enabled: true},
		Before: Setting{Tenant: Tenant, Name: SettingName, Revision: 4}, State: StatePending, Proposer: ActorAgent}
	handler := newTestWebHandler(t, func(_ context.Context, command Command) ([]byte, error) {
		if err := command.Validate(); err != nil {
			t.Fatal(err)
		}
		commands = append(commands, command)
		if command.Kind == KindInbox {
			return json.Marshal(Response{CommandID: command.CommandID, Operations: []Operation{op}, Setting: &op.Before})
		}
		if command.Kind == KindApprove {
			op.State = StateApplied
		} else {
			op.State = StateDenied
		}
		return json.Marshal(Response{CommandID: command.CommandID, Operation: &op})
	})
	unauthenticated := webTestRequest(t, handler, "GET", "/api/inbox", nil, testWebSession{})
	if unauthenticated.Code != 401 || len(commands) != 0 {
		t.Fatal("inbox did not require a login")
	}
	page := webTestRequest(t, handler, "GET", "/", nil, testWebSession{})
	if page.Code != 200 || !strings.Contains(page.Body.String(), `id="dashboard" hidden`) || strings.Contains(page.Body.String(), op.OperationID) {
		t.Fatal("unauthenticated page must contain only the empty login application")
	}
	session := loginWebTest(t, handler)
	if !session.cookie.HttpOnly || session.cookie.SameSite != http.SameSiteStrictMode || session.cookie.Path != "/" || session.cookie.Secure || session.cookie.MaxAge > 8*60*60 {
		t.Fatal("unexpected browser session cookie")
	}
	if session.csrf == session.cookie.Value || session.cookie.Value == testWebLoginToken {
		t.Fatal("session, login, and CSRF secrets must differ")
	}
	restored := webTestRequest(t, handler, "GET", "/api/session", nil, session)
	var restoredSession struct {
		CSRF      string `json:"csrf_token"`
		Assurance string `json:"assurance"`
		Gateway   string `json:"gateway_actor"`
		Human     string `json:"human_participant"`
	}
	if err := json.Unmarshal(restored.Body.Bytes(), &restoredSession); err != nil {
		t.Fatal(err)
	}
	if restored.Code != 200 || restoredSession.CSRF != session.csrf || restoredSession.Assurance != Assurance || restoredSession.Gateway != ActorGateway || restoredSession.Human != HumanParticipant {
		t.Fatal("reload did not recover the same session and assurance")
	}
	inbox := webTestRequest(t, handler, "GET", "/api/inbox", nil, session)
	if inbox.Code != 200 || len(commands) != 1 || commands[0].Kind != KindInbox {
		t.Fatal("inbox was not sent through the gateway executor")
	}
	for _, approve := range []bool{true, false} {
		decision := webTestRequest(t, handler, "POST", "/api/decision", map[string]any{"operation_id": op.OperationID, "proposal_digest": op.ProposalDigest, "expected_revision": 4, "approve": approve}, session)
		if decision.Code != 200 {
			t.Fatalf("decision: %d %s", decision.Code, decision.Body.String())
		}
		command := commands[len(commands)-1]
		wantKind := KindDecline
		if approve {
			wantKind = KindApprove
		}
		if command.Kind != wantKind || command.OperationID != op.OperationID || command.ProposalDigest != op.ProposalDigest || command.ExpectedRevision != 4 || command.Change != nil {
			t.Fatalf("decision changed the selected request: %+v", command)
		}
		if _, err := uuid.Parse(command.CommandID); err != nil {
			t.Fatal("decision command must have a generated UUID")
		}
	}
	if commands[1].CommandID == commands[2].CommandID {
		t.Fatal("distinct decisions reused a command ID")
	}
	logout := webTestRequest(t, handler, "POST", "/api/logout", map[string]any{}, session)
	if logout.Code != 204 {
		t.Fatalf("logout: %d", logout.Code)
	}
	if restored := webTestRequest(t, handler, "GET", "/api/session", nil, session); restored.Code != 401 {
		t.Fatal("logout retained a live browser session")
	}
}

func TestWebSessionExpiresAndHTTPSCookieIsSecure(t *testing.T) {
	handler := newTestWebHandler(t, func(context.Context, Command) ([]byte, error) { return []byte(`{}`), nil })
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	handler.now = func() time.Time { return now }
	session := loginWebTest(t, handler)
	now = now.Add(webSessionLifetime)
	if response := webTestRequest(t, handler, "GET", "/api/session", nil, session); response.Code != 401 {
		t.Fatal("expired session was accepted")
	}
	secureHandler, err := NewWebHandler(WebConfig{Origin: "https://127.0.0.1:43117", LoginToken: testWebLoginToken, Execute: handler.execute})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", "https://127.0.0.1:43117/api/session", strings.NewReader(`{"token":"`+testWebLoginToken+`"}`))
	request.RemoteAddr = "127.0.0.1:52111"
	request.Header.Set("Origin", "https://127.0.0.1:43117")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	secureHandler.ServeHTTP(response, request)
	if response.Code != 200 || len(response.Result().Cookies()) != 1 || !response.Result().Cookies()[0].Secure {
		t.Fatal("HTTPS session cookie must be secure")
	}
}

func TestWebRequiresSessionOriginCSRFAndExactDecisionFields(t *testing.T) {
	calls := 0
	handler := newTestWebHandler(t, func(context.Context, Command) ([]byte, error) { calls++; return []byte(`{}`), nil })
	session := loginWebTest(t, handler)
	valid := `{"operation_id":"change-1","proposal_digest":"sha256:` + strings.Repeat("b", 64) + `","expected_revision":2,"approve":false}`
	tests := []struct {
		name   string
		edit   func(*http.Request)
		body   string
		status int
	}{
		{"missing session", func(r *http.Request) { r.Header.Del("Cookie") }, valid, 401},
		{"missing csrf", func(r *http.Request) { r.Header.Del("X-CSRF-Token") }, valid, 403},
		{"different csrf", func(r *http.Request) { r.Header.Set("X-CSRF-Token", "other-session") }, valid, 403},
		{"different origin", func(r *http.Request) { r.Header.Set("Origin", "http://localhost:43117") }, valid, 403},
		{"missing origin", func(r *http.Request) { r.Header.Del("Origin") }, valid, 403},
		{"different host", func(r *http.Request) { r.Host = "localhost:43117" }, valid, 403},
		{"non-loopback peer", func(r *http.Request) { r.RemoteAddr = "192.0.2.1:52111" }, valid, 403},
		{"non-json input", func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, valid, 403},
		{"missing decision", nil, `{"operation_id":"change-1","proposal_digest":"sha256:` + strings.Repeat("b", 64) + `","expected_revision":2}`, 400},
		{"missing revision", nil, `{"operation_id":"change-1","proposal_digest":"sha256:` + strings.Repeat("b", 64) + `","approve":false}`, 400},
		{"missing digest", nil, `{"operation_id":"change-1","expected_revision":2,"approve":false}`, 400},
		{"unrecognized field", nil, strings.TrimSuffix(valid, "}") + `,"actor":"gateway:other"}`, 400},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest("POST", testWebOrigin+"/api/decision", strings.NewReader(test.body))
			request.RemoteAddr = "127.0.0.1:52111"
			request.Header.Set("Origin", testWebOrigin)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-CSRF-Token", session.csrf)
			request.AddCookie(session.cookie)
			if test.edit != nil {
				test.edit(request)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("got %d, want %d", response.Code, test.status)
			}
		})
	}
	if calls != 0 {
		t.Fatal("invalid browser input reached the executor")
	}
}

func TestWebUnknownOutcomeIsNotRetriedAndDetailsAreRedacted(t *testing.T) {
	calls := 0
	handler := newTestWebHandler(t, func(context.Context, Command) ([]byte, error) {
		calls++
		return nil, errors.New("private transport details")
	})
	session := loginWebTest(t, handler)
	response := webTestRequest(t, handler, "POST", "/api/decision", map[string]any{"operation_id": "change-1", "proposal_digest": "sha256:" + strings.Repeat("c", 64), "expected_revision": 0, "approve": true}, session)
	var body struct {
		Code    string `json:"code"`
		Unknown bool   `json:"outcome_unknown"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if response.Code != 503 || body.Code != "OUTCOME_UNKNOWN" || !body.Unknown || calls != 1 || strings.Contains(response.Body.String(), "private transport details") {
		t.Fatal("unknown execution must remain visible without retries or private errors")
	}
}

func TestWebConfigAndLoginRequireLocalPrivateConfiguration(t *testing.T) {
	execute := func(context.Context, Command) ([]byte, error) { return []byte(`{}`), nil }
	for _, origin := range []string{"https://example.invalid", "http://127.0.0.1:43117/path", "http://127.0.0.1:43117?token=x"} {
		if _, err := NewWebHandler(WebConfig{Origin: origin, LoginToken: testWebLoginToken, Execute: execute}); err == nil {
			t.Fatalf("accepted origin %s", origin)
		}
	}
	if _, err := NewWebHandler(WebConfig{Origin: testWebOrigin, LoginToken: "short", Execute: execute}); err == nil {
		t.Fatal("accepted short login token")
	}
	handler := newTestWebHandler(t, execute)
	response := webTestRequest(t, handler, "POST", "/api/session", map[string]string{"token": "incorrect-local-token"}, testWebSession{})
	if response.Code != 401 || len(response.Result().Cookies()) != 0 {
		t.Fatal("incorrect token created a session")
	}
	for _, asset := range []string{"/", "/app.css", "/app.js"} {
		response := webTestRequest(t, handler, "GET", asset, nil, testWebSession{})
		if response.Code != 200 || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Content-Security-Policy") == "" {
			t.Fatalf("asset %s lacks local document policy", asset)
		}
	}
}
