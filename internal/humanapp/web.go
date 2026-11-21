// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanapp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

//go:embed web/index.html web/app.css web/app.js
var webAssets embed.FS

const (
	webSessionLifetime = 8 * time.Hour
	maxWebSessions     = 16
	webLoginLifetime   = 5 * time.Minute
)

// WebConfig configures a local browser gateway. Execute must perform the
// authenticated ASB exchange as ActorGateway; the UI never accesses a Store.
// LoginDirectory is the private application data directory.
type WebConfig struct {
	Origin         string
	LoginDirectory string
	Execute        func(context.Context, Command) ([]byte, error)
}

type webSession struct {
	csrf    string
	expires time.Time
}

// WebHandler serves the browser during one local application run.
type WebHandler struct {
	origin         string
	host           string
	cookieName     string
	secure         bool
	loginHash      [sha256.Size]byte
	loginDirectory string
	loginExpires   time.Time
	loginTimer     *time.Timer
	closed         bool
	execute        func(context.Context, Command) ([]byte, error)
	mu             sync.Mutex
	sessions       map[string]webSession
	now            func() time.Time
}

// NewWebHandler serves an experimental single-host Human review inbox. It
// accepts only the configured loopback origin and loopback network peers.
func NewWebHandler(config WebConfig) (*WebHandler, error) {
	origin, err := url.Parse(config.Origin)
	if err != nil || origin == nil || (origin.Scheme != "http" && origin.Scheme != "https") ||
		origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" ||
		origin.Fragment != "" || origin.Opaque != "" || origin.String() != config.Origin {
		return nil, fmt.Errorf("%w: exact browser origin is required", ErrInvalid)
	}
	hostname := origin.Hostname()
	ip := net.ParseIP(hostname)
	if hostname != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, fmt.Errorf("%w: browser origin must be loopback", ErrInvalid)
	}
	if config.LoginDirectory == "" || config.Execute == nil {
		return nil, fmt.Errorf("%w: private data directory and gateway executor are required", ErrInvalid)
	}
	if err := validatePrivateDirectory(config.LoginDirectory); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(config.LoginDirectory, "browser-login-")
	if err != nil {
		return nil, err
	}
	// Cookies are host-scoped, not port-scoped. Distinct names prevent two
	// trusted local instances from accidentally replacing each other's session.
	// This does not isolate mutually untrusted services on the same host.
	originHash := sha256.Sum256([]byte(config.Origin))
	h := &WebHandler{
		origin: config.Origin, host: origin.Host, secure: origin.Scheme == "https",
		cookieName:     fmt.Sprintf("asb_human_session_%x", originHash),
		loginDirectory: dir, execute: config.Execute,
		sessions: make(map[string]webSession), now: time.Now,
	}
	if err := h.rotateLoginLink(); err != nil {
		_ = h.Close()
		return nil, err
	}
	h.mu.Lock()
	h.loginTimer = time.AfterFunc(webLoginLifetime, h.refreshExpiredLink)
	h.mu.Unlock()
	return h, nil
}

// LoginFile contains the current single-use login URL. Only its path may be logged.
func (h *WebHandler) LoginFile() string { return filepath.Join(h.loginDirectory, "login.txt") }

// rotateLoginLink runs during construction or under mu. Publish the new file
// before accepting its token so that a failed write cannot strand a session.
func (h *WebHandler) rotateLoginLink() error {
	token, err := randomWebToken()
	if err != nil {
		return err
	}
	if err := writeAtomicPrivate(h.loginDirectory, "login.txt", []byte(h.origin+"/#login="+token+"\n")); err != nil {
		return err
	}
	h.loginHash = sha256.Sum256([]byte(token))
	h.loginExpires = h.now().Add(webLoginLifetime)
	return nil
}

func (h *WebHandler) refreshExpiredLink() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	if delay := h.loginExpires.Sub(h.now()); delay > 0 {
		h.loginTimer.Reset(delay)
		return
	}
	if err := h.rotateLoginLink(); err != nil {
		// The old link remains expired. Retry publication after a transient I/O error.
		h.loginTimer.Reset(5 * time.Second)
		return
	}
	h.loginTimer.Reset(webLoginLifetime)
}

// Close retires this instance's login link and removes its private file.
func (h *WebHandler) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	h.closed = true
	if h.loginTimer != nil {
		h.loginTimer.Stop()
	}
	clear(h.sessions)
	if err := os.Remove(h.LoginFile()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Remove(h.loginDirectory)
}

func (h *WebHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || !net.ParseIP(peer).IsLoopback() || r.Host != h.host || (r.TLS != nil) != h.secure ||
		(r.Header.Get("Origin") != "" && r.Header.Get("Origin") != h.origin) || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		webError(w, http.StatusForbidden, "LOCAL_ORIGIN_REQUIRED", "起動時に表示されたローカルURLを使用してください。", false)
		return
	}
	if r.Method == http.MethodPost && (r.Header.Get("Origin") != h.origin || !webJSONRequest(r)) {
		webError(w, http.StatusForbidden, "REQUEST_REJECTED", "この操作は受け付けられません。画面を再読み込みしてください。", false)
		return
	}
	switch r.URL.Path {
	case "/", "/app.css", "/app.js":
		if r.Method != http.MethodGet {
			h.methodNotAllowed(w, "GET")
			return
		}
		name, contentType := "index.html", "text/html; charset=utf-8"
		if r.URL.Path == "/app.css" {
			name, contentType = "app.css", "text/css; charset=utf-8"
		}
		if r.URL.Path == "/app.js" {
			name, contentType = "app.js", "text/javascript; charset=utf-8"
		}
		raw, err := webAssets.ReadFile("web/" + name)
		if err != nil {
			webError(w, 500, "INTERNAL_ERROR", "画面を読み込めませんでした。", false)
			return
		}
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(raw)
	case "/api/session":
		switch r.Method {
		case http.MethodPost:
			h.login(w, r)
		case http.MethodGet:
			_, session, ok := h.session(r)
			if !ok {
				h.unauthorized(w)
				return
			}
			h.writeSession(w, session)
		default:
			h.methodNotAllowed(w, "GET, POST")
		}
	case "/api/logout":
		if r.Method != http.MethodPost {
			h.methodNotAllowed(w, "POST")
			return
		}
		id, _, ok := h.authorizeMutation(w, r)
		if !ok {
			return
		}
		h.mu.Lock()
		delete(h.sessions, id)
		h.mu.Unlock()
		h.setCookie(w, "", time.Unix(1, 0), -1)
		w.WriteHeader(http.StatusNoContent)
	case "/api/inbox":
		if r.Method != http.MethodGet {
			h.methodNotAllowed(w, "GET")
			return
		}
		if _, _, ok := h.session(r); !ok {
			h.unauthorized(w)
			return
		}
		id, err := uuid.NewRandom()
		if err != nil {
			webError(w, 500, "INTERNAL_ERROR", "要求を作成できませんでした。", false)
			return
		}
		h.executeCommand(w, r, Command{CommandID: id.String(), Kind: KindInbox})
	case "/api/decision":
		if r.Method != http.MethodPost {
			h.methodNotAllowed(w, "POST")
			return
		}
		if _, _, ok := h.authorizeMutation(w, r); !ok {
			return
		}
		h.decision(w, r)
	default:
		webError(w, http.StatusNotFound, "NOT_FOUND", "ページが見つかりません。", false)
	}
}

func webJSONRequest(r *http.Request) bool {
	media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && media == "application/json" && (params["charset"] == "" || strings.EqualFold(params["charset"], "utf-8")) && r.Header.Get("Content-Encoding") == ""
}

func (h *WebHandler) login(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Token string `json:"token"`
	}
	if decodeJSON(http.MaxBytesReader(w, r.Body, MaxRequestBytes), &input) != nil || len(input.Token) > 256 {
		webError(w, 400, "INVALID_REQUEST", "ログイントークンを入力してください。", false)
		return
	}
	var previous string
	if cookie, err := r.Cookie(h.cookieName); err == nil {
		previous = cookie.Value
	}
	id, session, err := h.createSession(input.Token, previous)
	switch {
	case errors.Is(err, ErrUnauthorized):
		h.unauthorized(w)
	case errors.Is(err, errWebSessionLimit):
		webError(w, http.StatusTooManyRequests, "SESSION_LIMIT", "ログイン中のブラウザーが上限に達しました。別の画面でログアウトしてください。", false)
	case err != nil:
		webError(w, http.StatusServiceUnavailable, "LOGIN_UNAVAILABLE", "ログインリンクを更新できませんでした。", false)
	default:
		h.setCookie(w, id, session.expires, int(webSessionLifetime.Seconds()))
		h.writeSession(w, session)
	}
}

var errWebSessionLimit = errors.New("browser session limit reached")

func (h *WebHandler) createSession(token, previous string) (string, webSession, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	hash := sha256.Sum256([]byte(token))
	if h.closed || !now.Before(h.loginExpires) || subtle.ConstantTimeCompare(hash[:], h.loginHash[:]) != 1 {
		return "", webSession{}, ErrUnauthorized
	}
	for key, existing := range h.sessions {
		if !now.Before(existing.expires) {
			delete(h.sessions, key)
		}
	}
	if _, replacing := h.sessions[previous]; !replacing && len(h.sessions) >= maxWebSessions {
		return "", webSession{}, errWebSessionLimit
	}
	id, err := randomWebToken()
	if err != nil {
		return "", webSession{}, err
	}
	csrf, err := randomWebToken()
	if err != nil {
		return "", webSession{}, err
	}
	if err := h.rotateLoginLink(); err != nil {
		return "", webSession{}, err
	}
	session := webSession{csrf: csrf, expires: now.Add(webSessionLifetime)}
	delete(h.sessions, previous)
	h.sessions[id] = session
	return id, session, nil
}

func (h *WebHandler) session(r *http.Request) (string, webSession, bool) {
	cookie, err := r.Cookie(h.cookieName)
	if err != nil {
		return "", webSession{}, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	session, ok := h.sessions[cookie.Value]
	if !ok {
		return "", webSession{}, false
	}
	if !h.now().Before(session.expires) {
		delete(h.sessions, cookie.Value)
		return "", webSession{}, false
	}
	return cookie.Value, session, true
}

func (h *WebHandler) authorizeMutation(w http.ResponseWriter, r *http.Request) (string, webSession, bool) {
	id, session, ok := h.session(r)
	if !ok {
		h.unauthorized(w)
		return "", webSession{}, false
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(session.csrf)) != 1 {
		webError(w, http.StatusForbidden, "SESSION_REFRESH_REQUIRED", "画面を再読み込みしてから操作してください。", false)
		return "", webSession{}, false
	}
	return id, session, true
}

func (h *WebHandler) decision(w http.ResponseWriter, r *http.Request) {
	var input struct {
		OperationID      string          `json:"operation_id"`
		ProposalDigest   string          `json:"proposal_digest"`
		ExpectedRevision *uint64         `json:"expected_revision"`
		Decision         json.RawMessage `json:"decision"`
		Approve          json.RawMessage `json:"approve"`
	}
	if decodeJSON(http.MaxBytesReader(w, r.Body, MaxRequestBytes), &input) != nil || input.ExpectedRevision == nil {
		webError(w, 400, "INVALID_REQUEST", "対象の変更を再読み込みしてください。", false)
		return
	}
	kind, ok := webDecisionKind(input.Decision, input.Approve)
	if !ok {
		webError(w, 400, "INVALID_REQUEST", "対象の変更を再読み込みしてください。", false)
		return
	}
	id, err := uuid.NewRandom()
	if err != nil {
		webError(w, 500, "INTERNAL_ERROR", "要求を作成できませんでした。", false)
		return
	}
	command := Command{CommandID: id.String(), Kind: kind, OperationID: input.OperationID, ProposalDigest: input.ProposalDigest, ExpectedRevision: *input.ExpectedRevision}
	if command.Validate() != nil {
		webError(w, 400, "INVALID_REQUEST", "対象の変更を再読み込みしてください。", false)
		return
	}
	h.executeCommand(w, r, command)
}

func webDecisionKind(decision, approve json.RawMessage) (string, bool) {
	// Presence matters: even a null legacy field must not accompany decision.
	if (len(decision) == 0) == (len(approve) == 0) {
		return "", false
	}
	if len(decision) != 0 {
		var kind string
		if json.Unmarshal(decision, &kind) != nil || !isDecisionKind(kind) {
			return "", false
		}
		return kind, true
	}
	// Preserve the original boolean-only API without treating null as decline.
	var legacy *bool
	if json.Unmarshal(approve, &legacy) != nil || legacy == nil {
		return "", false
	}
	if *legacy {
		return KindApprove, true
	}
	return KindDecline, true
}

func (h *WebHandler) executeCommand(w http.ResponseWriter, r *http.Request, command Command) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	raw, err := h.execute(ctx, command)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalid):
			webError(w, 400, "INVALID_REQUEST", "要求を受け付けられませんでした。", false)
		case errors.Is(err, ErrConflict):
			webError(w, 409, "STATE_CHANGED", "変更の状態が更新されています。最新の状態を確認してください。", false)
		case errors.Is(err, ErrNotFound):
			webError(w, 404, "NOT_FOUND", "変更が見つかりません。最新の一覧を確認してください。", false)
		case errors.Is(err, ErrUnauthorized):
			webError(w, 403, "GATEWAY_NOT_AUTHORIZED", "Gatewayの認証に失敗しました。起動設定を確認してください。", false)
		default:
			webError(w, 503, "OUTCOME_UNKNOWN", "結果を確認できません。操作を繰り返さず、一覧を更新して状態を確認してください。", command.Mutation())
		}
		return
	}
	if !json.Valid(raw) {
		webError(w, 502, "OUTCOME_UNKNOWN", "結果を読み取れません。操作を繰り返さず、一覧を更新してください。", command.Mutation())
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(raw)
}

func (h *WebHandler) setCookie(w http.ResponseWriter, value string, expires time.Time, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: h.cookieName, Value: value, Path: "/", HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: maxAge})
}

func (h *WebHandler) writeSession(w http.ResponseWriter, session webSession) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	writeJSONResponse(w, http.StatusOK, map[string]any{"authenticated": true, "csrf_token": session.csrf, "expires_at": session.expires.UTC(), "gateway_actor": ActorGateway, "human_participant": HumanParticipant, "assurance": Assurance, "mode": "local-preview"})
}

func (h *WebHandler) unauthorized(w http.ResponseWriter) {
	webError(w, http.StatusUnauthorized, "LOGIN_REQUIRED", "起動時に表示された非公開ファイルから、最新のログインURLを開いてください。", false)
}

func (h *WebHandler) methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	webError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "この操作は受け付けられません。", false)
}

func webError(w http.ResponseWriter, status int, code, message string, unknown bool) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	writeJSONResponse(w, status, map[string]any{"code": code, "message": message, "outcome_unknown": unknown})
}

func randomWebToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}
