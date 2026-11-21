// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package protectedchange

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/production"
)

// TestDurableRecoveryRecipe is also a runnable integration recipe. All keys,
// certificates, verifier nonces and trust sources are synthetic fixture data.
func TestDurableRecoveryRecipe(t *testing.T) {
	for _, softwareOnly := range []bool{false, true} {
		for _, lostHTTP := range []bool{false, true} {
			t.Run(fmt.Sprintf("software=%t/lost-http=%t", softwareOnly, lostHTTP), func(t *testing.T) {
				ctx := context.Background()
				path := privateChangePath(t)
				store, err := OpenSQLiteChangeStore(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				backend := &recoveryBackend{store: store, loseCommitAck: !lostHTTP}
				t.Cleanup(backend.close)
				fixture := newE2EFixtureWithHandler(t, softwareOnly, func(app Application) http.Handler {
					app.Store = backend
					mux := http.NewServeMux()
					mux.Handle(ChangePath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if !lostHTTP {
							app.ServeHTTP(w, r)
							return
						}
						response := httptest.NewRecorder()
						app.ServeHTTP(response, r)
						if response.Code == http.StatusNoContent {
							// The application committed, but the HTTP response never
							// reaches the caller. Only the test injects this loss.
							conn, _, hijackErr := w.(http.Hijacker).Hijack()
							if hijackErr == nil {
								_ = conn.Close()
							}
							return
						}
						for key, values := range response.Header() {
							w.Header()[key] = values
						}
						w.WriteHeader(response.Code)
						_, _ = w.Write(response.Body.Bytes())
					}))
					mux.Handle(OutcomePath, OutcomeApplication{Verifier: app, Store: backend})
					return mux
				})
				change := e2eChange(true)
				session := fixture.dial(t)
				headers := fixture.headers(t, session, change, nil)
				status, body, err := exchangeRecoveryRequest(session, ChangePath, change, headers)
				if lostHTTP {
					if err == nil {
						t.Fatal("expected lost HTTP response")
					}
					_ = session.conn.Close()
				} else if err != nil || status != http.StatusServiceUnavailable || !strings.Contains(body, "OUTCOME_UNKNOWN") {
					t.Fatalf("commit acknowledgement loss: status=%d body=%s err=%v", status, body, err)
				}
				if !lostHTTP && (!strings.Contains(fmt.Sprint(fixture.audit.last()), "injected acknowledgement loss") || strings.Contains(body, "injected")) {
					t.Fatalf("private failure audit or public redaction missing: body=%s audit=%v", body, fixture.audit.last())
				}
				t.Log("commit acknowledgement lost; the original mutation must not be retried")

				// The acknowledgement-error case reuses the SAME TLS connection,
				// proving replay consumption rather than only channel mismatch.
				retry := session
				if lostHTTP {
					retry = fixture.dial(t)
				}
				status, _, err = exchangeRecoveryRequest(retry, ChangePath, change, headers)
				_ = retry.conn.Close()
				if err != nil || status != http.StatusUnauthorized {
					t.Fatalf("old proof: status=%d err=%v", status, err)
				}
				applies, _ := backend.counts()
				if applies != 1 {
					t.Fatalf("mutation dispatched %d times", applies)
				}
				if !lostHTTP && !strings.Contains(fmt.Sprint(fixture.audit.last()), "replay") {
					t.Fatalf("same-connection proof was not rejected as replay: %v", fixture.audit.last())
				}
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
				reopened, err := OpenSQLiteChangeStore(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				backend.replace(reopened)

				lookup := fixture.dial(t)
				defer lookup.conn.Close()
				readProof := fixture.actionHeaders(t, lookup, change, true, nil)
				status, body, err = exchangeRecoveryRequest(lookup, OutcomePath, change, readProof)
				if err != nil || status != http.StatusOK || strings.TrimSpace(body) != `{"state":"APPLIED"}` {
					t.Fatalf("authenticated recovered outcome: status=%d body=%s err=%v", status, body, err)
				}
				var enabled bool
				if err := reopened.db.QueryRowContext(ctx, "SELECT enabled FROM tenant_settings WHERE tenant=? AND setting=?", change.Tenant, change.Setting).Scan(&enabled); err != nil || !enabled {
					t.Fatalf("local effect not retained: enabled=%t err=%v", enabled, err)
				}
				// Even the read operation is one-shot; it does not become a bypass.
				status, _, err = exchangeRecoveryRequest(lookup, OutcomePath, change, readProof)
				if err != nil || status != http.StatusUnauthorized {
					t.Fatalf("read replay: status=%d err=%v", status, err)
				}
				t.Log("reopened database; fresh TLS-bound change.read proof recovered APPLIED without redispatch")
			})
		}
	}
}

func TestOutcomeRequiresSeparateExactAuthorization(t *testing.T) {
	store, err := OpenSQLiteChangeStore(context.Background(), privateChangePath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	backend := &recoveryBackend{store: store}
	fixture := newE2EFixtureWithHandler(t, true, func(app Application) http.Handler {
		app.Store = backend
		mux := http.NewServeMux()
		mux.Handle(ChangePath, app)
		mux.Handle(OutcomePath, OutcomeApplication{Verifier: app, Store: backend})
		return mux
	})
	change := e2eChange(true)
	if err := store.Apply(context.Background(), change, recipeIdentity(change)); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"missing-proof", "write-proof-to-read", "read-proof-to-write", "changed-tenant", "changed-value"} {
		t.Run(mode, func(t *testing.T) {
			session := fixture.dial(t)
			defer session.conn.Close()
			path := OutcomePath
			sent := change
			headers := fixture.actionHeaders(t, session, change, true, nil)
			switch mode {
			case "missing-proof":
				headers = make(http.Header)
			case "write-proof-to-read":
				headers = fixture.headers(t, session, change, nil)
			case "read-proof-to-write":
				path = ChangePath
			case "changed-tenant":
				sent.Tenant = "other-tenant"
			case "changed-value":
				sent.Enabled = false
			}
			status, body, err := exchangeRecoveryRequest(session, path, sent, headers)
			if err != nil || status != http.StatusUnauthorized || strings.Contains(body, "APPLIED") {
				t.Fatalf("status=%d body=%s err=%v", status, body, err)
			}
		})
	}
	applies, lookups := backend.counts()
	if lookups != 0 || applies != 0 {
		t.Fatalf("unauthorized access reached application store: reads=%d writes=%d", lookups, applies)
	}
	// A properly signed request for a different tenant still cannot retrieve the
	// original receipt under a reused change identifier.
	session := fixture.dial(t)
	defer session.conn.Close()
	other := change
	other.Tenant = "other-tenant"
	headers := fixture.actionHeaders(t, session, other, true, nil)
	status, body, err := exchangeRecoveryRequest(session, OutcomePath, other, headers)
	if err != nil || status != http.StatusNotFound || strings.Contains(body, "APPLIED") {
		t.Fatalf("cross-tenant receipt: status=%d body=%s err=%v", status, body, err)
	}
}

func TestSQLiteChangeStoreAtomicIdempotenceAndReopen(t *testing.T) {
	ctx := context.Background()
	path := privateChangePath(t)
	first, err := OpenSQLiteChangeStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := OpenSQLiteChangeStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	change := e2eChange(true)
	identity := recipeIdentity(change)
	var wg sync.WaitGroup
	errorsFound := make(chan error, 16)
	for index := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store := first
			if index%2 != 0 {
				store = second
			}
			errorsFound <- store.Apply(ctx, change, identity)
		}()
	}
	wg.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := first.db.QueryRowContext(ctx, "SELECT count(*) FROM change_outcomes").Scan(&count); err != nil || count != 1 {
		t.Fatalf("receipt count=%d err=%v", count, err)
	}
	renewed := identity
	renewed.GrantExpiresAt = time.Now().Add(time.Hour)
	if err := first.Apply(ctx, change, renewed); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*ChangeRequest, *production.AcceptedIdentity){
		func(change *ChangeRequest, _ *production.AcceptedIdentity) { change.Enabled = false },
		func(_ *ChangeRequest, identity *production.AcceptedIdentity) { identity.Agent = "other-agent" },
		func(_ *ChangeRequest, identity *production.AcceptedIdentity) {
			identity.DelegationID = "other-delegation"
		},
	} {
		conflicting, actor := change, identity
		mutate(&conflicting, &actor)
		if err := first.Apply(ctx, conflicting, actor); !errors.Is(err, ErrChangeConflict) {
			t.Fatalf("conflicting reuse error=%v", err)
		}
		if _, err := first.Outcome(ctx, conflicting, actor); !errors.Is(err, ErrChangeConflict) {
			t.Fatalf("conflicting lookup error=%v", err)
		}
	}
	if _, err := first.db.ExecContext(ctx, `CREATE TRIGGER fail_setting BEFORE INSERT ON tenant_settings BEGIN SELECT RAISE(ABORT,'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
	failed := change
	failed.ChangeID = "change-rollback"
	if err := first.Apply(ctx, failed, recipeIdentity(failed)); err == nil {
		t.Fatal("expected injected write failure")
	}
	if found, err := first.Outcome(ctx, failed, recipeIdentity(failed)); err != nil || found {
		t.Fatalf("receipt survived rolled-back effect: found=%t err=%v", found, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenSQLiteChangeStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if found, err := reopened.Outcome(ctx, change, identity); err != nil || !found {
		t.Fatalf("reopened outcome: found=%t err=%v", found, err)
	}
}

func TestSQLiteChangeStoreRejectsUnsafePaths(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Dir(privateChangePath(t))
	path := filepath.Join(dir, "changes.sqlite")
	if _, err := OpenSQLiteChangeStore(ctx, "relative.sqlite"); err == nil {
		t.Fatal("accepted relative database path")
	}
	target := filepath.Join(dir, "target.sqlite")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := OpenSQLiteChangeStore(ctx, path); err == nil {
		t.Fatal("accepted symlink database")
	}
	if runtime.GOOS == goosWindows {
		return // Windows directory privacy is a caller-owned ACL requirement.
	}
	publicDir := filepath.Join(dir, "public")
	if err := os.Mkdir(publicDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(publicDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSQLiteChangeStore(ctx, filepath.Join(publicDir, "changes.sqlite")); err == nil {
		t.Fatal("accepted a non-private parent directory")
	}
}

func TestSQLiteChangeDSNPreservesLocalFilePaths(t *testing.T) {
	for _, test := range []struct {
		path   string
		volume string
		want   string
	}{
		{path: "/private/data/change #1?.sqlite", want: "/private/data/change #1?.sqlite"},
		{path: "C:/private data/change #1?.sqlite", volume: "C:", want: "/C:/private data/change #1?.sqlite"},
	} {
		parsed, err := url.Parse(sqliteChangeDSN(test.path, test.volume))
		if err != nil || parsed.Scheme != "file" || parsed.Host != "" || parsed.Path != test.want {
			t.Fatalf("file path %q became %v (err=%v)", test.path, parsed, err)
		}
		pragmas := parsed.Query()["_pragma"]
		if len(pragmas) != 2 || pragmas[0] != "busy_timeout(5000)" || pragmas[1] != "synchronous(FULL)" {
			t.Fatalf("connection durability settings missing: %v", pragmas)
		}
	}
}

func TestSQLiteChangeStoreRejectsInconsistentReceipt(t *testing.T) {
	ctx := context.Background()
	store, err := OpenSQLiteChangeStore(ctx, privateChangePath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	change := e2eChange(true)
	identity := recipeIdentity(change)
	if err := store.Apply(ctx, change, identity); err != nil {
		t.Fatal(err)
	}
	inconsistent := change
	inconsistent.ChangeID = "different-id"
	raw, err := json.Marshal(inconsistent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, "UPDATE change_outcomes SET change_json=? WHERE change_id=?", string(raw), change.ChangeID); err != nil {
		t.Fatal(err)
	}
	if found, err := store.Outcome(ctx, change, identity); found || !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("inconsistent receipt accepted: found=%t err=%v", found, err)
	}
}

func TestOutcomeNotRecordedDoesNotDispatch(t *testing.T) {
	store, err := OpenSQLiteChangeStore(context.Background(), privateChangePath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	backend := &recoveryBackend{store: store}
	fixture := newE2EFixtureWithHandler(t, true, func(app Application) http.Handler {
		return OutcomeApplication{Verifier: app, Store: backend}
	})
	change := e2eChange(true)
	session := fixture.dial(t)
	defer session.conn.Close()
	headers := fixture.actionHeaders(t, session, change, true, nil)
	status, body, err := exchangeRecoveryRequest(session, OutcomePath, change, headers)
	if err != nil || status != http.StatusOK || strings.TrimSpace(body) != `{"state":"NOT_RECORDED"}` {
		t.Fatalf("missing receipt: status=%d body=%s err=%v", status, body, err)
	}
	if applies, lookups := backend.counts(); applies != 0 || lookups != 1 {
		t.Fatalf("missing receipt dispatched: writes=%d reads=%d", applies, lookups)
	}
}

func TestNonceBackendFailuresAreAuditedAndClassified(t *testing.T) {
	for _, test := range []struct {
		name   string
		err    error
		status int
	}{
		{name: "backend-outage", err: errors.New("nonce backend unavailable"), status: http.StatusServiceUnavailable},
		{name: "missing-nonce", err: ErrMissingNonce, status: http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newE2EFixtureWithHandler(t, true, func(app Application) http.Handler {
				app.Nonces = failedNonceSource{err: test.err}
				return app
			})
			session := fixture.dial(t)
			defer session.conn.Close()
			status, _, err := exchangeRecoveryRequest(session, ChangePath, e2eChange(true), nil)
			if err != nil || status != test.status || !errors.Is(fixture.audit.last(), test.err) {
				t.Fatalf("status=%d err=%v audit=%v", status, err, fixture.audit.last())
			}
		})
	}
}

type failedNonceSource struct{ err error }

func (s failedNonceSource) ExpectedNonce(context.Context, ChangeRequest) (string, error) {
	return "", s.err
}

type recoveryBackend struct {
	mu            sync.Mutex
	store         *SQLiteChangeStore
	loseCommitAck bool
	applies       int
	lookups       int
}

func (s *recoveryBackend) Apply(ctx context.Context, change ChangeRequest, identity production.AcceptedIdentity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applies++
	if err := s.store.Apply(ctx, change, identity); err != nil {
		return err
	}
	if s.loseCommitAck {
		s.loseCommitAck = false
		return errors.New("injected acknowledgement loss after commit")
	}
	return nil
}

func (s *recoveryBackend) Outcome(ctx context.Context, change ChangeRequest, viewer production.AcceptedIdentity) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lookups++
	return s.store.Outcome(ctx, change, viewer)
}

func (s *recoveryBackend) replace(store *SQLiteChangeStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store = store
}

func (s *recoveryBackend) counts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applies, s.lookups
}

func (s *recoveryBackend) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.store.Close()
}

func recipeIdentity(change ChangeRequest) production.AcceptedIdentity {
	return production.AcceptedIdentity{
		Issuer: e2eManagerIssuer, Agent: e2eExpectedAgent, TaskID: change.ChangeID,
		IntentRef: "change:intent:apply", CapabilityRef: "change:capability:write",
		Scopes: []string{"change.write"}, Resources: []string{changeResource(change)},
		AuthorizationDetails: []string{"change:set-enabled"},
	}
}

func privateChangePath(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(directory, "changes.sqlite")
}

func exchangeRecoveryRequest(session *e2eSession, path string, change ChangeRequest, headers http.Header) (int, string, error) {
	body, err := json.Marshal(change)
	if err != nil {
		return 0, "", err
	}
	request, err := http.NewRequest(http.MethodPost, "https://example.com"+path, bytes.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	request.Header = headers.Clone()
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	request.Header.Set("Content-Type", "application/json")
	if err := request.Write(session.conn); err != nil {
		return 0, "", err
	}
	response, err := http.ReadResponse(session.reader, request)
	if err != nil {
		return 0, "", err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	return response.StatusCode, string(raw), err
}
