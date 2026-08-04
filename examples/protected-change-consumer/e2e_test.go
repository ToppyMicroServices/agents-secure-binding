// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package protectedchange

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/thinksyncs/agents-secure-binding/pkg/atls/identitypolicy"
	"github.com/thinksyncs/agents-secure-binding/pkg/clients"
	"github.com/thinksyncs/agents-secure-binding/pkg/production"
)

const (
	e2eAudience      = "https://protected-change.example.test/v1/changes"
	e2eManagerIssuer = "https://manager.example.test"
	e2eAgentIssuer   = "https://agent.example.test"
	e2eManagerKeyID  = "manager-ed25519-2026-01"
	e2eAgentKeyID    = "agent-ed25519-2026-01"
	e2eAttesterKeyID = "attester-ed25519-2026-01"
	e2ePolicyID      = "protected-change-attestation/v1"
	e2eMeasurement   = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	e2eExpectedAgent = "change-agent-01"
	e2eExpectedNonce = "verifier-nonce-change-0001"
)

type e2eFixture struct {
	server          *httptest.Server
	clientTLS       *tls.Config
	clientLeaf      *x509.Certificate
	managerPrivate  ed25519.PrivateKey
	agentPrivate    ed25519.PrivateKey
	attesterPrivate ed25519.PrivateKey
	managerTrust    *mutableTrustSource
	replayStore     *sharedSetNXStore
	store           *MemoryChangeStore
	audit           *e2eAudit
	now             time.Time
	softwareOnly    bool
}

type e2eSession struct {
	conn   *tls.Conn
	reader *bufio.Reader
}

type e2eAudit struct {
	mu  sync.Mutex
	err error
}

func (a *e2eAudit) record(_ context.Context, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.err = err
}

func (a *e2eAudit) last() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.err
}

type mutableTrustSource struct {
	mu       sync.Mutex
	snapshot production.TrustSnapshot
	err      error
}

func (s *mutableTrustSource) Snapshot(context.Context) (production.TrustSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return production.TrustSnapshot{}, s.err
	}
	return s.snapshot, nil
}

func (s *mutableTrustSource) revoke(tokenID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshot.RevokedTokenIDs = append(s.snapshot.RevokedTokenIDs, tokenID)
}

type sharedSetNXStore struct {
	mu   sync.Mutex
	seen map[string]struct{}
	err  error
}

func (s *sharedSetNXStore) SetNX(_ context.Context, key string, _ time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return false, s.err
	}
	if _, ok := s.seen[key]; ok {
		return false, nil
	}
	s.seen[key] = struct{}{}
	return true, nil
}

type fixedNonceSource map[string]string

func (s fixedNonceSource) ExpectedNonce(_ context.Context, change ChangeRequest) (string, error) {
	nonce, ok := s[change.ChangeID]
	if !ok {
		return "", ErrMissingNonce
	}
	return nonce, nil
}

func TestProtectedChangeE2EAcceptsExactBoundAction(t *testing.T) {
	t.Parallel()
	fixture := newE2EFixture(t)
	session := fixture.dial(t)
	defer session.conn.Close()
	change := e2eChange(true)
	headers := fixture.headers(t, session, change, nil)

	if status := sendChange(t, session, change, headers); status != http.StatusNoContent {
		t.Fatalf("status = %d, want %d, audit = %v", status, http.StatusNoContent, fixture.audit.last())
	}
	stored, ok := fixture.store.Lookup(change.ChangeID)
	if !ok || stored != change {
		t.Fatalf("stored change = %+v, %v", stored, ok)
	}
}

func TestSoftwareOnlyProtectedChangeE2EAcceptsExactBoundAction(t *testing.T) {
	t.Parallel()
	fixture := newSoftwareOnlyE2EFixture(t)
	session := fixture.dial(t)
	defer session.conn.Close()
	change := e2eChange(true)
	headers := fixture.headers(t, session, change, nil)

	if status := sendChange(t, session, change, headers); status != http.StatusNoContent {
		t.Fatalf("status = %d, want %d, audit = %v", status, http.StatusNoContent, fixture.audit.last())
	}
	stored, ok := fixture.store.Lookup(change.ChangeID)
	if !ok || stored != change {
		t.Fatalf("stored change = %+v, %v", stored, ok)
	}
}

func TestSoftwareOnlyProtectedChangeE2ERejectsAttestationHeader(t *testing.T) {
	t.Parallel()
	fixture := newSoftwareOnlyE2EFixture(t)
	session := fixture.dial(t)
	defer session.conn.Close()
	change := e2eChange(true)
	headers := fixture.headers(t, session, change, nil)
	headers.Set(AttestationHeader, "unexpected-attestation")

	if status := sendChange(t, session, change, headers); status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", status, http.StatusUnauthorized)
	}
	if _, ok := fixture.store.Lookup(change.ChangeID); ok {
		t.Fatal("software-only action with attestation header was applied")
	}
}

func TestSoftwareOnlyProtectedChangeE2ERejectsChangedAction(t *testing.T) {
	t.Parallel()
	fixture := newSoftwareOnlyE2EFixture(t)
	session := fixture.dial(t)
	defer session.conn.Close()
	signed := e2eChange(true)
	sent := e2eChange(false)
	headers := fixture.headers(t, session, signed, nil)

	if status := sendChange(t, session, sent, headers); status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", status, http.StatusUnauthorized)
	}
	if _, ok := fixture.store.Lookup(sent.ChangeID); ok {
		t.Fatal("changed software-only action was applied")
	}
}

func TestProtectedChangeE2ERejectsChangedAction(t *testing.T) {
	t.Parallel()
	fixture := newE2EFixture(t)
	session := fixture.dial(t)
	defer session.conn.Close()
	signed := e2eChange(true)
	sent := e2eChange(false)
	headers := fixture.headers(t, session, signed, nil)

	if status := sendChange(t, session, sent, headers); status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", status, http.StatusUnauthorized)
	}
	if _, ok := fixture.store.Lookup(sent.ChangeID); ok {
		t.Fatal("changed action was applied")
	}
}

func TestProtectedChangeE2ERejectsWrongTLSSession(t *testing.T) {
	t.Parallel()
	fixture := newE2EFixture(t)
	boundSession := fixture.dial(t)
	headers := fixture.headers(t, boundSession, e2eChange(true), nil)
	_ = boundSession.conn.Close()

	sentSession := fixture.dial(t)
	defer sentSession.conn.Close()
	if status := sendChange(t, sentSession, e2eChange(true), headers); status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", status, http.StatusUnauthorized)
	}
	if _, ok := fixture.store.Lookup("change-0001"); ok {
		t.Fatal("wrong-session action was applied")
	}
}

func TestProtectedChangeE2ERejectsReplay(t *testing.T) {
	t.Parallel()
	fixture := newE2EFixture(t)
	session := fixture.dial(t)
	defer session.conn.Close()
	change := e2eChange(true)
	headers := fixture.headers(t, session, change, nil)

	if status := sendChange(t, session, change, headers); status != http.StatusNoContent {
		t.Fatalf("first status = %d, want %d, audit = %v", status, http.StatusNoContent, fixture.audit.last())
	}
	if status := sendChange(t, session, change, headers); status != http.StatusUnauthorized {
		t.Fatalf("second status = %d, want %d", status, http.StatusUnauthorized)
	}
}

func TestProtectedChangeE2ERejectsRevokedGrant(t *testing.T) {
	t.Parallel()
	fixture := newE2EFixture(t)
	fixture.managerTrust.revoke("grant-change-0001")
	session := fixture.dial(t)
	defer session.conn.Close()
	change := e2eChange(true)
	headers := fixture.headers(t, session, change, nil)

	if status := sendChange(t, session, change, headers); status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", status, http.StatusUnauthorized)
	}
	if _, ok := fixture.store.Lookup(change.ChangeID); ok {
		t.Fatal("revoked-grant action was applied")
	}
}

func TestProtectedChangeE2ERejectsAttestationMismatch(t *testing.T) {
	t.Parallel()
	fixture := newE2EFixture(t)
	session := fixture.dial(t)
	defer session.conn.Close()
	change := e2eChange(true)
	headers := fixture.headers(t, session, change, func(result *production.AttestationResult) {
		result.AttestationBinderSHA256 = strings.Repeat("0", 64)
	})

	if status := sendChange(t, session, change, headers); status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", status, http.StatusUnauthorized)
	}
	if _, ok := fixture.store.Lookup(change.ChangeID); ok {
		t.Fatal("attestation-mismatch action was applied")
	}
}

func TestProtectedChangeE2ERejectsReplayStoreOutage(t *testing.T) {
	t.Parallel()
	fixture := newE2EFixture(t)
	fixture.replayStore.err = errors.New("shared replay unavailable")
	session := fixture.dial(t)
	defer session.conn.Close()
	change := e2eChange(true)
	headers := fixture.headers(t, session, change, nil)

	if status := sendChange(t, session, change, headers); status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", status, http.StatusUnauthorized)
	}
	if _, ok := fixture.store.Lookup(change.ChangeID); ok {
		t.Fatal("replay-outage action was applied")
	}
}

func newE2EFixture(t *testing.T) *e2eFixture {
	return newE2EFixtureForMode(t, false)
}

func newSoftwareOnlyE2EFixture(t *testing.T) *e2eFixture {
	return newE2EFixtureForMode(t, true)
}

func newE2EFixtureForMode(t *testing.T, softwareOnly bool) *e2eFixture {
	t.Helper()
	now := time.Date(2026, time.August, 3, 3, 0, 0, 0, time.UTC)
	managerPublic, managerPrivate := generateEd25519(t)
	agentPublic, agentPrivate := generateEd25519(t)
	attesterPublic, attesterPrivate := generateEd25519(t)
	managerTrust := &mutableTrustSource{snapshot: production.TrustSnapshot{Keys: []clients.LocalKey{{
		KeyID: e2eManagerKeyID,
		Key:   managerPublic,
	}}}}
	agentTrust := &mutableTrustSource{snapshot: production.TrustSnapshot{Keys: []clients.LocalKey{{
		KeyID: e2eAgentKeyID,
		Key:   agentPublic,
	}}}}
	replayStore := &sharedSetNXStore{seen: make(map[string]struct{})}
	store := NewMemoryChangeStore()
	audit := &e2eAudit{}
	profile := production.Profile{
		GrantAuthority: production.AuthorityPolicy{
			ExpectedIssuer:   e2eManagerIssuer,
			ExpectedAudience: e2eAudience,
			ValidMethods:     []string{jwt.SigningMethodEdDSA.Alg()},
			TrustSource:      managerTrust,
		},
		BindingAuthority: production.AuthorityPolicy{
			ExpectedIssuer:   e2eAgentIssuer,
			ExpectedAudience: e2eAudience,
			ValidMethods:     []string{jwt.SigningMethodEdDSA.Alg()},
			TrustSource:      agentTrust,
		},
		Attestation: production.SignedAttestationPolicy{
			TrustedKeys:         map[string]ed25519.PublicKey{e2eAttesterKeyID: attesterPublic},
			PolicyID:            e2ePolicyID,
			AllowedMeasurements: []string{e2eMeasurement},
			MaxAge:              2 * time.Minute,
			ClockSkew:           5 * time.Second,
		},
		ReplayCache: identitypolicy.NewSetNXReplayCacheWithClock(context.Background(), replayStore, func() time.Time { return now }),
		Now:         func() time.Time { return now },
	}
	clientCertificate, clientLeaf, clientCAPool := e2eClientCertificate(t, time.Now().UTC())
	app := Application{
		Nonces:        fixedNonceSource{"change-0001": e2eExpectedNonce},
		Store:         store,
		ExpectedAgent: e2eExpectedAgent,
		AuditFailure:  audit.record,
	}
	if softwareOnly {
		app.SoftwareProfile = &production.SoftwareOnlyProfile{
			GrantAuthority:   profile.GrantAuthority,
			BindingAuthority: profile.BindingAuthority,
			ReplayCache:      profile.ReplayCache,
			Now:              profile.Now,
		}
	} else {
		app.Profile = profile
	}
	server := httptest.NewUnstartedServer(app)
	server.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientCAPool,
		MinVersion: tls.VersionTLS13,
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(server.Certificate())
	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{clientCertificate},
		RootCAs:      serverRoots,
		ServerName:   "example.com",
		MinVersion:   tls.VersionTLS13,
	}
	return &e2eFixture{
		server:          server,
		clientTLS:       clientTLS,
		clientLeaf:      clientLeaf,
		managerPrivate:  managerPrivate,
		agentPrivate:    agentPrivate,
		attesterPrivate: attesterPrivate,
		managerTrust:    managerTrust,
		replayStore:     replayStore,
		store:           store,
		audit:           audit,
		now:             now,
		softwareOnly:    softwareOnly,
	}
}

func (f *e2eFixture) dial(t *testing.T) *e2eSession {
	t.Helper()
	address := strings.TrimPrefix(f.server.URL, "https://")
	conn, err := tls.Dial("tcp", address, f.clientTLS.Clone())
	if err != nil {
		t.Fatalf("TLS dial: %v", err)
	}
	return &e2eSession{conn: conn, reader: bufio.NewReader(conn)}
}

func (f *e2eFixture) headers(t *testing.T, session *e2eSession, change ChangeRequest, mutateAttestation func(*production.AttestationResult)) http.Header {
	t.Helper()
	actionContext, err := CanonicalActionContext(change)
	if err != nil {
		t.Fatal(err)
	}
	state := session.conn.ConnectionState()
	var binding identitypolicy.Binding
	if f.softwareOnly {
		binding, err = production.SoftwareBindingFromTLS(&state, f.clientLeaf, actionContext, e2eExpectedNonce)
	} else {
		binding, err = production.BindingFromTLS(&state, f.clientLeaf, actionContext, e2eExpectedNonce)
	}
	if err != nil {
		t.Fatalf("derive binding: %v", err)
	}
	binding.IssuedAt = f.now.Add(-30 * time.Second)
	binding.ExpiresAt = f.now.Add(90 * time.Second)
	resource := "config://" + change.Tenant + "/" + change.Setting
	grant := signE2EJWT(t, f.managerPrivate, e2eManagerKeyID, jwt.MapClaims{
		"iss":                   e2eManagerIssuer,
		"sub":                   e2eExpectedAgent,
		"aud":                   e2eAudience,
		"jti":                   "grant-change-0001",
		"iat":                   f.now.Add(-time.Minute).Unix(),
		"exp":                   f.now.Add(5 * time.Minute).Unix(),
		"profile_type":          clients.TokenTypeIdentityGrant,
		"profile_version":       clients.ProfileVersion,
		"cnf":                   map[string]string{"kid": e2eAgentKeyID},
		"service":               "protected-change",
		"agent":                 e2eExpectedAgent,
		"task_id":               change.ChangeID,
		"intent_ref":            "change:intent:apply",
		"capability_ref":        "change:capability:write",
		"scopes":                []string{"change.write"},
		"resources":             []string{resource},
		"authorization_details": []string{"change:set-enabled"},
	})
	sessionClaims := jwt.MapClaims{
		"iss":                    e2eAgentIssuer,
		"aud":                    e2eAudience,
		"jti":                    "binding-change-0001",
		"iat":                    binding.IssuedAt.Unix(),
		"exp":                    binding.ExpiresAt.Unix(),
		"profile_type":           clients.TokenTypeSessionBinding,
		"profile_version":        clients.ProfileVersion,
		"grant_hash":             clients.IdentityGrantHash(grant),
		"leaf_public_key_sha256": binding.LeafPublicKeySHA256,
		"tls_exporter_sha256":    binding.TLSExporterSHA256,
		"request_context_sha256": binding.RequestContextSHA256,
		"nonce":                  binding.Nonce,
	}
	if !f.softwareOnly {
		sessionClaims["attestation_binder_sha256"] = binding.AttestationBinderSHA256
	}
	sessionBinding := signE2EJWT(t, f.agentPrivate, e2eAgentKeyID, sessionClaims)
	headers := make(http.Header)
	headers.Set(IdentityGrantHeader, grant)
	headers.Set(SessionBindingHeader, sessionBinding)
	if f.softwareOnly {
		return headers
	}
	attestation := production.AttestationResult{
		Version:                 production.AttestationResultVersion,
		ResultID:                "attestation-change-0001",
		VerifierKeyID:           e2eAttesterKeyID,
		PolicyID:                e2ePolicyID,
		Measurement:             e2eMeasurement,
		AttestationBinderSHA256: binding.AttestationBinderSHA256,
		IssuedAt:                f.now.Add(-30 * time.Second),
		ExpiresAt:               f.now.Add(90 * time.Second),
	}
	if mutateAttestation != nil {
		mutateAttestation(&attestation)
	}
	signE2EAttestation(t, &attestation, f.attesterPrivate)
	attestationJSON, err := json.Marshal(attestation)
	if err != nil {
		t.Fatal(err)
	}
	headers.Set(AttestationHeader, base64.RawURLEncoding.EncodeToString(attestationJSON))
	return headers
}

func sendChange(t *testing.T, session *e2eSession, change ChangeRequest, headers http.Header) int {
	t.Helper()
	body, err := json.Marshal(change)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, "https://example.com"+ChangePath, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header = headers.Clone()
	request.Header.Set("Content-Type", "application/json")
	if err := request.Write(session.conn); err != nil {
		t.Fatalf("write request: %v", err)
	}
	response, err := http.ReadResponse(session.reader, request)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	return response.StatusCode
}

func e2eChange(enabled bool) ChangeRequest {
	return ChangeRequest{
		ChangeID: "change-0001",
		Tenant:   "tenant-01",
		Setting:  "feature-x",
		Enabled:  enabled,
	}
}

func signE2EJWT(t *testing.T, key ed25519.PrivateKey, keyID string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = keyID
	value, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func signE2EAttestation(t *testing.T, result *production.AttestationResult, key ed25519.PrivateKey) {
	t.Helper()
	result.Signature = nil
	payload, err := result.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	result.Signature = ed25519.Sign(key, payload)
}

func generateEd25519(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func e2eClientCertificate(t *testing.T, now time.Time) (tls.Certificate, *x509.Certificate, *x509.CertPool) {
	t.Helper()
	caPublic, caPrivate := generateEd25519(t)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ASB protected-change test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	clientPublic, clientPrivate := generateEd25519(t)
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "change-agent-01"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, ca, clientPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	clientLeaf, err := x509.ParseCertificate(clientDER)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})
	certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	keyDER, err := x509.MarshalPKCS8PrivateKey(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return certificate, clientLeaf, pool
}
