// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package agtpdiscover

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/thinksyncs/agents-secure-binding/pkg/agtp/discovery"
	"github.com/thinksyncs/agents-secure-binding/pkg/atls/identitypolicy"
	"github.com/thinksyncs/agents-secure-binding/pkg/clients"
	"github.com/thinksyncs/agents-secure-binding/pkg/production"
)

const (
	testAudience      = "https://agtp-gateway.example.test/v1/discover"
	testManagerIssuer = "https://manager.example.test"
	testAgentIssuer   = "https://agent.example.test"
	testManagerKeyID  = "manager-ed25519-2026-01"
	testAgentKeyID    = "agent-ed25519-2026-01"
	testExpectedAgent = "discover-client-01"
	testNonce         = "verifier-nonce-discover-0001"
)

type testFixture struct {
	server         *httptest.Server
	clientTLS      *tls.Config
	clientLeaf     *x509.Certificate
	managerPrivate ed25519.PrivateKey
	agentPrivate   ed25519.PrivateKey
	catalog        *recordingCatalog
	now            time.Time
}

type testSession struct {
	conn   *tls.Conn
	reader *bufio.Reader
}

type fixedNonceSource struct{ nonce string }

func (s fixedNonceSource) ExpectedNonce(context.Context, Query) (string, error) {
	return s.nonce, nil
}

type recordingCatalog struct {
	mu         sync.Mutex
	queries    []Query
	requesters []discovery.Requester
	store      *discovery.PresenceStore
}

func (c *recordingCatalog) Discover(ctx context.Context, query Query, requester discovery.Requester) (discovery.Response, error) {
	c.mu.Lock()
	c.queries = append(c.queries, query)
	c.requesters = append(c.requesters, requester)
	c.mu.Unlock()
	return c.store.Discover(ctx, query, requester)
}

func (c *recordingCatalog) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.queries)
}

func TestASBDiscoverAcceptsExactBoundQuery(t *testing.T) {
	fixture := newTestFixture(t)
	session := fixture.dial(t)
	defer session.conn.Close()
	query := testQuery("generate")
	headers := fixture.headers(t, session, query)

	status, body := sendQuery(t, session, query, headers)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", status, http.StatusOK, body)
	}
	if fixture.catalog.callCount() != 1 {
		t.Fatalf("catalog calls = %d, want 1", fixture.catalog.callCount())
	}
	if !bytes.Contains(body, []byte("result-agent-01")) {
		t.Fatalf("response body = %s", body)
	}
}

func TestASBDiscoverRejectsChangedCapability(t *testing.T) {
	fixture := newTestFixture(t)
	session := fixture.dial(t)
	defer session.conn.Close()
	headers := fixture.headers(t, session, testQuery("generate"))

	status, _ := sendQuery(t, session, testQuery("analyze"), headers)
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", status, http.StatusUnauthorized)
	}
	if fixture.catalog.callCount() != 0 {
		t.Fatalf("catalog calls = %d, want 0", fixture.catalog.callCount())
	}
}

func TestASBDiscoverRejectsReplay(t *testing.T) {
	fixture := newTestFixture(t)
	session := fixture.dial(t)
	defer session.conn.Close()
	query := testQuery("generate")
	headers := fixture.headers(t, session, query)

	if status, _ := sendQuery(t, session, query, headers); status != http.StatusOK {
		t.Fatalf("first status = %d, want %d", status, http.StatusOK)
	}
	if status, _ := sendQuery(t, session, query, headers); status != http.StatusUnauthorized {
		t.Fatalf("second status = %d, want %d", status, http.StatusUnauthorized)
	}
	if fixture.catalog.callCount() != 1 {
		t.Fatalf("catalog calls = %d, want 1", fixture.catalog.callCount())
	}
}

func TestASBDiscoverRejectsWrongTLSSession(t *testing.T) {
	fixture := newTestFixture(t)
	boundSession := fixture.dial(t)
	headers := fixture.headers(t, boundSession, testQuery("generate"))
	_ = boundSession.conn.Close()

	otherSession := fixture.dial(t)
	defer otherSession.conn.Close()
	status, _ := sendQuery(t, otherSession, testQuery("generate"), headers)
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", status, http.StatusUnauthorized)
	}
	if fixture.catalog.callCount() != 0 {
		t.Fatalf("catalog calls = %d, want 0", fixture.catalog.callCount())
	}
}

func TestCanonicalActionContextRejectsAliases(t *testing.T) {
	valid, err := CanonicalActionContext(testQuery("generate"))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"profile":"asb.agtp-discover/v1","method":"DISCOVER","path":"/population","capability":"generate","limit":12}`
	if string(valid) != want {
		t.Fatalf("context = %s, want %s", valid, want)
	}
	if _, err := CanonicalActionContext(testQuery("Generate")); err == nil {
		t.Fatal("mixed-case capability accepted, want canonical rejection")
	}
}

func newTestFixture(t *testing.T) *testFixture {
	t.Helper()
	store := discovery.NewPresenceStore()
	if _, err := store.Announce(discovery.Record{
		AgentID:      "result-agent-01",
		Name:         "generator.example",
		Capabilities: []string{"generate"},
		Visibility: discovery.Visibility{
			Mode:          discovery.VisibilityExplicitOnly,
			AllowedAgents: []string{testExpectedAgent},
		},
		Version: 1,
	}); err != nil {
		t.Fatal(err)
	}
	catalog := &recordingCatalog{store: store}
	now := time.Now().UTC().Truncate(time.Second)
	managerPublic, managerPrivate := generateEd25519(t)
	agentPublic, agentPrivate := generateEd25519(t)
	clientCertificate, clientLeaf, clientCAs := testClientCertificate(t, now)
	profile := production.SoftwareOnlyProfile{
		GrantAuthority: production.AuthorityPolicy{
			ExpectedIssuer:   testManagerIssuer,
			ExpectedAudience: testAudience,
			ValidMethods:     []string{"EdDSA"},
			TrustSource: production.StaticTrustSource{Trust: production.TrustSnapshot{
				Keys: []clients.LocalKey{{KeyID: testManagerKeyID, Key: managerPublic}},
			}},
			MaxTokenLifetime: 10 * time.Minute,
		},
		BindingAuthority: production.AuthorityPolicy{
			ExpectedIssuer:   testAgentIssuer,
			ExpectedAudience: testAudience,
			ValidMethods:     []string{"EdDSA"},
			TrustSource: production.StaticTrustSource{Trust: production.TrustSnapshot{
				Keys: []clients.LocalKey{{KeyID: testAgentKeyID, Key: agentPublic}},
			}},
			MaxTokenLifetime: 10 * time.Minute,
		},
		ReplayCache: identitypolicy.NewMemoryReplayCache(),
		Now:         func() time.Time { return now },
	}
	server := httptest.NewUnstartedServer(Application{
		Profile:       profile,
		Nonces:        fixedNonceSource{nonce: testNonce},
		Catalog:       catalog,
		ExpectedAgent: testExpectedAgent,
	})
	server.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientCAs,
		MinVersion: tls.VersionTLS13,
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(server.Certificate())
	return &testFixture{
		server: server,
		clientTLS: &tls.Config{
			Certificates: []tls.Certificate{clientCertificate},
			RootCAs:      serverRoots,
			ServerName:   "example.com",
			MinVersion:   tls.VersionTLS13,
		},
		clientLeaf:     clientLeaf,
		managerPrivate: managerPrivate,
		agentPrivate:   agentPrivate,
		catalog:        catalog,
		now:            now,
	}
}

func (f *testFixture) dial(t *testing.T) *testSession {
	t.Helper()
	address := strings.TrimPrefix(f.server.URL, "https://")
	conn, err := tls.Dial("tcp", address, f.clientTLS.Clone())
	if err != nil {
		t.Fatalf("TLS dial: %v", err)
	}
	return &testSession{conn: conn, reader: bufio.NewReader(conn)}
}

func (f *testFixture) headers(t *testing.T, session *testSession, query Query) http.Header {
	t.Helper()
	actionContext, err := CanonicalActionContext(query)
	if err != nil {
		t.Fatal(err)
	}
	state := session.conn.ConnectionState()
	binding, err := production.SoftwareBindingFromTLS(&state, f.clientLeaf, actionContext, testNonce)
	if err != nil {
		t.Fatalf("derive binding: %v", err)
	}
	binding.IssuedAt = f.now.Add(-30 * time.Second)
	binding.ExpiresAt = f.now.Add(90 * time.Second)
	grant := signJWT(t, f.managerPrivate, testManagerKeyID, jwt.MapClaims{
		"iss":             testManagerIssuer,
		"sub":             testExpectedAgent,
		"aud":             testAudience,
		"jti":             "grant-discover-0001",
		"iat":             f.now.Add(-time.Minute).Unix(),
		"exp":             f.now.Add(5 * time.Minute).Unix(),
		"profile_type":    clients.TokenTypeIdentityGrant,
		"profile_version": clients.ProfileVersion,
		"cnf":             map[string]string{"kid": testAgentKeyID},
		"service":         "agtp-discovery",
		"agent":           testExpectedAgent,
		"capability_ref":  capabilityReference(query.Capability),
		"ontology_id":     "agtp:capability-method:v1",
		"scopes":          []string{"agtp.discover"},
		"resources":       []string{"agtp:/population"},
	})
	bindingJWT := signJWT(t, f.agentPrivate, testAgentKeyID, jwt.MapClaims{
		"iss":                    testAgentIssuer,
		"aud":                    testAudience,
		"jti":                    "binding-discover-0001",
		"iat":                    binding.IssuedAt.Unix(),
		"exp":                    binding.ExpiresAt.Unix(),
		"profile_type":           clients.TokenTypeSessionBinding,
		"profile_version":        clients.ProfileVersion,
		"grant_hash":             clients.IdentityGrantHash(grant),
		"leaf_public_key_sha256": binding.LeafPublicKeySHA256,
		"tls_exporter_sha256":    binding.TLSExporterSHA256,
		"request_context_sha256": binding.RequestContextSHA256,
		"nonce":                  binding.Nonce,
	})
	headers := make(http.Header)
	headers.Set(IdentityGrantHeader, grant)
	headers.Set(SessionBindingHeader, bindingJWT)
	return headers
}

func sendQuery(t *testing.T, session *testSession, query Query, headers http.Header) (int, []byte) {
	t.Helper()
	body, err := json.Marshal(query)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, "https://example.com"+DiscoverPath, bytes.NewReader(body))
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
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, responseBody
}

func testQuery(capability string) Query {
	return Query{Capability: capability, Limit: 12}
}

func signJWT(t *testing.T, key ed25519.PrivateKey, keyID string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = keyID
	value, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func generateEd25519(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func testClientCertificate(t *testing.T, now time.Time) (tls.Certificate, *x509.Certificate, *x509.CertPool) {
	t.Helper()
	caPublic, caPrivate := generateEd25519(t)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ASB AGTP discover test CA"},
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
		Subject:      pkix.Name{CommonName: testExpectedAgent},
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
