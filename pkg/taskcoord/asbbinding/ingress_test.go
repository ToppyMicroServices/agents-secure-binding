// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
	"github.com/golang-jwt/jwt/v5"
)

const (
	ingressManagerKeyID = "manager-key"
	ingressActorKeyID   = "actor-key"
)

var (
	ingressManagerSecret = []byte("manager-secret-for-live-ingress-test")
	ingressActorSecret   = []byte("actor-secret-for-live-ingress-test")
)

func TestHumanTaskCoordIngressDemo(t *testing.T) {
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	server, client, store := newLiveIngress(t, now)

	request := TransitionRequest{
		ParticipantID: "human:alice", EventID: "event:accept:live", TaskID: "task:human:1",
		AssignmentID: "assignment:human:1", Operation: taskcoord.OperationAccept,
		ExpectedRevision: 1, Detail: "accept through the TLS ingress",
	}
	challenge := requestChallenge(t, client, server.URL, OperationAssignmentTransition, request, http.StatusCreated)
	digest, err := TransitionDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	if challenge.RequestDigest != digest.String() || challenge.Nonce == "" ||
		challenge.binding.LeafPublicKeySHA256 == "" || challenge.binding.TLSExporterSHA256 == "" ||
		challenge.binding.RequestContextSHA256 != RequestContextSHA256(digest) {
		t.Fatalf("client did not derive the expected TLS binding: %+v", challenge)
	}
	t.Logf("bound: request_digest=%s tls_exporter_sha256=%s", challenge.RequestDigest, challenge.binding.TLSExporterSHA256)
	grant, proof := signedIngressEvidence(t, now, digest, challenge)
	response := executeOperation(t, client, server.URL, ExecuteRequest{
		ChallengeID: challenge.ChallengeID, Operation: OperationAssignmentTransition,
		Request: mustJSON(t, request), GrantJWT: grant, SessionBindingJWT: proof,
	}, http.StatusOK)
	if response.Assignment == nil || response.Assignment.Status != taskcoord.AssignmentAccepted {
		t.Fatalf("execute response = %+v", response)
	}
	stored, err := store.LoadAssignment(context.Background(), request.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != taskcoord.AssignmentAccepted || stored.Revision != 2 ||
		stored.LastTransition.ActorID != testActorID ||
		stored.LastTransition.ParticipantID != request.ParticipantID {
		t.Fatalf("stored Assignment = %+v", stored)
	}
	t.Logf("accepted: participant=%s actor=%s status=%s revision=%d",
		stored.LastTransition.ParticipantID, stored.LastTransition.ActorID, stored.Status, stored.Revision)

	interactionRequest := InteractionRequest{
		ParticipantID: "human:alice", EventID: "event:question:live",
		InteractionID: "interaction:live", TaskID: stored.TaskID, AssignmentID: stored.AssignmentID,
		Kind: taskcoord.InteractionQuestion, ContentRef: "urn:encrypted-content:question:live",
		ContentDigest: repeatedDigest('c'),
	}
	interactionChallenge := requestChallenge(
		t, client, server.URL, OperationInteractionAppend, interactionRequest, http.StatusCreated,
	)
	interactionDigest, err := InteractionDigest(interactionRequest)
	if err != nil {
		t.Fatal(err)
	}
	interactionGrant, interactionProof := signedIngressEvidence(t, now, interactionDigest, interactionChallenge)
	interactionResponse := executeOperation(t, client, server.URL, ExecuteRequest{
		ChallengeID: interactionChallenge.ChallengeID, Operation: OperationInteractionAppend,
		Request: mustJSON(t, interactionRequest), GrantJWT: interactionGrant,
		SessionBindingJWT: interactionProof,
	}, http.StatusOK)
	if interactionResponse.Interaction == nil ||
		interactionResponse.Interaction.EventID != interactionRequest.EventID {
		t.Fatalf("interaction response = %+v", interactionResponse)
	}
	storedInteraction, err := store.LoadInteractionEvent(context.Background(), interactionRequest.EventID)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("appended: interaction=%s kind=%s content_digest=%s",
		storedInteraction.InteractionID, storedInteraction.Kind, storedInteraction.ContentDigest)
}

func TestIngressRejectsChallengeOnAnotherTLSConnection(t *testing.T) {
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	server, firstClient, _ := newLiveIngress(t, now)
	secondClient := cloneHTTPClient(t, firstClient)
	request := TransitionRequest{
		ParticipantID: "human:alice", EventID: "event:accept:cross-connection", TaskID: "task:human:1",
		AssignmentID: "assignment:human:1", Operation: taskcoord.OperationAccept, ExpectedRevision: 1,
	}
	challenge := requestChallenge(t, firstClient, server.URL, OperationAssignmentTransition, request, http.StatusCreated)
	digest, err := TransitionDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	grant, proof := signedIngressEvidence(t, now, digest, challenge)
	executeOperation(t, secondClient, server.URL, ExecuteRequest{
		ChallengeID: challenge.ChallengeID, Operation: OperationAssignmentTransition,
		Request: mustJSON(t, request), GrantJWT: grant, SessionBindingJWT: proof,
	}, http.StatusUnauthorized)
}

func TestIngressRejectsRequestMutationAndStaleRevision(t *testing.T) {
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	server, client, store := newLiveIngress(t, now)
	request := TransitionRequest{
		ParticipantID: "human:alice", EventID: "event:accept:mutation", TaskID: "task:human:1",
		AssignmentID: "assignment:human:1", Operation: taskcoord.OperationAccept,
		ExpectedRevision: 1, Detail: "original",
	}
	challenge := requestChallenge(t, client, server.URL, OperationAssignmentTransition, request, http.StatusCreated)
	digest, err := TransitionDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	grant, proof := signedIngressEvidence(t, now, digest, challenge)
	mutated := request
	mutated.Detail = "changed"
	executeOperation(t, client, server.URL, ExecuteRequest{
		ChallengeID: challenge.ChallengeID, Operation: OperationAssignmentTransition,
		Request: mustJSON(t, mutated), GrantJWT: grant, SessionBindingJWT: proof,
	}, http.StatusUnauthorized)

	fresh := request
	fresh.EventID = "event:accept:fresh"
	fresh.Detail = ""
	freshChallenge := requestChallenge(t, client, server.URL, OperationAssignmentTransition, fresh, http.StatusCreated)
	freshDigest, err := TransitionDigest(fresh)
	if err != nil {
		t.Fatal(err)
	}
	freshGrant, freshProof := signedIngressEvidence(t, now, freshDigest, freshChallenge)
	executeOperation(t, client, server.URL, ExecuteRequest{
		ChallengeID: freshChallenge.ChallengeID, Operation: OperationAssignmentTransition,
		Request: mustJSON(t, fresh), GrantJWT: freshGrant, SessionBindingJWT: freshProof,
	}, http.StatusOK)

	stale := fresh
	stale.EventID = "event:accept:stale"
	stale.Operation = taskcoord.OperationDecline
	staleChallenge := requestChallenge(t, client, server.URL, OperationAssignmentTransition, stale, http.StatusCreated)
	staleDigest, err := TransitionDigest(stale)
	if err != nil {
		t.Fatal(err)
	}
	staleGrant, staleProof := signedIngressEvidence(t, now, staleDigest, staleChallenge)
	executeOperation(t, client, server.URL, ExecuteRequest{
		ChallengeID: staleChallenge.ChallengeID, Operation: OperationAssignmentTransition,
		Request: mustJSON(t, stale), GrantJWT: staleGrant, SessionBindingJWT: staleProof,
	}, http.StatusConflict)

	stored, err := store.LoadAssignment(context.Background(), request.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != taskcoord.AssignmentAccepted || stored.Revision != 2 {
		t.Fatalf("stale request changed Assignment: %+v", stored)
	}
}

func TestIngressRejectsPlainHTTPAndUnverifiedClient(t *testing.T) {
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	store := seededIngressStore(t, now)
	handler := mustIngressHandler(t, now, store, identitypolicy.NewMemoryReplayCache())
	request := TransitionRequest{
		ParticipantID: "human:alice", EventID: "event:accept:no-tls", TaskID: "task:human:1",
		AssignmentID: "assignment:human:1", Operation: taskcoord.OperationAccept, ExpectedRevision: 1,
	}
	body := mustJSON(t, ChallengeRequest{Operation: OperationAssignmentTransition, Request: mustJSON(t, request)})
	recorder := httptest.NewRecorder()
	httpRequest := httptest.NewRequest(http.MethodPost, IngressChallengePath, bytes.NewReader(body))
	handler.ServeHTTP(recorder, httpRequest)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("plaintext status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}

	server, _, _ := newLiveIngress(t, now)
	unverified := server.Client()
	response, err := unverified.Post(server.URL+IngressChallengePath, "application/json", bytes.NewReader(body))
	if err == nil {
		defer response.Body.Close()
		t.Fatalf("TLS request without client certificate unexpectedly returned status %d", response.StatusCode)
	}
}

func TestIngressStrictJSONRejectsDuplicateAndUnknownMembers(t *testing.T) {
	tests := []string{
		`{"operation":"ASSIGNMENT_TRANSITION","operation":"INTERACTION_APPEND","request":{}}`,
		`{"operation":"ASSIGNMENT_TRANSITION","request":{},"verified":true}`,
		`{"operation":"ASSIGNMENT_TRANSITION","request":{"participant_id":"human:1","participant_id":"human:2"}}`,
	}
	for _, input := range tests {
		var request ChallengeRequest
		if err := decodeIngressJSON(strings.NewReader(input), &request); err == nil {
			t.Fatalf("invalid JSON accepted: %s", input)
		}
	}
}

func TestServerTLSConfigRequiresCertificateAndClientCA(t *testing.T) {
	if _, err := ServerTLSConfig(tls.Certificate{}, x509.NewCertPool()); err == nil {
		t.Fatal("missing server certificate was accepted")
	}
	ca, _, serverCert, _ := ingressCertificates(t)
	if _, err := ServerTLSConfig(serverCert, nil); err == nil {
		t.Fatal("missing client CA was accepted")
	}
	config, err := ServerTLSConfig(serverCert, ca)
	if err != nil {
		t.Fatal(err)
	}
	if config.MinVersion != tls.VersionTLS13 || config.MaxVersion != tls.VersionTLS13 ||
		config.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("TLS config = %+v", config)
	}
	ingress := newTestIngress(time.Now(), taskcoord.NewMemoryStore(), identitypolicy.NewMemoryReplayCache())
	if _, err := ingress.NewTLSServer("", serverCert, ca); err == nil {
		t.Fatal("missing listen address was accepted")
	}
	httpServer, err := ingress.NewTLSServer("127.0.0.1:8443", serverCert, ca)
	if err != nil {
		t.Fatal(err)
	}
	if httpServer.TLSConfig == nil || httpServer.ReadHeaderTimeout == 0 || httpServer.MaxHeaderBytes == 0 {
		t.Fatalf("HTTP server safety limits were not configured: %+v", httpServer)
	}
}

func newLiveIngress(t *testing.T, now time.Time) (*httptest.Server, *http.Client, *taskcoord.MemoryStore) {
	t.Helper()
	store := seededIngressStore(t, now)
	replay, err := identitypolicy.NewDirectoryReplayCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ingress := newTestIngress(now, store, replay)
	ca, serverRoots, serverCert, clientCert := ingressCertificates(t)
	configured, err := ingress.NewTLSServer("127.0.0.1:0", serverCert, ca)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(configured.Handler)
	server.TLS = configured.TLSConfig
	server.EnableHTTP2 = true
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)

	clientTLS := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: serverRoots, Certificates: []tls.Certificate{clientCert},
	}
	transport := &http.Transport{
		TLSClientConfig: clientTLS, ForceAttemptHTTP2: true, MaxConnsPerHost: 1,
	}
	client := &http.Client{Transport: transport}
	t.Cleanup(transport.CloseIdleConnections)
	return server, client, store
}

func mustIngressHandler(
	t *testing.T,
	now time.Time,
	store taskcoord.Store,
	replay identitypolicy.ReplayCache,
) http.Handler {
	t.Helper()
	ingress := newTestIngress(now, store, replay)
	handler, err := ingress.Handler()
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func newTestIngress(now time.Time, store taskcoord.Store, replay identitypolicy.ReplayCache) *Ingress {
	return &Ingress{
		Store: store, Now: func() time.Time { return now }, ChallengeTTL: time.Minute,
		Policy: IngressPolicy{
			Grant: clients.JWTVerifyOptions{
				ExpectedIssuer: "human-operation-authority", ExpectedAudience: testAudience,
				ValidMethods: []string{"HS256"},
				LocalKeys:    []clients.LocalKey{{KeyID: ingressManagerKeyID, Key: ingressManagerSecret}},
			},
			SessionBinding: clients.JWTVerifyOptions{
				ExpectedIssuer: "human-gateway", ExpectedAudience: testAudience,
				ValidMethods: []string{"HS256"},
				LocalKeys:    []clients.LocalKey{{KeyID: ingressActorKeyID, Key: ingressActorSecret}},
			},
			ReplayCache: replay,
		},
	}
}

func seededIngressStore(t *testing.T, now time.Time) *taskcoord.MemoryStore {
	t.Helper()
	ctx := context.Background()
	store := taskcoord.NewMemoryStore()
	human := testParticipant("human:alice", taskcoord.ParticipantHuman, false, now.Add(-time.Hour))
	registerParticipants(t, ctx, store, human)
	assignment := offeredHumanAssignment(t, human, now.Add(-10*time.Minute))
	if err := store.CommitAssignment(ctx, 0, assignment, assignment.LastTransition); err != nil {
		t.Fatal(err)
	}
	return store
}

func requestChallenge(
	t *testing.T,
	client *http.Client,
	baseURL string,
	operation string,
	request any,
	wantStatus int,
) liveChallenge {
	t.Helper()
	body := mustJSON(t, ChallengeRequest{Operation: operation, Request: mustJSON(t, request)})
	response, err := client.Post(baseURL+IngressChallengePath, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("challenge request: %v", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != wantStatus {
		t.Fatalf("challenge status = %d, want %d, body = %s", response.StatusCode, wantStatus, raw)
	}
	var result liveChallenge
	if wantStatus < 300 {
		if err := json.Unmarshal(raw, &result.ChallengeResponse); err != nil {
			t.Fatal(err)
		}
		operationEnvelope, err := decodeOperation(operation, mustJSON(t, request))
		if err != nil {
			t.Fatal(err)
		}
		transport, ok := client.Transport.(*http.Transport)
		if !ok || len(transport.TLSClientConfig.Certificates) == 0 ||
			transport.TLSClientConfig.Certificates[0].Leaf == nil || response.TLS == nil {
			t.Fatal("test client does not expose TLS binding material")
		}
		result.binding, err = BindingFromTLS(
			response.TLS,
			transport.TLSClientConfig.Certificates[0].Leaf,
			operationEnvelope.digest,
			result.Nonce,
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	return result
}

type liveChallenge struct {
	ChallengeResponse
	binding identitypolicy.Binding
}

func executeOperation(
	t *testing.T,
	client *http.Client,
	baseURL string,
	request ExecuteRequest,
	wantStatus int,
) ExecuteResponse {
	t.Helper()
	response, err := client.Post(baseURL+IngressExecutePath, "application/json", bytes.NewReader(mustJSON(t, request)))
	if err != nil {
		t.Fatalf("execute request: %v", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != wantStatus {
		t.Fatalf("execute status = %d, want %d, body = %s", response.StatusCode, wantStatus, raw)
	}
	var result ExecuteResponse
	if wantStatus < 300 {
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}
	}
	return result
}

func signedIngressEvidence(
	t *testing.T,
	now time.Time,
	digest Digest,
	challenge liveChallenge,
) (string, string) {
	t.Helper()
	grant := signTestJWT(t, ingressManagerKeyID, ingressManagerSecret, jwt.MapClaims{
		"iss": "human-operation-authority", "sub": testActorID, "aud": testAudience,
		"jti": "authorization:" + challenge.ChallengeID, "iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(5 * time.Minute).Unix(), "profile_type": clients.TokenTypeIdentityGrant,
		"profile_version": clients.ProfileVersion, "cnf": map[string]any{"kid": ingressActorKeyID},
		"authorization_details": []string{AuthorizationDetail(digest)},
	})
	proof := signTestJWT(t, ingressActorKeyID, ingressActorSecret, jwt.MapClaims{
		"iss": "human-gateway", "aud": testAudience, "jti": "proof:" + challenge.ChallengeID,
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Minute).Unix(),
		"profile_type": clients.TokenTypeSessionBinding, "profile_version": clients.ProfileVersion,
		"grant_hash":             clients.IdentityGrantHash(grant),
		"leaf_public_key_sha256": challenge.binding.LeafPublicKeySHA256,
		"tls_exporter_sha256":    challenge.binding.TLSExporterSHA256,
		"request_context_sha256": challenge.binding.RequestContextSHA256,
		"nonce":                  challenge.Nonce,
	})
	return grant, proof
}

func cloneHTTPClient(t *testing.T, source *http.Client) *http.Client {
	t.Helper()
	original, ok := source.Transport.(*http.Transport)
	if !ok {
		t.Fatal("source client does not use *http.Transport")
	}
	transport := original.Clone()
	transport.CloseIdleConnections()
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport}
}

func mustJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func ingressCertificates(t *testing.T) (*x509.CertPool, *x509.CertPool, tls.Certificate, tls.Certificate) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ASB demo CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(caCertificate)
	serverCert := issuedCertificate(t, caCertificate, caKey, big.NewInt(2), "localhost", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	clientCert := issuedCertificate(t, caCertificate, caKey, big.NewInt(3), "human-gateway", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	return certPool, certPool.Clone(), serverCert, clientCert
}

func issuedCertificate(
	t *testing.T,
	ca *x509.Certificate,
	caKey *ecdsa.PrivateKey,
	serial *big.Int,
	commonName string,
	usage []x509.ExtKeyUsage,
) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: commonName},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usage,
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key, Leaf: leaf}
}
