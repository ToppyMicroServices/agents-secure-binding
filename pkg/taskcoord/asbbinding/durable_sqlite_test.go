// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding_test

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
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord/asbbinding"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord/sqlitestore"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/schemas"
	"github.com/golang-jwt/jwt/v5"
)

// This uses actual TLS exporter bindings, signed exact grants, and a reopened
// SQLite store. The proxy discards the successful body after commit; recovery
// is a separate request on a new TLS connection with a new proof.
func TestSQLiteHumanIngressLostResponsesRecoverAllOperationKinds(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "coordination.db")
	now := time.Now().UTC().Truncate(time.Second)
	store, err := sqlitestore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []taskcoord.Participant{
		{Schema: taskcoord.ParticipantSchemaV1, ParticipantID: "human:alice", Kind: taskcoord.ParticipantHuman, IdentityRef: "urn:identity:alice", Status: taskcoord.ParticipantActive, MayDelegate: true, RegisteredAt: now.Add(-time.Hour)},
		{Schema: taskcoord.ParticipantSchemaV1, ParticipantID: "human:bob", Kind: taskcoord.ParticipantHuman, IdentityRef: "urn:identity:bob", Status: taskcoord.ParticipantActive, RegisteredAt: now.Add(-time.Hour)},
		{Schema: taskcoord.ParticipantSchemaV1, ParticipantID: "agent:reviewer", Kind: taskcoord.ParticipantAgent, IdentityRef: "urn:identity:reviewer", Status: taskcoord.ParticipantActive, RegisteredAt: now.Add(-time.Hour)},
	} {
		if err := store.RegisterParticipant(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	offer := asbbinding.OfferRequest{ParticipantID: "human:alice", EventID: "event:offer", TaskID: "task:1", AssignmentID: "assignment:1", TargetParticipantID: "human:alice", Role: taskcoord.RoleAssignee, AuthorityDigest: strings.Repeat("a", 64)}
	accept := asbbinding.TransitionRequest{ParticipantID: "human:alice", EventID: "event:accept", TaskID: "task:1", AssignmentID: "assignment:1", Operation: taskcoord.OperationAccept, ExpectedRevision: 1}
	question := asbbinding.InteractionRequest{ParticipantID: "human:alice", EventID: "event:question", TaskID: "task:1", AssignmentID: "assignment:1", InteractionID: "interaction:1", Kind: taskcoord.InteractionQuestion, ContentRef: "urn:question:1", ContentDigest: strings.Repeat("b", 64)}
	delegation := asbbinding.DelegationRequest{ParticipantID: "human:alice", EventID: "event:delegate", ParentTaskID: "task:1", ParentAssignmentID: "assignment:1", ExpectedRevision: 2, DecisionID: "decision:1", ChildEventID: "event:child", ChildTaskID: "task:child", ChildAssignmentID: "assignment:child", TargetParticipantID: "agent:reviewer", Role: taskcoord.RoleReviewer, AuthorityDigest: strings.Repeat("c", 64)}
	offerDigest, _ := asbbinding.OfferDigest(offer)
	acceptDigest, _ := asbbinding.TransitionDigest(accept)
	questionDigest, _ := asbbinding.InteractionDigest(question)
	delegationDigest, _ := asbbinding.DelegationDigest(delegation)
	cases := []struct {
		operation, id string
		request       any
		digest        asbbinding.Digest
	}{
		{asbbinding.OperationAssignmentOffer, offer.EventID, offer, offerDigest},
		{asbbinding.OperationAssignmentTransition, accept.EventID, accept, acceptDigest},
		{asbbinding.OperationInteractionAppend, question.EventID, question, questionDigest},
		{asbbinding.OperationAssignmentDelegation, delegation.EventID, delegation, delegationDigest},
	}
	for _, tc := range cases {
		t.Run(tc.operation, func(t *testing.T) {
			server, client, discarded := sqliteIngressServer(t, store, now, true, nil)
			request := sqliteSignedRequest(t, client, server.URL, now, tc.operation, tc.request, tc.digest, "gateway:1")
			status, _ := sqlitePost(t, client, server.URL+asbbinding.IngressExecutePath, request)
			if status != http.StatusServiceUnavailable {
				t.Fatalf("lost response status = %d", status)
			}
			original := <-discarded
			server.Close()
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = sqlitestore.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			// The original proof and challenge have expired; a new recovery grant is
			// authorized for this outcome only, without resubmitting its mutation.
			now = now.Add(6 * time.Minute)
			var denied atomic.Bool
			server, client, _ = sqliteIngressServer(t, store, now, false, &denied)
			defer server.Close()
			recovery := asbbinding.RecoveryRequest{ParticipantID: "human:alice", OperationID: tc.id, RequestDigest: tc.digest.String()}
			digest, err := asbbinding.RecoveryDigest(recovery)
			if err != nil {
				t.Fatal(err)
			}
			read := sqliteSignedRequest(t, client, server.URL, now, asbbinding.OperationRecover, recovery, digest, "gateway:1")
			status, recovered := sqlitePost(t, client, server.URL+asbbinding.IngressRecoverPath, read)
			if status != http.StatusOK || !bytes.Equal(original, recovered) {
				t.Fatalf("recovery status=%d; body differs from original: %s", status, recovered)
			}
			if err := schemas.ValidateHumanIngressResponseJSON(recovered); err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(recovered, []byte("proof:"+request.ChallengeID)) || bytes.Contains(recovered, []byte("proof:"+read.ChallengeID)) {
				t.Fatal("recovery replaced original proof provenance")
			}
			// The replayed recovery cannot be reused on its original connection.
			status, _ = sqlitePost(t, client, server.URL+asbbinding.IngressRecoverPath, read)
			if status != http.StatusUnauthorized {
				t.Fatalf("recovery replay = %d", status)
			}
			freshExecute := sqliteSignedRequest(t, client, server.URL, now, tc.operation, tc.request, tc.digest, "gateway:1")
			status, _ = sqlitePost(t, client, server.URL+asbbinding.IngressExecutePath, freshExecute)
			if status != http.StatusConflict {
				t.Fatalf("fresh proof repeated mutation = %d", status)
			}
			// Explicit mode binding prevents a recovery grant from authorizing an
			// execute call, and a mutation grant from authorizing an outcome read.
			wrongMode := sqliteSignedRequest(t, client, server.URL, now, asbbinding.OperationRecover, recovery, digest, "gateway:1")
			status, _ = sqlitePost(t, client, server.URL+asbbinding.IngressExecutePath, wrongMode)
			if status != http.StatusBadRequest {
				t.Fatalf("recovery through execute = %d", status)
			}
			mutationGrant := sqliteSignedRequest(t, client, server.URL, now, asbbinding.OperationRecover, recovery, tc.digest, "gateway:1")
			status, _ = sqlitePost(t, client, server.URL+asbbinding.IngressRecoverPath, mutationGrant)
			if status != http.StatusForbidden {
				t.Fatalf("mutation grant recovered outcome = %d", status)
			}
			for _, scope := range []struct{ name, actor, participant, digest string }{
				{"other Actor", "gateway:2", "human:alice", tc.digest.String()},
				{"other Human", "gateway:1", "human:bob", tc.digest.String()},
				{"different request", "gateway:1", "human:alice", strings.Repeat("f", 64)},
			} {
				mismatched := recovery
				mismatched.ParticipantID = scope.participant
				mismatched.RequestDigest = scope.digest
				mismatchDigest, _ := asbbinding.RecoveryDigest(mismatched)
				input := sqliteSignedRequest(t, client, server.URL, now, asbbinding.OperationRecover, mismatched, mismatchDigest, scope.actor)
				status, _ := sqlitePost(t, client, server.URL+asbbinding.IngressRecoverPath, input)
				if status != http.StatusForbidden {
					t.Fatalf("%s recovered outcome: %d", scope.name, status)
				}
			}
			denied.Store(true)
			deniedRead := sqliteSignedRequest(t, client, server.URL, now, asbbinding.OperationRecover, recovery, digest, "gateway:1")
			status, _ = sqlitePost(t, client, server.URL+asbbinding.IngressRecoverPath, deniedRead)
			if status != http.StatusForbidden {
				t.Fatalf("current policy denial = %d", status)
			}
			denied.Store(false)
			allowedRead := sqliteSignedRequest(t, client, server.URL, now, asbbinding.OperationRecover, recovery, digest, "gateway:1")
			status, recovered = sqlitePost(t, client, server.URL+asbbinding.IngressRecoverPath, allowedRead)
			if status != http.StatusOK || !bytes.Equal(original, recovered) {
				t.Fatal("failed recovery altered outcome")
			}
		})
	}
	defer func() { _ = store.Close() }()
	assignment, err := store.LoadAssignment(ctx, "assignment:1")
	if err != nil || assignment.Revision != 3 {
		t.Fatalf("assignment after recovery = %+v, %v", assignment, err)
	}
	history, err := store.ListInteractionEvents(ctx, "interaction:1")
	if err != nil || len(history) != 1 {
		t.Fatalf("interaction history after recovery: %d %v", len(history), err)
	}
	outbox, err := store.PollOutbox(ctx, taskcoord.OutboxPoll{ConsumerID: "consumer:1", LeaseID: "lease:1", Limit: 10, LeaseDuration: time.Minute})
	if err != nil || len(outbox) != len(cases) {
		t.Fatalf("outbox after recovery: %d, want %d; %v", len(outbox), len(cases), err)
	}
}

func TestSQLiteHumanIngressExpiryDuringCallbackRollsBackAcceptance(t *testing.T) {
	ctx := context.Background()
	store, err := sqlitestore.Open(filepath.Join(t.TempDir(), "coordination.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	now := time.Now().UTC().Truncate(time.Second)
	if err := store.RegisterParticipant(ctx, taskcoord.Participant{Schema: taskcoord.ParticipantSchemaV1, ParticipantID: "human:alice", Kind: taskcoord.ParticipantHuman, IdentityRef: "urn:identity:alice", Status: taskcoord.ParticipantActive, RegisteredAt: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	var clock atomic.Int64
	clock.Store(now.UnixNano())
	server, client, _ := sqliteIngressServer(t, store, now, false, nil, func(ingress *asbbinding.Ingress) {
		ingress.Now = func() time.Time { return time.Unix(0, clock.Load()) }
		ingress.Policy.AcceptedUntil = func(context.Context, asbbinding.RequestKind, asbbinding.Digest) (time.Time, error) {
			clock.Store(now.Add(2 * time.Minute).UnixNano())
			return now.Add(time.Minute), nil
		}
	})
	request := asbbinding.OfferRequest{ParticipantID: "human:alice", EventID: "event:expired", TaskID: "task:1", AssignmentID: "assignment:1", TargetParticipantID: "human:alice", Role: taskcoord.RoleAssignee, AuthorityDigest: strings.Repeat("a", 64)}
	digest, err := asbbinding.OfferDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	input := sqliteSignedRequest(t, client, server.URL, now, asbbinding.OperationAssignmentOffer, request, digest, "gateway:1")
	status, body := sqlitePost(t, client, server.URL+asbbinding.IngressExecutePath, input)
	if status != http.StatusForbidden {
		t.Fatalf("expired acceptance = %d %s", status, body)
	}
	if _, err := store.LoadAssignment(ctx, request.AssignmentID); !errors.Is(err, taskcoord.ErrNotFound) {
		t.Fatalf("expired mutation survived: %v", err)
	}
	statement, err := clients.VerifySessionBindingJWT(input.SessionBindingJWT, clients.JWTVerifyOptions{ExpectedIssuer: "gateway", ExpectedAudience: "coordination", ValidMethods: []string{"HS256"}, LocalKeys: []clients.LocalKey{{KeyID: "actor", Key: sqliteProofKey}}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	rollback := errors.New("discard test replay check")
	err = store.RunHumanTransaction(ctx, func(tx asbbinding.HumanTransaction) error {
		if _, err := tx.LookupHumanOutcome(ctx, request.EventID); !errors.Is(err, asbbinding.ErrHumanOutcomeNotFound) {
			t.Fatalf("expired outcome survived: %v", err)
		}
		if err := identitypolicy.MarkSessionBindingUsed(tx, statement); err != nil {
			t.Fatalf("expired acceptance consumed replay: %v", err)
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	outbox, err := store.PollOutbox(ctx, taskcoord.OutboxPoll{ConsumerID: "consumer:1", LeaseID: "lease:1", Limit: 10, LeaseDuration: time.Minute})
	if err != nil || len(outbox) != 0 {
		t.Fatalf("expired outbox survived: %d, %v", len(outbox), err)
	}
}

var (
	sqliteGrantKey = []byte("sqlite-integration-manager-test-key")
	sqliteProofKey = []byte("sqlite-integration-gateway-test-key")
)

func sqliteIngressServer(t *testing.T, store taskcoord.Store, now time.Time, drop bool, deny *atomic.Bool, configure ...func(*asbbinding.Ingress)) (*httptest.Server, *http.Client, chan []byte) {
	t.Helper()
	ingress := &asbbinding.Ingress{Store: store, Now: func() time.Time { return now }, Policy: asbbinding.IngressPolicy{
		Grant:          clients.JWTVerifyOptions{ExpectedIssuer: "authority", ExpectedAudience: "coordination", ValidMethods: []string{"HS256"}, LocalKeys: []clients.LocalKey{{KeyID: "manager", Key: sqliteGrantKey}}},
		SessionBinding: clients.JWTVerifyOptions{ExpectedIssuer: "gateway", ExpectedAudience: "coordination", ValidMethods: []string{"HS256"}, LocalKeys: []clients.LocalKey{{KeyID: "actor", Key: sqliteProofKey}}},
		AcceptedUntil: func(_ context.Context, kind asbbinding.RequestKind, _ asbbinding.Digest) (time.Time, error) {
			if deny != nil && deny.Load() && kind == asbbinding.RequestKindOperationRecover {
				return time.Time{}, errors.New("current recovery authorization revoked")
			}
			return time.Time{}, nil
		},
		DelegationVerifier: asbbinding.DelegationDecisionVerifierFunc(func(_ context.Context, parent taskcoord.Assignment, r asbbinding.DelegationRequest, at time.Time) (taskcoord.VerifiedDelegation, error) {
			return taskcoord.VerifiedDelegation{DecisionID: r.DecisionID, ParentAssignmentID: parent.AssignmentID, ChildAssignmentID: r.ChildAssignmentID, FromParticipantID: parent.ParticipantID, ToParticipantID: r.TargetParticipantID, ParentAuthorityDigest: parent.AuthorityDigest, ChildAuthorityDigest: r.AuthorityDigest, PolicyRef: "urn:policy:1", EvidenceRef: "urn:evidence:1", VerifiedAt: at}, nil
		}),
	}}
	for _, apply := range configure {
		apply(ingress)
	}
	roots, serverCert, clientCert := sqliteCertificates(t)
	configured, err := ingress.NewTLSServer("127.0.0.1:0", serverCert, roots)
	if err != nil {
		t.Fatal(err)
	}
	discarded := make(chan []byte, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if drop && r.URL.Path == asbbinding.IngressExecutePath {
			recorder := httptest.NewRecorder()
			configured.Handler.ServeHTTP(recorder, r)
			if recorder.Code == http.StatusOK {
				discarded <- append([]byte(nil), recorder.Body.Bytes()...)
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			for k, v := range recorder.Header() {
				w.Header()[k] = v
			}
			w.WriteHeader(recorder.Code)
			_, _ = w.Write(recorder.Body.Bytes())
			return
		}
		configured.Handler.ServeHTTP(w, r)
	}))
	server.TLS = configured.TLSConfig
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{clientCert}}, ForceAttemptHTTP2: true, MaxConnsPerHost: 1}
	t.Cleanup(transport.CloseIdleConnections)
	return server, &http.Client{Transport: transport}, discarded
}

func sqliteSignedRequest(t *testing.T, client *http.Client, url string, now time.Time, operation string, request any, grantDigest asbbinding.Digest, actor string) asbbinding.ExecuteRequest {
	t.Helper()
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Post(url+asbbinding.IngressChallengePath, "application/json", bytes.NewReader(sqliteJSON(t, asbbinding.ChallengeRequest{Operation: operation, Request: raw})))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("challenge: %d %s", response.StatusCode, body)
	}
	var challenge asbbinding.ChallengeResponse
	if err := json.Unmarshal(body, &challenge); err != nil {
		t.Fatal(err)
	}
	// TLS binding always covers the challenge's actual request. The separate
	// grantDigest argument lets a test sign an incorrect permission scope.
	var boundDigest asbbinding.Digest
	if operation == asbbinding.OperationRecover {
		boundDigest, err = asbbinding.RecoveryDigest(request.(asbbinding.RecoveryRequest))
	} else {
		boundDigest = grantDigest
	}
	if err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*http.Transport)
	binding, err := asbbinding.BindingFromTLS(response.TLS, transport.TLSClientConfig.Certificates[0].Leaf, boundDigest, challenge.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	grant := sqliteJWT(t, "manager", sqliteGrantKey, jwt.MapClaims{"iss": "authority", "sub": actor, "aud": "coordination", "jti": "authorization:" + challenge.ChallengeID, "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(5 * time.Minute).Unix(), "profile_type": clients.TokenTypeIdentityGrant, "profile_version": clients.ProfileVersion, "cnf": map[string]any{"kid": "actor"}, "authorization_details": []string{asbbinding.AuthorizationDetail(grantDigest)}})
	proof := sqliteJWT(t, "actor", sqliteProofKey, jwt.MapClaims{"iss": "gateway", "aud": "coordination", "jti": "proof:" + challenge.ChallengeID, "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Minute).Unix(), "profile_type": clients.TokenTypeSessionBinding, "profile_version": clients.ProfileVersion, "grant_hash": clients.IdentityGrantHash(grant), "leaf_public_key_sha256": binding.LeafPublicKeySHA256, "tls_exporter_sha256": binding.TLSExporterSHA256, "request_context_sha256": binding.RequestContextSHA256, "nonce": challenge.Nonce})
	return asbbinding.ExecuteRequest{ChallengeID: challenge.ChallengeID, Operation: operation, Request: raw, GrantJWT: grant, SessionBindingJWT: proof}
}

func sqliteJWT(t *testing.T, id string, key []byte, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = id
	value, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func sqliteJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func sqlitePost(t *testing.T, client *http.Client, url string, input any) (int, []byte) {
	t.Helper()
	response, err := client.Post(url, "application/json", bytes.NewReader(sqliteJSON(t, input)))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, raw
}

func sqliteCertificates(t *testing.T) (*x509.CertPool, tls.Certificate, tls.Certificate) {
	t.Helper()
	now := time.Now()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ASB integration CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	issue := func(id int64, usage x509.ExtKeyUsage) tls.Certificate {
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(id), Subject: pkix.Name{CommonName: "ASB integration peer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"}}
		der, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: leafKey, Leaf: leaf}
	}
	return roots, issue(2, x509.ExtKeyUsageServerAuth), issue(3, x509.ExtKeyUsageClientAuth)
}
