//go:build linux && awsiam_live

// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package s3product

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege/asbbinding"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege/awsiam"
	"github.com/golang-jwt/jwt/v5"
)

// This opt-in gate uses a real product subprocess and real AWS only for the
// explicitly supplied object. Its private PKI, mandates and journal are local
// qualification fixtures, not an organization's deployed identity authority.
func TestLiveProductReadAndRestore(t *testing.T) {
	if os.Getenv("ASB_AWS_LIVE_CONFIRM") != "read-explicit-fixture" {
		t.Skip("live product gate requires explicit opt-in and fixture")
	}
	binary := os.Getenv("ASB_S3_LIVE_BINARY")
	if !filepath.IsAbs(binary) {
		t.Fatal("absolute product binary path is required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)
	defer cancel()
	fixture, solution, action := loadLiveProductFixture(t, ctx)
	h := newLiveProduct(t, ctx, binary)
	h.config.ProfileFile = h.write(t, "profile.json", fixture.Specification)
	h.config.AWSCLI = fixture.CLIPath
	h.config.WebIdentityTokenFile = fixture.WebIdentityTokenFile
	var initialized lp.SQLiteStatus
	h.admin(t, &initialized, "init-store", "--directory", h.config.StoreDirectory)
	h.configure(t, initialized.Namespace, action, solution.ProblemDigest)
	stop := h.start(t)
	capability := h.authorize(t, solution)
	first := h.execute(t, capability)
	stop()

	// An executable that cannot acquire credentials makes accidental redispatch
	// observable while checking a completed record after a process restart.
	blockedCLI := h.write(t, "disabled-aws", []byte("#!/bin/sh\nexit 91\n"))
	if err := os.Chmod(blockedCLI, 0o700); err != nil {
		t.Fatal("cannot prepare offline recovery check")
	}
	h.config.AWSCLI = blockedCLI
	stop = h.start(t)
	if recovered := h.execute(t, capability); recovered != first {
		t.Fatal("restart did not return the exact retained execution record")
	}
	backupDir := filepath.Join(h.directory, "backups")
	if err := os.Mkdir(backupDir, 0o700); err != nil {
		t.Fatal("cannot prepare private backup directory")
	}
	backupPath := filepath.Join(backupDir, "snapshot.sqlite")
	var backup lp.SQLiteBackup
	h.admin(t, &backup, "backup", "--directory", h.config.StoreDirectory, "--output", backupPath)
	stop() // Fence and reap the old process before opening a restored authority.

	restoredDirectory := filepath.Join(h.directory, "restored")
	var restored lp.SQLiteStatus
	h.admin(t, &restored, "restore", "--input", backupPath, "--sha256", backup.SHA256, "--directory", restoredDirectory)
	if restored.Namespace == initialized.Namespace || restored.Operations != 1 {
		t.Fatal("restore did not rotate the namespace and retain its operation")
	}
	var inspected lp.ExecutionRecord
	h.admin(t, &inspected, "inspect", "--directory", restoredDirectory, "--operation", first.OperationID, "--request-digest", first.RequestDigest)
	if inspected != first {
		t.Fatal("restored journal changed the recorded outcome")
	}
	oldOperation := h.operation
	h.config.StoreDirectory = restoredDirectory
	h.config.AWSCLI = fixture.CLIPath
	h.configure(t, restored.Namespace, action, solution.ProblemDigest)
	stop = h.start(t)
	challenge := h.challenge(t, "execute", oldOperation)
	status, body, _ := h.post(t, "/execute", asbbinding.HTTPExecuteRequest{ChallengeID: challenge.ChallengeID, Operation: oldOperation, Proof: h.proof(t, challenge, oldOperation), Capability: capability})
	var rejection asbbinding.HTTPResponse
	if json.Unmarshal(body, &rejection) != nil || status != http.StatusForbidden || rejection.Error != "authorization_denied" {
		t.Fatal("restored authority did not deny the old operation and mandate")
	}
	newResult := h.execute(t, h.authorize(t, solution))
	if newResult.OperationID == first.OperationID {
		t.Fatal("new authorized read reused an old operation identity")
	}
	var finalStatus lp.SQLiteStatus
	h.admin(t, &finalStatus, "status", "--directory", restoredDirectory)
	if finalStatus.Operations != 2 || finalStatus.Uncertain != 0 || finalStatus.Accepted != 0 {
		t.Fatal("unexpected final journal state")
	}
	stop()
	t.Log("product mTLS/ASB read passed; restart recovered without STS; sealed backup restored; old authority denied; new authorized AWS read passed")
}

type liveProductFixture struct {
	Specification        json.RawMessage  `json:"specification"`
	Resource             string           `json:"resource"`
	DeniedResource       string           `json:"denied_resource"`
	Arguments            awsiam.Arguments `json:"arguments"`
	CLIPath              string           `json:"cli_path"`
	CredentialsFile      string           `json:"credentials_file"`
	WebIdentityTokenFile string           `json:"web_identity_token_file"`
}

func loadLiveProductFixture(t *testing.T, ctx context.Context) (liveProductFixture, lp.Solution, lp.Action) {
	t.Helper()
	raw, err := privateFile(os.Getenv("ASB_AWS_LIVE_FIXTURE"), awsiam.MaxInputBytes)
	if err != nil {
		t.Fatal("private live fixture is required")
	}
	var fixture liveProductFixture
	if decode(raw, &fixture) != nil || fixture.CredentialsFile != "" || !filepath.IsAbs(fixture.WebIdentityTokenFile) {
		t.Fatal("explicit OIDC fixture is required")
	}
	profile, err := awsiam.Compile(fixture.Specification)
	if err != nil {
		t.Fatal("invalid live profile")
	}
	solution, err := lp.Solve(ctx, profile.Problem(), 1<<lp.MaxGrants)
	if err != nil || !slices.Contains(solution.Effective, fixture.Resource) || slices.Contains(solution.Effective, fixture.DeniedResource) {
		t.Fatal("invalid live permission selection")
	}
	if fixture.Arguments.ProfileDigest == "" {
		fixture.Arguments.ProfileDigest = profile.Digest()
	}
	action := lp.Action{Operation: awsiam.Operation, Resource: fixture.Resource, Arguments: liveJSON(t, fixture.Arguments)}
	return fixture, solution, action
}

type liveProduct struct {
	ctx                context.Context
	binary             string
	directory          string
	config             Config
	client             *http.Client
	transport          *http.Transport
	clientTLS          *tls.Config
	clientSPKI         string
	grantKey, actorKey ed25519.PrivateKey
	mandate            lp.Mandate
	operation          asbbinding.Operation
	nonce              uint64
	pid                int
	kill               func()
}

func liveJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal("cannot encode qualification input")
	}
	return raw
}

func (h *liveProduct) write(t *testing.T, name string, raw []byte) string {
	t.Helper()
	path := filepath.Join(h.directory, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal("cannot write private qualification input")
	}
	return path
}

func liveKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("cannot create ephemeral qualification key")
	}
	return key
}

func newLiveProduct(t *testing.T, ctx context.Context, binary string) *liveProduct {
	t.Helper()
	h := &liveProduct{ctx: ctx, binary: binary, directory: t.TempDir(), grantKey: liveKey(t), actorKey: liveKey(t)}
	now := time.Now()
	caKey := liveKey(t)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
	if err != nil {
		t.Fatal("cannot create qualification CA")
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	encodeKey := func(key ed25519.PrivateKey) []byte {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal("cannot encode qualification key")
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	pair := func(serial int64, usage x509.ExtKeyUsage) ([]byte, []byte) {
		key := liveKey(t)
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		der, err := x509.CreateCertificate(rand.Reader, cert, ca, key.Public(), caKey)
		if err != nil {
			t.Fatal("cannot create qualification certificate")
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), encodeKey(key)
	}
	serverPEM, serverKey := pair(2, x509.ExtKeyUsageServerAuth)
	clientPEM, clientKey := pair(3, x509.ExtKeyUsageClientAuth)
	client, err := tls.X509KeyPair(clientPEM, clientKey)
	if err != nil {
		t.Fatal("cannot load qualification client certificate")
	}
	leaf, err := x509.ParseCertificate(client.Certificate[0])
	if err != nil {
		t.Fatal("cannot parse qualification client certificate")
	}
	spki := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	h.clientSPKI = "sha256:" + hex.EncodeToString(spki[:])
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("cannot load qualification CA")
	}
	h.clientTLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "localhost", Certificates: []tls.Certificate{client}}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("cannot select a loopback port")
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal("cannot release qualification port")
	}
	h.config = Config{Schema: ConfigSchema, Listen: address, StoreDirectory: filepath.Join(h.directory, "store"), SigningKeyFile: h.write(t, "signer.pem", encodeKey(liveKey(t))), CertificateFile: h.write(t, "server.pem", serverPEM), TLSKeyFile: h.write(t, "server-key.pem", serverKey), ClientCAFile: h.write(t, "ca.pem", caPEM), Issuer: "live-authority", Audience: "live-s3", GrantKeys: map[string]ed25519.PublicKey{"grant-key": h.grantKey.Public().(ed25519.PublicKey)}, ActorKeys: map[string]ed25519.PublicKey{"actor-key": h.actorKey.Public().(ed25519.PublicKey)}}
	return h
}

func (h *liveProduct) configure(t *testing.T, namespace string, action lp.Action, problemDigest string) {
	t.Helper()
	digest, err := lp.DigestAction(action)
	if err != nil {
		t.Fatal("invalid qualification action")
	}
	h.config.Namespace = namespace
	h.operation = asbbinding.Operation{ID: namespace + "/read", MandateID: namespace + "/mandate", Action: action}
	h.mandate = lp.Mandate{ID: h.operation.MandateID, PolicyRef: "policy:live-s3", ActorID: "agent:live-reader", TaskID: "task:live-read", ActionDigest: digest, ProblemDigest: problemDigest, NotBefore: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(10 * time.Minute).UTC().Truncate(time.Second), MaxTTLSeconds: 300, AllowAutomatic: true}
	h.config.MandatesFile = h.write(t, "mandates.json", liveJSON(t, []lp.Mandate{h.mandate}))
}

func (h *liveProduct) command(args ...string) *exec.Cmd {
	cmd := exec.CommandContext(h.ctx, h.binary, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	cmd.Dir = h.directory
	return cmd
}

func (h *liveProduct) admin(t *testing.T, result any, args ...string) {
	t.Helper()
	raw, err := h.command(args...).Output()
	if err != nil || len(raw) > 1<<20 || json.Unmarshal(raw, result) != nil {
		t.Fatalf("product %s command failed", args[0])
	}
}

func (h *liveProduct) start(t *testing.T) func() {
	t.Helper()
	config := h.write(t, "config.json", liveJSON(t, h.config))
	cmd := h.command("serve", "--config", config)
	if err := cmd.Start(); err != nil {
		t.Fatal("product process did not start")
	}
	h.pid = cmd.Process.Pid
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	stopped := false
	stopProcess := func(force bool) {
		if stopped {
			return
		}
		stopped = true
		if h.transport != nil {
			h.transport.CloseIdleConnections()
		}
		if force {
			_ = cmd.Process.Kill()
		} else {
			_ = cmd.Process.Signal(syscall.SIGTERM)
		}
		select {
		case err := <-done:
			if force {
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
					t.Error("product did not terminate with the expected signal")
				}
			} else if err != nil {
				t.Error("product process did not stop cleanly")
			}
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-done
			t.Error("product process exceeded shutdown deadline")
		}
	}
	stop := func() { stopProcess(false) }
	h.kill = func() { stopProcess(true) }
	t.Cleanup(stop)
	h.transport = &http.Transport{TLSClientConfig: h.clientTLS.Clone(), MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, ForceAttemptHTTP2: false}
	h.client = &http.Client{Transport: h.transport, Timeout: 40 * time.Second}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", h.config.Listen, 100*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return stop
		}
		select {
		case <-done:
			stopped = true
			t.Fatal("product process exited before becoming ready")
		case <-h.ctx.Done():
			t.Fatal("qualification deadline reached")
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatal("product listener did not become ready")
	return stop
}

func (h *liveProduct) post(t *testing.T, path string, input any) (int, []byte, *tls.ConnectionState) {
	t.Helper()
	request, err := http.NewRequestWithContext(h.ctx, http.MethodPost, "https://"+h.config.Listen+path, bytes.NewReader(liveJSON(t, input)))
	if err != nil {
		t.Fatal("cannot prepare qualification request")
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := h.client.Do(request)
	if err != nil {
		t.Fatalf("product %s request failed", path)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		t.Fatal("invalid product response length")
	}
	return response.StatusCode, body, response.TLS
}

func (h *liveProduct) challenge(t *testing.T, mode string, op asbbinding.Operation) asbbinding.HTTPChallenge {
	t.Helper()
	status, body, state := h.post(t, "/challenge", asbbinding.HTTPChallengeRequest{Mode: mode, Operation: op})
	var challenge asbbinding.HTTPChallenge
	if status != http.StatusOK || json.Unmarshal(body, &challenge) != nil || state == nil || state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 {
		t.Fatal("verified product mTLS challenge failed")
	}
	exported, err := state.ExportKeyingMaterial(asbbinding.HTTPExporterLabel, []byte(challenge.Binding.BindingContextSHA256), 32)
	if err != nil {
		t.Fatal("cannot verify product channel binding")
	}
	digest := sha256.Sum256(exported)
	if challenge.Binding.TLSExporterSHA256 != "sha256:"+hex.EncodeToString(digest[:]) || challenge.Binding.AcceptedEndpointSPKISHA256 != h.clientSPKI {
		t.Fatal("product challenge does not bind the actual TLS connection")
	}
	return challenge
}

func (h *liveProduct) proof(t *testing.T, c asbbinding.HTTPChallenge, op asbbinding.Operation) asbbinding.Proof {
	t.Helper()
	h.nonce++
	digest, err := asbbinding.ContextDigest(c.Mode, op)
	if err != nil {
		t.Fatal("cannot bind qualification operation")
	}
	sign := func(claims jwt.MapClaims, kid, typ string, key ed25519.PrivateKey) string {
		token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
		token.Header["kid"], token.Header["typ"] = kid, typ
		raw, err := token.SignedString(key)
		if err != nil {
			t.Fatal("cannot sign qualification proof")
		}
		return raw
	}
	grant := sign(jwt.MapClaims{
		"iss": h.config.Issuer, "sub": h.mandate.ActorID, "aud": h.config.Audience, "jti": fmt.Sprintf("live-grant-%d", h.nonce),
		"iat": c.Binding.IssuedAt.Unix(), "exp": c.ExpiresAt.Unix(), clients.ClaimTokenType: clients.TokenTypeIdentityGrant, clients.ClaimProfileVersion: clients.ProfileVersion,
		"cnf": map[string]any{"kid": "actor-key"}, "agent": h.mandate.ActorID, "task_id": h.mandate.TaskID,
		"target_resource": op.Action.Resource, "target_operation": op.Action.Operation, "capability_ref": h.mandate.PolicyRef, "scope": op.Action.Operation, "resource": op.Action.Resource,
		"authorization_details": []string{asbbinding.AuthorizationDetail(c.Mode, op, digest)},
	}, "grant-key", clients.IdentityGrantJWTTypeV2, h.grantKey)
	b := c.Binding
	proof := sign(jwt.MapClaims{
		"iss": h.mandate.ActorID, "aud": h.config.Audience, "jti": fmt.Sprintf("live-proof-%d", h.nonce), "iat": b.IssuedAt.Unix(), "exp": b.ExpiresAt.Unix(),
		clients.ClaimTokenType: clients.TokenTypeSessionBinding, clients.ClaimProfileVersion: clients.ProfileVersionV2, "grant_hash": clients.IdentityGrantHash(grant),
		"endpoint_role": b.EndpointRole, "interaction_type": b.InteractionType, "accepted_endpoint_spki_sha256": b.AcceptedEndpointSPKISHA256, "tls_exporter_sha256": b.TLSExporterSHA256,
		"binding_context_sha256": b.BindingContextSHA256, "verifier_nonce": b.VerifierNonce,
	}, "actor-key", clients.SessionBindingJWTTypeV2, h.actorKey)
	return asbbinding.Proof{GrantJWT: grant, SessionBindingJWT: proof}
}

func (h *liveProduct) authorize(t *testing.T, solution lp.Solution) lp.Capability {
	t.Helper()
	c := h.challenge(t, "authorize", h.operation)
	status, body, _ := h.post(t, "/authorize", asbbinding.HTTPAuthorizeRequest{ChallengeID: c.ChallengeID, Operation: h.operation, Proof: h.proof(t, c, h.operation), Candidate: solution})
	var response asbbinding.HTTPResponse
	if status != http.StatusOK || json.Unmarshal(body, &response) != nil || response.Capability == nil {
		t.Fatal("product authorization failed")
	}
	return *response.Capability
}

func (h *liveProduct) execute(t *testing.T, capability lp.Capability) lp.ExecutionRecord {
	t.Helper()
	c := h.challenge(t, "execute", h.operation)
	status, body, _ := h.post(t, "/execute", asbbinding.HTTPExecuteRequest{ChallengeID: c.ChallengeID, Operation: h.operation, Proof: h.proof(t, c, h.operation), Capability: capability})
	var response asbbinding.HTTPResponse
	if status != http.StatusOK || json.Unmarshal(body, &response) != nil || response.Execution == nil || response.Execution.State != lp.ExecutionSucceeded || response.Execution.EvidenceDigest == "" {
		t.Fatalf("product execution failed with HTTP %d", status)
	}
	return *response.Execution
}
