// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package peer

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
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/thinksyncs/agents-secure-binding/pkg/agtp/discovery"
	"github.com/thinksyncs/agents-secure-binding/pkg/clients"
	"github.com/thinksyncs/agents-secure-binding/pkg/production"
)

const (
	testManagerIssuer = "https://manager.discovery.test"
	testManagerKeyID  = "manager-ed25519-1"
)

type nodeMaterial struct {
	id      string
	issuer  string
	keyID   string
	public  ed25519.PublicKey
	private ed25519.PrivateKey
	tlsCert tls.Certificate
	leaf    *x509.Certificate
}

type testCluster struct {
	t              *testing.T
	directory      string
	managerPublic  ed25519.PublicKey
	managerPrivate ed25519.PrivateKey
	ca             *x509.Certificate
	caPrivate      ed25519.PrivateKey
	roots          *x509.CertPool
	materials      []nodeMaterial
	nodes          []*Node
	infos          []discovery.NodeInfo
	interval       time.Duration
}

func TestThreeNodeProductGatePartitionRestartAndNoResurrection(t *testing.T) {
	cluster := newTestCluster(t, time.Hour)
	defer cluster.stop()

	expires := time.Now().UTC().Add(24 * time.Hour)
	if changed, err := cluster.nodes[0].Register(discovery.NameBinding{
		Name: "agent-000.example", AgentID: "agent-000", Endpoint: "https://127.0.0.1:9443",
		Capabilities: []string{"generate"}, Version: 1, ExpiresAt: expires,
		Visibility: discovery.Visibility{Mode: discovery.VisibilityPublic},
	}); err != nil || !changed {
		t.Fatalf("ANS register = %v, %v", changed, err)
	}
	for i := 1; i < DefaultMaxRecords; i++ {
		record := discovery.Record{
			AgentID:      fmt.Sprintf("agent-%03d", i),
			Capabilities: []string{"generate"},
			Visibility:   discovery.Visibility{Mode: discovery.VisibilityPublic},
			Version:      1,
			ExpiresAt:    expires,
		}
		if changed, err := cluster.nodes[0].Announce(record); err != nil || !changed {
			t.Fatalf("announce %d = %v, %v", i, changed, err)
		}
	}
	if _, err := cluster.nodes[0].Announce(discovery.Record{
		AgentID: "agent-100", Capabilities: []string{"generate"}, Version: 1, ExpiresAt: expires,
	}); err != discovery.ErrLimitExceeded {
		t.Fatalf("101st record error = %v", err)
	}

	mustGossip(t, cluster.nodes[0])
	mustGossip(t, cluster.nodes[1])
	assertMatchCount(t, cluster.nodes[2], "generate", 100)
	if binding, ok := cluster.nodes[2].Resolve("agent-000.example"); !ok || binding.AgentID != "agent-000" {
		t.Fatalf("ANS did not converge: %+v, %v", binding, ok)
	}

	located, err := cluster.nodes[0].Locate(context.Background(), cluster.nodes[2].Info().ID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !containsNode(located, cluster.nodes[2].Info().ID) {
		t.Fatalf("multi-peer lookup did not find node C: %+v", located)
	}

	cluster.partition(0, true)
	if changed, err := cluster.nodes[0].Deregister("agent-000.example", 2); err != nil || !changed {
		t.Fatalf("withdraw = %v, %v", changed, err)
	}
	assertMatchCount(t, cluster.nodes[1], "generate", 100)
	assertMatchCount(t, cluster.nodes[2], "generate", 100)

	cluster.restartAll()
	mustGossip(t, cluster.nodes[0])
	mustGossip(t, cluster.nodes[1])
	for i, node := range cluster.nodes {
		assertMatchCount(t, node, "generate", 99)
		if response, err := node.Discover(context.Background(), discovery.Query{Capability: "generate", Limit: 100}, discovery.Requester{}); err != nil || hasAgent(response, "agent-000") {
			t.Fatalf("node %d resurrected withdrawn agent: %+v, %v", i, response, err)
		}
		if _, ok := node.Resolve("agent-000.example"); ok {
			t.Fatalf("node %d resolved deregistered ANS name", i)
		}
	}
	if changed, err := cluster.nodes[2].Announce(discovery.Record{
		AgentID: "agent-000", Capabilities: []string{"generate"}, Version: 1, ExpiresAt: expires,
	}); err != nil || changed {
		t.Fatalf("stale re-announce = %v, %v", changed, err)
	}

	stopped := cluster.nodes[1]
	cluster.stopNode(1)
	if _, err := stopped.Announce(discovery.Record{AgentID: "after-stop", Version: 1, ExpiresAt: expires}); err == nil {
		t.Fatal("stopped node accepted a mutation")
	}
	if changed, err := cluster.nodes[0].Announce(discovery.Record{
		AgentID: "agent-001", Capabilities: []string{"analyze"}, Version: 3, ExpiresAt: expires,
	}); err != nil || !changed {
		t.Fatalf("rolling update = %v, %v", changed, err)
	}
	cluster.restartNode(1)
	mustGossip(t, cluster.nodes[0])
	assertMatchCount(t, cluster.nodes[1], "analyze", 1)

	metrics := cluster.readMetrics(0)
	if !strings.Contains(metrics, "agtp_gossip_success_total") || !strings.Contains(metrics, "agtp_presence_records 99") {
		t.Fatalf("metrics = %s", metrics)
	}
	for i := range cluster.nodes {
		info, err := os.Stat(cluster.auditPath(i))
		if err != nil || info.Size() == 0 {
			t.Fatalf("node %d audit log = %v, %v", i, info, err)
		}
	}
}

func TestPeriodicGossipConvergesWithoutStateGrowth(t *testing.T) {
	cluster := newTestCluster(t, 200*time.Millisecond)
	defer cluster.stop()
	if _, err := cluster.nodes[0].Announce(discovery.Record{
		AgentID: "periodic-agent", Capabilities: []string{"audit"}, Version: 1, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	eventually(t, 8*time.Second, func() bool {
		response, err := cluster.nodes[2].Discover(context.Background(), discovery.Query{Capability: "audit", Limit: 10}, discovery.Requester{})
		return err == nil && response.TotalMatches == 1
	})
	if err := cluster.nodes[2].persist(); err != nil {
		t.Fatal(err)
	}
	before, found, err := cluster.nodes[2].state.Load()
	if err != nil || !found {
		t.Fatalf("load state before stable gossip = %v, %v", found, err)
	}
	for i := 0; i < 20; i++ {
		_ = cluster.nodes[0].GossipOnce(context.Background())
		_ = cluster.nodes[1].GossipOnce(context.Background())
	}
	records, tombstones, peers := cluster.nodes[2].Counts()
	if records != 1 || tombstones != 0 || peers > DefaultMaxPeers {
		t.Fatalf("bounded state = records:%d tombstones:%d peers:%d", records, tombstones, peers)
	}
	after, found, err := cluster.nodes[2].state.Load()
	if err != nil || !found {
		t.Fatalf("load state after stable gossip = %v, %v", found, err)
	}
	before.SavedAt = time.Time{}
	after.SavedAt = time.Time{}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("stable gossip changed durable state: before=%+v after=%+v", before, after)
	}
}

func TestPeerServiceRejectsUnknownTamperedReplayFakeAndHugeDelta(t *testing.T) {
	cluster := newTestCluster(t, time.Hour)
	defer cluster.stop()

	unknownCertificate, _, _ := cluster.issueTLSCertificate(t, 99)
	unknownClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{unknownCertificate}, RootCAs: cluster.roots, ServerName: "localhost", MinVersion: tls.VersionTLS13,
	}}}
	request, _ := http.NewRequest(http.MethodPost, "https://"+cluster.nodes[0].Info().Endpoint+NoncePath, http.NoBody)
	response, err := unknownClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown peer status = %d", response.StatusCode)
	}
	authorizedClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{cluster.materials[0].tlsCert}, RootCAs: cluster.roots, ServerName: "localhost", MinVersion: tls.VersionTLS13,
	}}}
	request, err = http.NewRequest(http.MethodPost, "https://"+cluster.nodes[1].Info().Endpoint+NoncePath, strings.NewReader("not-empty"))
	if err != nil {
		t.Fatal(err)
	}
	response, err = authorizedClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("nonce body status = %d", response.StatusCode)
	}

	fake := ReplicateRequest{Protocol: ProtocolVersion, Sender: discovery.NodeInfo{ID: testNodeID("ff"), Endpoint: cluster.nodes[0].Info().Endpoint}}
	fakeBody, err := json.Marshal(fake)
	if err != nil {
		t.Fatal(err)
	}
	var replicateResponse ReplicateResponse
	if err := cluster.nodes[0].config.Client.do(context.Background(), cluster.nodes[1].Info(), ActionReplicate, fakeBody, &replicateResponse); err == nil || !strings.Contains(err.Error(), "status 400") {
		t.Fatalf("fake Node-ID error = %v", err)
	}
	client := cluster.nodes[0].config.Client
	remote := client.Remotes[cluster.nodes[1].Info().ID]
	originalFingerprint := remote.ServerCertificateSHA256
	remote.ServerCertificateSHA256 = strings.Repeat("0", 64)
	client.Remotes[cluster.nodes[1].Info().ID] = remote
	validForPin := ReplicateRequest{Protocol: ProtocolVersion, Sender: cluster.nodes[0].Info()}
	if _, err := client.Replicate(context.Background(), cluster.nodes[1].Info(), validForPin); err != ErrUnauthorized {
		t.Fatalf("wrong server pin error = %v", err)
	}
	remote.ServerCertificateSHA256 = originalFingerprint
	client.Remotes[cluster.nodes[1].Info().ID] = remote

	valid := ReplicateRequest{Protocol: ProtocolVersion, Sender: cluster.nodes[0].Info(), Digest: discovery.Digest{}, NameDigest: map[string]uint64{}}
	validBody, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), validBody...)
	tampered[len(tampered)-1] = ' '
	status := cluster.sendPrepared(0, 1, ActionReplicate, validBody, tampered, false)
	if status != http.StatusUnauthorized {
		t.Fatalf("tampered status = %d", status)
	}

	status = cluster.sendPrepared(0, 1, ActionReplicate, validBody, validBody, true)
	if status != http.StatusUnauthorized {
		t.Fatalf("replay status = %d", status)
	}

	huge := ReplicateRequest{Protocol: ProtocolVersion, Sender: cluster.nodes[0].Info()}
	for i := 0; i < DefaultMaxRecords+DefaultMaxTombstones+1; i++ {
		huge.Delta.Tombstones = append(huge.Delta.Tombstones, discovery.Tombstone{
			AgentID: fmt.Sprintf("oversized-%03d", i), Version: 1,
		})
	}
	hugeBody, err := json.Marshal(huge)
	if err != nil {
		t.Fatal(err)
	}
	if err := cluster.nodes[0].config.Client.do(context.Background(), cluster.nodes[1].Info(), ActionReplicate, hugeBody, &replicateResponse); err == nil || !strings.Contains(err.Error(), "status 413") {
		t.Fatalf("oversized delta error = %v", err)
	}
	rawOversized := bytes.Repeat([]byte{'x'}, DefaultMaxRequestBytes+1)
	if err := cluster.nodes[0].config.Client.do(context.Background(), cluster.nodes[1].Info(), ActionReplicate, rawOversized, &replicateResponse); err == nil || !strings.Contains(err.Error(), "status 413") {
		t.Fatalf("oversized request error = %v", err)
	}
}

func TestPeerServiceSoak(t *testing.T) {
	if os.Getenv("ASB_DISCOVERY_SOAK") != "1" {
		t.Skip("set ASB_DISCOVERY_SOAK=1 to run the bounded gossip soak")
	}
	duration := 30 * time.Second
	if configured := os.Getenv("ASB_DISCOVERY_SOAK_DURATION"); configured != "" {
		parsed, err := time.ParseDuration(configured)
		if err != nil || parsed <= 0 {
			t.Fatalf("invalid ASB_DISCOVERY_SOAK_DURATION %q", configured)
		}
		duration = parsed
	}
	cluster := newTestCluster(t, time.Hour)
	defer cluster.stop()
	for i := 0; i < DefaultMaxRecords; i++ {
		if _, err := cluster.nodes[0].Announce(discovery.Record{
			AgentID: fmt.Sprintf("soak-agent-%03d", i), Capabilities: []string{"audit"}, Version: 1,
			ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		for _, node := range cluster.nodes {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = node.GossipOnce(ctx)
			cancel()
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, node := range cluster.nodes {
		records, tombstones, peers := node.Counts()
		if records != DefaultMaxRecords || tombstones != 0 || peers > DefaultMaxPeers {
			t.Fatalf("soak state grew outside bounds: records=%d tombstones=%d peers=%d", records, tombstones, peers)
		}
	}
}

func newTestCluster(t *testing.T, interval time.Duration) *testCluster {
	t.Helper()
	managerPublic, managerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca, caPrivate := issueTestCA(t)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	cluster := &testCluster{
		t: t, directory: t.TempDir(), managerPublic: managerPublic, managerPrivate: managerPrivate,
		ca: ca, caPrivate: caPrivate, roots: roots, interval: interval,
	}
	for i, prefix := range []string{"01", "40", "fe"} {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tlsCertificate, leaf, _ := cluster.issueTLSCertificate(t, i+1)
		cluster.materials = append(cluster.materials, nodeMaterial{
			id: testNodeID(prefix), issuer: fmt.Sprintf("https://peer-%d.discovery.test", i), keyID: fmt.Sprintf("peer-ed25519-%d", i),
			public: public, private: private, tlsCert: tlsCertificate, leaf: leaf,
		})
		cluster.infos = append(cluster.infos, discovery.NodeInfo{ID: testNodeID(prefix), Endpoint: "127.0.0.1:0"})
	}
	cluster.nodes = make([]*Node, 3)
	directories := make([]*PeerDirectory, 3)
	clientsByNode := make([]*Client, 3)
	replays := make([]*FileReplayCache, 3)
	for i := range cluster.nodes {
		directories[i] = NewPeerDirectory()
		clientsByNode[i] = cluster.newClient(i)
		replays[i], err = NewFileReplayCache(cluster.replayPath(i), nil)
		if err != nil {
			t.Fatal(err)
		}
		node, err := NewNode(cluster.nodeConfig(i, cluster.infos[i], directories[i], clientsByNode[i]))
		if err != nil {
			t.Fatal(err)
		}
		cluster.nodes[i] = node
		if err := node.Start(); err != nil {
			t.Fatal(err)
		}
		cluster.infos[i] = node.Info()
	}
	for i := range cluster.nodes {
		cluster.configureTrust(i, directories[i], clientsByNode[i], replays[i])
	}
	cluster.addLineRoutes()
	return cluster
}

func (c *testCluster) nodeConfig(index int, info discovery.NodeInfo, directory *PeerDirectory, client *Client) Config {
	return Config{
		Info: info, ListenAddress: info.Endpoint,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{c.materials[index].tlsCert}, ClientCAs: c.roots, MinVersion: tls.VersionTLS13,
		},
		Directory: directory, Client: client,
		StatePath: c.statePath(index), AuditPath: c.auditPath(index), AuditMaxBytes: 64 << 10,
		GossipInterval: c.interval, RequestTimeout: 5 * time.Second,
		ErrorLog: log.New(io.Discard, "", 0),
	}
}

func (c *testCluster) newClient(index int) *Client {
	material := c.materials[index]
	return &Client{
		AgentID: material.id, Issuer: material.issuer, KeyID: material.keyID, PrivateKey: material.private,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{material.tlsCert}, RootCAs: c.roots, MinVersion: tls.VersionTLS13,
		},
		Remotes: make(map[string]RemoteAuthorization), Timeout: 5 * time.Second,
	}
}

func (c *testCluster) configureTrust(receiver int, directory *PeerDirectory, client *Client, replay *FileReplayCache) {
	for sender := range c.materials {
		if sender == receiver {
			continue
		}
		profile := c.peerProfile(receiver, sender, replay)
		if err := directory.Add(c.materials[sender].leaf, PeerIdentity{Node: c.infos[sender], Profile: profile}); err != nil {
			c.t.Fatal(err)
		}
	}
	for remote := range c.materials {
		if remote == receiver {
			continue
		}
		client.Remotes[c.infos[remote].ID] = RemoteAuthorization{
			Audience: c.audience(remote), ServerName: "localhost", ServerCertificateSHA256: certificateKey(c.materials[remote].leaf),
			Grants: map[Action]string{
				ActionReplicate: c.issueGrant(receiver, remote, ActionReplicate),
				ActionFindNode:  c.issueGrant(receiver, remote, ActionFindNode),
			},
		}
	}
}

func (c *testCluster) peerProfile(receiver, sender int, replay *FileReplayCache) production.SoftwareOnlyProfile {
	return production.SoftwareOnlyProfile{
		GrantAuthority: production.AuthorityPolicy{
			ExpectedIssuer: testManagerIssuer, ExpectedAudience: c.audience(receiver), ValidMethods: []string{"EdDSA"},
			TrustSource:      production.StaticTrustSource{Trust: production.TrustSnapshot{Keys: []clients.LocalKey{{KeyID: testManagerKeyID, Key: c.managerPublic}}}},
			MaxTokenLifetime: time.Hour,
		},
		BindingAuthority: production.AuthorityPolicy{
			ExpectedIssuer: c.materials[sender].issuer, ExpectedAudience: c.audience(receiver), ValidMethods: []string{"EdDSA"},
			TrustSource:      production.StaticTrustSource{Trust: production.TrustSnapshot{Keys: []clients.LocalKey{{KeyID: c.materials[sender].keyID, Key: c.materials[sender].public}}}},
			MaxTokenLifetime: 5 * time.Minute,
		},
		ReplayCache: replay,
	}
}

func (c *testCluster) issueGrant(sender, receiver int, action Action) string {
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss": testManagerIssuer, "sub": c.materials[sender].id, "aud": c.audience(receiver),
		"jti": fmt.Sprintf("grant-%d-%d-%s", sender, receiver, action), "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(30 * time.Minute).Unix(),
		"profile_type": clients.TokenTypeIdentityGrant, "profile_version": clients.ProfileVersion,
		"cnf":     map[string]string{"kid": c.materials[sender].keyID},
		"service": "agtp-discovery-peer", "agent": c.materials[sender].id,
		"capability_ref": capabilityReference(action), "ontology_id": "agtp:peer-action:v1",
		"scopes": []string{actionScope(action)}, "resources": []string{nodeResource(c.materials[receiver].id)},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = testManagerKeyID
	value, err := token.SignedString(c.managerPrivate)
	if err != nil {
		c.t.Fatal(err)
	}
	return value
}

func (c *testCluster) addLineRoutes() {
	for _, edge := range [][2]int{{0, 1}, {1, 0}, {1, 2}, {2, 1}} {
		if err := c.nodes[edge[0]].AddPeer(c.nodes[edge[1]].Info()); err != nil {
			c.t.Fatal(err)
		}
	}
}

func (c *testCluster) restartAll() {
	c.stopCurrent()
	for i := range c.nodes {
		c.nodes[i] = c.buildRestartedNode(i)
	}
}

func (c *testCluster) restartNode(index int) { c.nodes[index] = c.buildRestartedNode(index) }

func (c *testCluster) buildRestartedNode(index int) *Node {
	replay, err := NewFileReplayCache(c.replayPath(index), nil)
	if err != nil {
		c.t.Fatal(err)
	}
	directory := NewPeerDirectory()
	client := c.newClient(index)
	c.configureTrust(index, directory, client, replay)
	node, err := NewNode(c.nodeConfig(index, c.infos[index], directory, client))
	if err != nil {
		c.t.Fatal(err)
	}
	if err := node.Start(); err != nil {
		c.t.Fatal(err)
	}
	c.infos[index] = node.Info()
	return node
}

func (c *testCluster) stopNode(index int) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.nodes[index].Stop(ctx); err != nil {
		c.t.Fatal(err)
	}
}

func (c *testCluster) stopCurrent() {
	for i := range c.nodes {
		if c.nodes[i] != nil {
			c.stopNode(i)
		}
	}
}

func (c *testCluster) stop() {
	for _, node := range c.nodes {
		if node == nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = node.Stop(ctx)
		cancel()
	}
}

func (c *testCluster) partition(index int, blocked bool) {
	for other := range c.nodes {
		if other == index {
			continue
		}
		c.nodes[index].SetPeerBlocked(c.nodes[other].Info().ID, blocked)
		c.nodes[other].SetPeerBlocked(c.nodes[index].Info().ID, blocked)
	}
}

func (c *testCluster) readMetrics(index int) string {
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{c.materials[index].tlsCert}, RootCAs: c.roots, ServerName: "localhost", MinVersion: tls.VersionTLS13,
	}}}
	response, err := client.Get("https://" + c.nodes[index].Info().Endpoint + MetricsPath)
	if err != nil {
		c.t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		c.t.Fatal(err)
	}
	return string(body)
}

func (c *testCluster) sendPrepared(sender, receiver int, action Action, signedBody, sentBody []byte, replay bool) int {
	client := c.nodes[sender].config.Client
	peerInfo := c.nodes[receiver].Info()
	authorization := client.Remotes[peerInfo.ID]
	config := client.TLSConfig.Clone()
	config.ServerName = authorization.ServerName
	connection, err := tls.Dial("tcp", peerInfo.Endpoint, config)
	if err != nil {
		c.t.Fatal(err)
	}
	defer connection.Close()
	reader := bufio.NewReader(connection)
	nonce, err := requestNonce(context.Background(), connection, reader, peerInfo.Endpoint, client.maxResponseBytes())
	if err != nil {
		c.t.Fatal(err)
	}
	state := connection.ConnectionState()
	leaf, _ := clientLeaf(config)
	actionContext, _ := canonicalActionContext(action, client.AgentID, peerInfo.ID, signedBody)
	binding, err := production.SoftwareBindingFromTLS(&state, leaf, actionContext, nonce)
	if err != nil {
		c.t.Fatal(err)
	}
	bindingJWT, err := client.signBinding(authorization, authorization.Grants[action], binding)
	if err != nil {
		c.t.Fatal(err)
	}
	path, _ := actionPath(action)
	send := func() int {
		request, _ := http.NewRequest(http.MethodPost, "https://"+peerInfo.Endpoint+path, bytes.NewReader(sentBody))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set(IdentityGrantHeader, authorization.Grants[action])
		request.Header.Set(SessionBindingHeader, bindingJWT)
		request.Header.Set(VerifierNonceHeader, nonce)
		_, status, err := exchangeHTTP(connection, reader, request, client.maxResponseBytes())
		if err != nil {
			c.t.Fatal(err)
		}
		return status
	}
	first := send()
	if replay {
		if first != http.StatusOK {
			c.t.Fatalf("first replay request status = %d", first)
		}
		return send()
	}
	return first
}

func (c *testCluster) issueTLSCertificate(t *testing.T, serial int) (tls.Certificate, *x509.Certificate, ed25519.PrivateKey) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(int64(serial + 100)), Subject: pkix.Name{CommonName: fmt.Sprintf("node-%d", serial)},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, c.ca, public, c.caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, c.ca.Raw}, PrivateKey: private, Leaf: leaf}, leaf, private
}

func issueTestCA(t *testing.T) (*x509.Certificate, ed25519.PrivateKey) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "discovery-test-ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, private
}

func (c *testCluster) audience(index int) string { return "https://" + c.materials[index].id + "/peer" }

func (c *testCluster) statePath(index int) string {
	return filepath.Join(c.directory, fmt.Sprintf("node-%d", index), "state.json")
}

func (c *testCluster) replayPath(index int) string {
	return filepath.Join(c.directory, fmt.Sprintf("node-%d", index), "replay.json")
}

func (c *testCluster) auditPath(index int) string {
	return filepath.Join(c.directory, fmt.Sprintf("node-%d", index), "audit.jsonl")
}

func mustGossip(t *testing.T, node *Node) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := node.GossipOnce(ctx); err != nil {
		t.Fatal(err)
	}
}

func assertMatchCount(t *testing.T, node *Node, capability string, want int) {
	t.Helper()
	response, err := node.Discover(context.Background(), discovery.Query{Capability: capability, Limit: 100}, discovery.Requester{})
	if err != nil {
		t.Fatal(err)
	}
	if response.TotalMatches != want {
		t.Fatalf("node %s matches = %d, want %d", node.Info().ID[:2], response.TotalMatches, want)
	}
}

func eventually(t *testing.T, timeout time.Duration, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("condition did not converge before timeout")
}

func hasAgent(response discovery.Response, agentID string) bool {
	for _, match := range response.Results {
		if match.AgentID == agentID {
			return true
		}
	}
	return false
}

func containsNode(nodes []discovery.NodeInfo, nodeID string) bool {
	for _, node := range nodes {
		if node.ID == nodeID {
			return true
		}
	}
	return false
}
