// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	agtpdiscover "github.com/ToppyMicroServices/agents-secure-binding/v2/examples/agtp-discover-consumer"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/agtp/discovery"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/production"
	"github.com/golang-jwt/jwt/v5"
)

type searchTestNonce struct {
	mu    sync.Mutex
	value string
}

func (n *searchTestNonce) ExpectedNonce(context.Context, agtpdiscover.Query) (string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.value, nil
}

func (n *searchTestNonce) issue(t *testing.T) string {
	t.Helper()
	value, err := randomID()
	if err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.value = value
	return value
}

func TestGossipFeedsASBAuthenticatedAgentSearch(t *testing.T) {
	cluster := newTestCluster(t, time.Hour)
	defer cluster.stop()

	// Replace the empty stores before any replication or search traffic. The
	// clock controls Presence leases only; TLS and ASB retain their real clock.
	now := time.Now().UTC()
	var clockMu sync.Mutex
	clock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}
	for _, node := range cluster.nodes {
		node.presence = discovery.NewPresenceStoreWithOptions(discovery.PresenceOptions{
			TombstoneRetention: node.config.TombstoneRetention,
			MaxRecords:         node.config.MaxRecords,
			MaxTombstones:      node.config.MaxTombstones,
			Now:                clock,
		})
		node.names = discovery.NewNameService(node.presence, clock)
	}

	requester := cluster.materials[0].id
	for _, record := range []discovery.Record{
		{AgentID: "public-agent", Visibility: discovery.Visibility{Mode: discovery.VisibilityPublic}},
		{AgentID: "allowed-agent", Visibility: discovery.Visibility{Mode: discovery.VisibilityExplicitOnly, AllowedAgents: []string{requester}}},
		{AgentID: "other-agent", Visibility: discovery.Visibility{Mode: discovery.VisibilityExplicitOnly, AllowedAgents: []string{cluster.materials[1].id}}},
		{AgentID: "invisible-agent", Visibility: discovery.Visibility{Mode: discovery.VisibilityInvisible}},
		{AgentID: "expiring-agent", Visibility: discovery.Visibility{Mode: discovery.VisibilityPublic}, ExpiresAt: now.Add(time.Minute)},
	} {
		record.Capabilities = []string{"generate"}
		record.Version = 1
		if record.ExpiresAt.IsZero() {
			record.ExpiresAt = now.Add(time.Hour)
		}
		if changed, err := cluster.nodes[0].Announce(record); err != nil || !changed {
			t.Fatalf("announce %s = %v, %v", record.AgentID, changed, err)
		}
	}

	const audience = "https://search.discovery.test/v1/discover"
	nonces := &searchTestNonce{}
	profile := cluster.peerProfile(2, 0, nil)
	profile.GrantAuthority.ExpectedAudience = audience
	profile.BindingAuthority.ExpectedAudience = audience
	profile.ReplayCache = identitypolicy.NewMemoryReplayCache()
	server := httptest.NewUnstartedServer(agtpdiscover.Application{
		Profile: profile, Nonces: nonces, Catalog: cluster.nodes[2], ExpectedAgent: requester,
		AuditFailure: func(_ context.Context, err error) { t.Logf("search authentication: %v", err) },
	})
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{cluster.materials[2].tlsCert},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: cluster.roots, MinVersion: tls.VersionTLS13,
	}
	server.StartTLS()
	defer server.Close()

	query := discovery.Query{Capability: "generate", Limit: 10}
	search := func(signedQuery *discovery.Query) (int, []byte) {
		t.Helper()
		return cluster.searchHTTP(t, server, audience, nonces.issue(t), query, signedQuery)
	}
	assertSearch := func(want ...string) {
		t.Helper()
		status, body := search(&query)
		if status != http.StatusOK {
			t.Fatalf("search status = %d, body = %s", status, body)
		}
		var response discovery.Response
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, match := range response.Results {
			ids = append(ids, match.AgentID)
		}
		if response.TotalMatches != len(want) || response.Returned != len(want) || !reflect.DeepEqual(ids, want) {
			t.Fatalf("search = %+v, want agents %v", response, want)
		}
	}

	assertSearch() // Node C has no records before the actual gossip exchange.
	mustGossip(t, cluster.nodes[0])
	mustGossip(t, cluster.nodes[1])
	assertSearch("allowed-agent", "expiring-agent", "public-agent")
	if status, _ := search(nil); status != http.StatusUnauthorized {
		t.Fatalf("search without ASB proofs status = %d", status)
	}
	otherQuery := discovery.Query{Capability: "analyze", Limit: 10}
	if status, _ := search(&otherQuery); status != http.StatusUnauthorized {
		t.Fatalf("search with a different bound query status = %d", status)
	}

	if changed, err := cluster.nodes[0].Withdraw("public-agent", 2); err != nil || !changed {
		t.Fatalf("withdraw = %v, %v", changed, err)
	}
	mustGossip(t, cluster.nodes[0])
	mustGossip(t, cluster.nodes[1])
	assertSearch("allowed-agent", "expiring-agent")

	clockMu.Lock()
	now = now.Add(2 * time.Minute)
	clockMu.Unlock()
	assertSearch("allowed-agent") // Expiry is enforced locally without another gossip round.
}

func (c *testCluster) searchHTTP(t *testing.T, server *httptest.Server, audience, nonce string, query discovery.Query, signedQuery *discovery.Query) (int, []byte) {
	t.Helper()
	config := c.nodes[0].config.Client.TLSConfig.Clone()
	config.ServerName = "localhost"
	connection, err := tls.Dial("tcp", strings.TrimPrefix(server.URL, "https://"), config)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(query)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, server.URL+agtpdiscover.DiscoverPath, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if signedQuery != nil {
		material := c.materials[0]
		now := time.Now().UTC()
		values := agtpdiscover.ExpectedPolicy(*signedQuery, material.id).Expected
		grantToken := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
			"iss": testManagerIssuer, "sub": material.id, "aud": audience,
			"jti": "gossip-search-grant", "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(5 * time.Minute).Unix(),
			"profile_type": clients.TokenTypeIdentityGrant, "profile_version": clients.ProfileVersion,
			"cnf":     map[string]string{"kid": material.keyID},
			"service": values.Service, "agent": values.Agent, "capability_ref": values.CapabilityRef,
			"ontology_id": values.OntologyID, "scopes": values.Scopes, "resources": values.Resources,
		})
		grantToken.Header["kid"] = testManagerKeyID
		grant, err := grantToken.SignedString(c.managerPrivate)
		if err != nil {
			t.Fatal(err)
		}
		actionContext, err := agtpdiscover.CanonicalActionContext(*signedQuery)
		if err != nil {
			t.Fatal(err)
		}
		state := connection.ConnectionState()
		binding, err := production.SoftwareBindingFromTLS(&state, material.leaf, actionContext, nonce)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := c.nodes[0].config.Client.signBinding(RemoteAuthorization{Audience: audience}, grant, binding)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set(agtpdiscover.IdentityGrantHeader, grant)
		request.Header.Set(agtpdiscover.SessionBindingHeader, proof)
	}
	responseBody, status, err := exchangeHTTP(connection, bufio.NewReader(connection), request, DefaultMaxRequestBytes)
	if err != nil {
		t.Fatal(err)
	}
	return status, responseBody
}
