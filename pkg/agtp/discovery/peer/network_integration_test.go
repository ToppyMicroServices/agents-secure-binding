// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/agtp/discovery"
)

func TestLANPolicyDiscoveryConvergesAndRestarts(t *testing.T) {
	exerciseNetworkDiscovery(t, netip.MustParseAddr("127.0.0.1"))
}

// TestLANInterfaceDiscovery is an opt-in single-host interface test. The caller
// selects a local address; it does not discover or contact other machines.
func TestLANInterfaceDiscovery(t *testing.T) {
	configured := os.Getenv("ASB_DISCOVERY_LAN_TEST_ADDR")
	if configured == "" {
		t.Skip("set ASB_DISCOVERY_LAN_TEST_ADDR to a local LAN/VPC interface IP")
	}
	address, err := netip.ParseAddr(configured)
	if err != nil || address.String() != configured || !address.IsPrivate() || address.IsLoopback() || address.Is4In6() || address.Zone() != "" {
		t.Fatalf("ASB_DISCOVERY_LAN_TEST_ADDR must be a canonical private interface IP: %q", configured)
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	local := false
	for _, candidate := range addresses {
		prefix, parseErr := netip.ParsePrefix(candidate.String())
		if parseErr == nil && prefix.Addr().Unmap() == address {
			local = true
			break
		}
	}
	if !local {
		t.Fatalf("selected IP %s is not assigned to a local interface", address)
	}
	exerciseNetworkDiscovery(t, address)
}

func exerciseNetworkDiscovery(t *testing.T, address netip.Addr) {
	t.Helper()
	policy := &NetworkPolicy{AllowedCIDRs: []netip.Prefix{netip.PrefixFrom(address, address.BitLen())}}
	cluster := newTestClusterWithNetwork(t, time.Hour, address.String(), policy)
	wantInfos := append([]discovery.NodeInfo(nil), cluster.infos...)

	if _, err := cluster.nodes[0].Register(discovery.NameBinding{
		Name: "domain-agent.example", AgentID: "domain-agent", Endpoint: "https://" + cluster.infos[0].Endpoint,
		Capabilities: []string{"domain-analysis"}, Version: 1, ExpiresAt: time.Now().Add(time.Hour),
		Visibility: discovery.Visibility{Mode: discovery.VisibilityPublic},
	}); err != nil {
		t.Fatal(err)
	}
	mustGossip(t, cluster.nodes[0])
	mustGossip(t, cluster.nodes[1])
	assertMatchCount(t, cluster.nodes[2], "domain-analysis", 1)
	if binding, found := cluster.nodes[2].Resolve("domain-agent.example"); !found || binding.AgentID != "domain-agent" {
		t.Fatalf("LAN name did not converge: %+v, %v", binding, found)
	}
	located, err := cluster.nodes[0].Locate(context.Background(), cluster.infos[2].ID, DefaultMaxPeers)
	if err != nil || !containsNode(located, cluster.infos[2].ID) {
		t.Fatalf("LAN DHT referral = %+v, %v", located, err)
	}
	for index := range cluster.nodes {
		assertNetworkObservability(t, cluster, (index+1)%len(cluster.nodes), index)
	}
	if changed, err := cluster.nodes[0].Deregister("domain-agent.example", 2); err != nil || !changed {
		t.Fatalf("LAN withdraw = %v, %v", changed, err)
	}
	mustGossip(t, cluster.nodes[0])
	mustGossip(t, cluster.nodes[1])
	cluster.restartAll()
	mustGossip(t, cluster.nodes[0])
	mustGossip(t, cluster.nodes[1])
	for index, node := range cluster.nodes {
		if node.Info() != wantInfos[index] {
			t.Fatalf("restart changed configured peer: got %+v, want %+v", node.Info(), wantInfos[index])
		}
		assertMatchCount(t, node, "domain-analysis", 0)
		if _, found := node.Resolve("domain-agent.example"); found {
			t.Fatal("restart restored a withdrawn LAN name")
		}
	}
}

func assertNetworkObservability(t *testing.T, cluster *testCluster, sender, receiver int) {
	t.Helper()
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{cluster.materials[sender].tlsCert}, RootCAs: cluster.roots,
		ServerName: cluster.networkAddress, MinVersion: tls.VersionTLS13,
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	for _, path := range []string{HealthPath, MetricsPath} {
		response, err := client.Get("https://" + cluster.infos[receiver].Endpoint + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("configured peer GET %s status = %d", path, response.StatusCode)
		}
	}
}

func TestLANConfigRequiresFixedAllowedEndpoints(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Config)
		valid  bool
	}{
		{name: "private-fixed-address", valid: true},
		{name: "private-address-without-policy", change: func(config *Config) { config.NetworkPolicy = nil }},
		{name: "wildcard-listener", change: func(config *Config) { config.ListenAddress = "0.0.0.0:9443" }},
		{name: "different-advertised-ip", change: func(config *Config) { config.Info.Endpoint = "10.20.30.8:9443" }},
		{name: "different-advertised-port", change: func(config *Config) { config.Info.Endpoint = "10.20.30.7:9444" }},
		{name: "dynamic-listener", change: func(config *Config) { config.ListenAddress = "10.20.30.7:0" }},
		{name: "dns-endpoint", change: func(config *Config) { config.Info.Endpoint = "peer.example.test:9443" }},
		{name: "outside-cidr", change: func(config *Config) { config.NetworkPolicy = testNetworkPolicy("10.20.31.0/24") }},
		{name: "empty-policy", change: func(config *Config) { config.NetworkPolicy = &NetworkPolicy{} }},
		{name: "unverified-server", change: func(config *Config) { config.Client.TLSConfig.InsecureSkipVerify = true }},
		{name: "server-tls-override", change: func(config *Config) {
			config.TLSConfig.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
				return nil, nil
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := networkValidationConfig(t)
			if test.change != nil {
				test.change(&config)
			}
			if err := validateConfig(withDefaults(config)); (err == nil) != test.valid {
				t.Fatalf("validateConfig = %v, want valid=%v", err, test.valid)
			}
		})
	}
}

func TestLANNodeSnapshotsPolicyWithoutChangingCallerClient(t *testing.T) {
	config := networkValidationConfig(t)
	callerClient := config.Client
	callerPolicy := testNetworkPolicy("192.0.2.0/24")
	callerClient.NetworkPolicy = callerPolicy
	wantPrefixes := append([]netip.Prefix(nil), config.NetworkPolicy.AllowedCIDRs...)
	node, err := NewNode(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Stop(context.Background()) })
	if node.config.Client == callerClient || callerClient.NetworkPolicy != callerPolicy {
		t.Fatal("NewNode changed the caller's client policy")
	}
	config.NetworkPolicy.AllowedCIDRs[0] = netip.MustParsePrefix("198.51.100.0/24")
	if !reflect.DeepEqual(node.config.NetworkPolicy.AllowedCIDRs, wantPrefixes) || !reflect.DeepEqual(node.config.Client.NetworkPolicy.AllowedCIDRs, wantPrefixes) {
		t.Fatal("caller policy mutation changed a constructed node")
	}
	if node.config.NetworkPolicy == node.config.Client.NetworkPolicy {
		t.Fatal("node and transport share a mutable network policy")
	}
}

func TestLANRegistrationAndRoutesRequireConfiguredMembership(t *testing.T) {
	config := networkValidationConfig(t)
	node, err := NewNode(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Stop(context.Background()) })
	unknown := discovery.NodeInfo{ID: testNodeID("40"), Endpoint: "10.20.30.8:9443"}
	if err := node.AddPeer(unknown); err == nil {
		t.Fatal("AddPeer accepted an unconfigured node within the allowed network")
	}
	certificate, _ := issueTestCA(t)
	outside := discovery.NodeInfo{ID: testNodeID("fe"), Endpoint: "192.0.2.7:9443"}
	if err := config.Directory.Add(certificate, PeerIdentity{Node: outside}); err != nil {
		t.Fatal(err)
	}
	if err := node.AddPeer(outside); err == nil {
		t.Fatal("AddPeer accepted a configured node outside the allowed network")
	}
	insideCertificate, _ := issueTestCA(t)
	if err := config.Directory.Add(insideCertificate, PeerIdentity{Node: unknown}); err != nil {
		t.Fatal(err)
	}
	if err := node.AddPeer(unknown); err != nil {
		t.Fatalf("AddPeer rejected an explicitly registered allowed peer: %v", err)
	}
	cases := []struct {
		name        string
		remote      string
		certificate *x509.Certificate
	}{
		{name: "missing-identity", remote: "10.20.30.8:43210"},
		{name: "outside-source-network", remote: "192.0.2.7:43210", certificate: insideCertificate},
		{name: "outside-configured-endpoint", remote: "10.20.30.8:43210", certificate: certificate},
	}
	for _, path := range []string{HealthPath, MetricsPath, NoncePath, ReplicatePath, FindNodePath} {
		for _, test := range cases {
			request := httptest.NewRequest(http.MethodGet, "https://"+config.Info.Endpoint+path, nil)
			request.RemoteAddr = test.remote
			if test.certificate != nil {
				request.TLS = &tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{test.certificate},
					VerifiedChains:   [][]*x509.Certificate{{test.certificate}},
				}
			}
			response := httptest.NewRecorder()
			node.routes().ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("%s request to %s status = %d", test.name, path, response.Code)
			}
		}
	}
}

// networkValidationConfig supports config and membership checks without opening
// a socket. Only the integration fixture starts a server and issues leaf certs.
func networkValidationConfig(t *testing.T) Config {
	t.Helper()
	certificate, private := issueTestCA(t)
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	localCertificate := tls.Certificate{Certificate: [][]byte{certificate.Raw}, PrivateKey: private, Leaf: certificate}
	info := discovery.NodeInfo{ID: testNodeID("01"), Endpoint: "10.20.30.7:9443"}
	directory := t.TempDir()
	return Config{
		Info: info, ListenAddress: info.Endpoint, NetworkPolicy: testNetworkPolicy("10.20.30.0/24"),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{localCertificate}, ClientCAs: roots, MinVersion: tls.VersionTLS13},
		Directory: NewPeerDirectory(),
		Client: &Client{
			AgentID: info.ID, PrivateKey: private,
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{localCertificate}, RootCAs: roots, MinVersion: tls.VersionTLS13},
		},
		StatePath: filepath.Join(directory, "state.json"), AuditPath: filepath.Join(directory, "audit.jsonl"),
		GossipInterval: time.Hour,
	}
}

// LAN endpoints have fixed ports. Reserve distinct ports together, then release
// them before Node.Start; another process can still claim a port in that gap.
func reserveNetworkEndpoints(t *testing.T, address string, count int) []string {
	t.Helper()
	listeners := make([]net.Listener, 0, count)
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
	endpoints := make([]string, 0, count)
	for i := 0; i < count; i++ {
		listener, err := net.Listen("tcp", net.JoinHostPort(address, "0"))
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
		endpoints = append(endpoints, listener.Addr().String())
	}
	return endpoints
}
