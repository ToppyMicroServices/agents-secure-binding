// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// This opt-in test owns only its temporary bridge, veths, and namespaces.
// It does not change the runner's default route, firewall, or external network.
func TestLinuxNamespaceInteraction(t *testing.T) {
	if os.Getenv("ASB_INTERACTION_NETNS_TEST") != "1" {
		t.Skip("set ASB_INTERACTION_NETNS_TEST=1 on a disposable Linux runner with root")
	}
	if os.Geteuid() != 0 {
		t.Fatal("network namespace test requires root on a disposable Linux runner")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ip, err := exec.LookPath("ip")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	configs, err := bootstrapDemo(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	runIP := func(args ...string) (string, error) {
		out, err := exec.CommandContext(ctx, ip, args...).CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	mustIP := func(args ...string) string {
		t.Helper()
		out, err := runIP(args...)
		if err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, out)
		}
		return out
	}
	bridge := fmt.Sprintf("asb%x", os.Getpid())
	var namespaces, veths []string
	bridgeCreated := false
	cleaned := false
	cleanup := func() {
		if cleaned {
			return
		}
		cleaned = true
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		remove := func(args ...string) {
			if out, err := exec.CommandContext(cleanupCtx, ip, args...).CombinedOutput(); err != nil {
				t.Errorf("network cleanup %v: %v: %s", args, err, out)
			}
		}
		// Deleting the host side removes both ends, including partially moved peers.
		for _, device := range veths {
			remove("link", "delete", device)
		}
		for _, namespace := range namespaces {
			remove("netns", "delete", namespace)
		}
		if bridgeCreated {
			remove("link", "delete", bridge)
		}
	}
	defer cleanup()
	mustIP("link", "add", bridge, "type", "bridge")
	bridgeCreated = true
	mustIP("link", "set", bridge, "up")
	roles := []string{roleAgentA, roleRelay, roleAgentB}
	addresses := map[string]string{roleAgentA: "10.203.0.11", roleRelay: "10.203.0.12", roleAgentB: "10.203.0.13"}
	roleNamespaces := make(map[string]string)
	namespaceIDs := make(map[string]string)
	seenIDs := make(map[string]bool)
	parentNamespace, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	for index, role := range roles {
		namespace := fmt.Sprintf("%s-%d", bridge, index)
		device := fmt.Sprintf("%sv%d", bridge, index)
		peerDevice := fmt.Sprintf("%sp%d", bridge, index)
		mustIP("netns", "add", namespace)
		namespaces = append(namespaces, namespace)
		mustIP("link", "add", device, "type", "veth", "peer", "name", peerDevice)
		veths = append(veths, device)
		mustIP("link", "set", peerDevice, "netns", namespace)
		mustIP("link", "set", device, "master", bridge)
		mustIP("link", "set", device, "up")
		mustIP("-n", namespace, "link", "set", "lo", "up")
		mustIP("-n", namespace, "address", "add", addresses[role]+"/24", "dev", peerDevice)
		mustIP("-n", namespace, "link", "set", peerDevice, "up")
		id := mustIP("netns", "exec", namespace, "readlink", "/proc/self/ns/net")
		if id == parentNamespace || seenIDs[id] {
			t.Fatal("agents do not have separate network namespaces")
		}
		seenIDs[id] = true
		namespaceIDs[role] = id
		roleNamespaces[role] = namespace
		config := configs[role]
		config.Self.Node.Endpoint = addresses[role] + ":9443"
		config.AllowedCIDRs = []string{"10.203.0.11/32", "10.203.0.12/32", "10.203.0.13/32"}
		config.Target.Endpoint = "https://10.203.0.13:9444"
		configs[role] = config
	}
	for _, role := range roles {
		config := configs[role]
		for index, remote := range config.Peers {
			config.Peers[index] = configs[remote.Role].Self
		}
		configs[role] = config
	}
	evidence, err := runPreparedDemo(ctx, childCommand{
		executable: executable, prefix: []string{"-test.run=^TestInteractionChild$", "--"}, namespaces: roleNamespaces,
	}, root, configs)
	if err != nil {
		t.Fatal(err)
	}
	if !evidence.Passed || !evidence.DistinctProcesses || !evidence.DistinctTLSKeys || !evidence.Discovery.DHTFound || evidence.Discovery.PeerCount != 2 || evidence.Discovery.Endpoint != "https://10.203.0.13:9444" || evidence.Result.Sum != 31 || evidence.Result.Executions != 1 || evidence.WithoutProofStatus != 401 || evidence.AuthorizedStatus != 200 {
		t.Fatalf("unexpected namespace interaction evidence: %+v", evidence)
	}
	evidence.NetworkScope = "single Linux host; three separate network namespaces over a private bridge"
	cleanup()
	if t.Failed() {
		return
	}
	if path := os.Getenv("ASB_INTERACTION_NETNS_REPORT"); path != "" {
		if !filepath.IsAbs(path) {
			t.Fatal("namespace report must have an absolute path")
		}
		report := struct {
			Interaction          interactionEvidence `json:"interaction"`
			OS                   string              `json:"os"`
			Architecture         string              `json:"architecture"`
			HostCount            int                 `json:"host_count"`
			Namespaces           map[string]string   `json:"network_namespaces"`
			DistinctNamespaces   bool                `json:"distinct_network_namespaces"`
			NetworkCleanupPassed bool                `json:"network_cleanup_passed"`
		}{evidence, runtime.GOOS, runtime.GOARCH, 1, namespaceIDs, true, true}
		if err := writeJSONFile(path, report); err != nil {
			t.Fatal(err)
		}
	}
}
