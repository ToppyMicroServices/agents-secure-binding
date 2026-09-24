# Discovery within an administrative LAN or VPC

Use this profile when one administrator controls the discovery peers on several
hosts. Configure both the allowed network ranges and each trusted peer. CIDR
membership alone does not authorize a peer; mTLS, public-key pins, and ASB action
verification still apply. The initial limit remains three nodes and 100 live
Agent records.

## Fixed addresses

For example, three hosts can expose these discovery endpoints:

| Node | Endpoint |
| --- | --- |
| A | `10.20.0.11:9443` |
| B | `10.20.0.12:9443` |
| C | `10.20.0.13:9443` |

For an otherwise configured `peer.Config`, node A selects its network as follows:

```go
cfg.Info.Endpoint = "10.20.0.11:9443"
cfg.ListenAddress = cfg.Info.Endpoint
cfg.NetworkPolicy = &peer.NetworkPolicy{
    AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")},
}
node, err := peer.NewNode(cfg)
if err != nil {
    return err
}
if err := node.Start(); err != nil {
    return err
}
```

The snippet uses `net/netip` from the standard library. Keep the existing TLS,
Manager grant, ASB profile, state, replay-cache, and audit configuration in `cfg`.
`NewNode` copies the network policy and applies it to its own client. A standalone
`peer.Client` needs its own `NetworkPolicy` to connect beyond loopback.

This first profile uses canonical literal IPv4 or IPv6 addresses and fixed,
nonzero ports. The listen and advertised endpoints must match. Wildcard listeners,
DNS endpoints, address zones, and `/0` policies are rejected. Without a policy,
the existing loopback configuration remains available, including ephemeral test
ports. The LAN profile preserves the configured advertised endpoint at startup.

## Register peers before bootstrapping

For every permitted remote node, configure its exact Node-ID and endpoint in
`PeerDirectory`, together with its client certificate public-key pin and ASB
verification profile. Configure the corresponding `Client.Remotes` entry with
its audience, TLS server name, server public-key pin, and Manager-issued grants
for `REPLICATE` and `FIND_NODE`.

`RemoteAuthorization.ServerCertificateSHA256` contains the hex-encoded SHA-256
of DER SubjectPublicKeyInfo, despite its historical field name. The TLS
`ServerName` must match the remote certificate's SAN; it may be a DNS name even
when transport uses a fixed IP. TLS hostname/chain verification remains enabled.
The LAN profile rejects `InsecureSkipVerify` on its client and a server
`GetConfigForClient` override.

All nodes need trust entries for the peers they may discover. Initial routing
can still use A–B–C: call `AddPeer` for B on A, A and C on B, and B on C. A's DHT
lookup can learn C from B only if C's exact identity and endpoint are already
registered on A and its address is allowed. Persisted peers are checked against
current registration and network policy when loaded.

Permit the selected TCP port between these hosts in the LAN/VPC firewall. Each
host should use its own state, replay, and audit files. Keep clocks synchronized
within the configured ASB token validity and skew limits. Endpoint or key changes
require explicit trust configuration updates on the other nodes. After changing
a peer's endpoint, also call `AddPeer` with the updated `NodeInfo` to replace its
routing entry; changing the directory alone does not refresh an existing route.
For changes to `Client.Remotes` (such as pins or grants), stop and rebuild the
affected node; that map must not be changed while requests are running.

LAN health and metrics requests also need a registered peer certificate and an
allowed source address. They do not take forwarding headers as evidence of the
source. Place monitoring inside this trust configuration. Proxies and NAT address
translation are not part of this initial profile.

## Validation boundary

The tests cover network-policy validation and three-node TLS exchanges on one
machine. `TestLANInterfaceDiscovery` can additionally use a specified local LAN
interface. Neither result proves that routing, firewall rules, clock settings,
or credential distribution work on three separate hosts.

Static analysis and selected unit tests can run without starting a discovery
listener or contacting another peer:

```bash
GOWORK=off go vet ./pkg/agtp/discovery/... ./examples/agtp-discover-consumer
GOWORK=off golangci-lint run ./pkg/agtp/discovery/...
GOWORK=off go test -race -count=1 ./pkg/agtp/discovery/peer \
  -run '^(TestNetworkPolicy.*|TestLANConfigRequiresFixedAllowedEndpoints|TestLANNodeSnapshotsPolicyWithoutChangingCallerClient|TestLANRegistrationAndRoutesRequireConfiguredMembership|TestLANRestoreRevalidatesPersistedPeers|TestLANEndpointRotationAtCapacity)$'
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build ./pkg/agtp/discovery/... ./examples/agtp-discover-consumer
```

The selected tests check CIDRs, configuration ownership, registered membership,
and routing-state persistence. They include reloading under changed trust or
network policy and replacing an endpoint when both peer slots are occupied.
These are local unit tests; static analysis and cross-compilation do not execute
the Linux service or establish network reachability.

Before qualifying a particular deployment, check convergence and authenticated
lookup across its hosts, then withdrawal during a temporary peer partition and
recovery after restarting a node with its own persistent files. Record those
results separately from local tests. The existing receiver-local tombstone
retention limits still apply; see the
[product profile](agtp-discovery-product-profile.md#trust-and-compatibility-boundary).

Agent search continues to query each node's locally converged Presence records.
This policy scopes discovery-peer transport. It does not automatically authorize
calls to an Agent endpoint returned by search.

The [agent interaction example](../examples/agtp-agent-interaction/README.md)
connects discovery to a separately authorized task between two local processes.
It provides a runnable first check without requiring another host or an LLM.
