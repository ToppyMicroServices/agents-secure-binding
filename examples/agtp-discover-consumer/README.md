# ASB-authenticated DISCOVER

This example authenticates a caller with ASB before querying the local Go
Presence store. It does not run or proxy the Python AGTP server.

To search records received through gossip, pass the running discovery peer
directly as the application's `Catalog`; `*peer.Node` implements that interface:

```go
application := agtpdiscover.Application{
    Profile:       discoverProfile,
    Nonces:        verifierNonces,
    Catalog:       node, // *peer.Node configured with trusted peers and ASB grants
    ExpectedAgent: expectedAgent,
}
```

The HTTP application needs its own DISCOVER authority policy and nonce source.
The peer can use the default loopback profile or the explicit
[LAN/VPC configuration](../../docs/agtp-discovery-lan.md).
Its queries read the peer's local converged state. A query does not trigger a
network-wide search: records arrive through periodic gossip, while expiry and
visibility are checked locally on every query.

The accepted Identity Grant fixes the Agent-ID, `agtp.discover` scope,
capability, and `/population` resource. The Session Binding fixes the complete
query, including its result limit, to the accepted mTLS session. Only then does
the application pass the authenticated Agent-ID into Presence visibility
filtering.

```bash
go test ./pkg/agtp/discovery/... ./examples/agtp-discover-consumer
```

The tests cover the successful query plus capability substitution, wrong TLS
session, replay, TTL update, selective visibility, partitioned withdrawal,
three-node DHT lookup, and ANS registration and deletion.

`TestGossipFeedsASBAuthenticatedAgentSearch` connects these layers: records
travel from A through B to C over authenticated gossip, then an ASB-protected
HTTP query searches C. It checks selective visibility, withdrawal, local lease
expiry, missing ASB proofs, and a query that differs from its session binding.

The HTTP consumer test uses ephemeral credentials and an in-memory replay
cache. The separate three-node peer profile uses durable replay and discovery
state plus authenticated DHT and gossip transport. A deployment must still
provide its own Manager, Agent, client-CA, and server keys.

See [the implementation boundary](../../docs/agtp-discovery-local.md) for the
supported subset and the features intentionally left out.
