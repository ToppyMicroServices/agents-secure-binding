# Three-node discovery product profile

This profile bounds discovery to three Go nodes and at most 100 live agents.
Loopback remains the default. An explicit `NetworkPolicy` enables fixed-address
peers across hosts in one administrator's LAN or VPC. This is an opt-in deployment
profile; local integration checks do not establish multi-host qualification.

## Release contract

- Three nodes use a Kademlia-style XOR routing table with at most two peers per
  node.
- `REPLICATE` exchanges Presence and ANS digests and deltas periodically.
- `FIND_NODE` performs authenticated multi-peer lookup.
- Every peer connection uses TLS 1.3 mutual authentication and a pinned server
  public key (SHA-256 of DER SubjectPublicKeyInfo).
- Every `REPLICATE` and `FIND_NODE` request carries a Manager-issued Identity
  Grant and an Agent-signed Session Binding.
- ASB binds the action, sender Node-ID, receiver Node-ID, path, body hash,
  server-issued nonce, client certificate, and accepted TLS session.
- Presence, tombstones, ANS bindings, and routing peers use checksummed atomic
  snapshots. Replay state uses a separate durable fail-closed cache.
- Failed snapshot writes are retried before replication succeeds. Until a
  snapshot is committed, Agent search fails closed and `/healthz` returns 503.
- Request bytes, live records, tombstones, peers, and per-peer request rate are
  bounded. Audit JSONL rotates at a configured byte limit.
- `/healthz` and `/metrics` are available through the same mTLS listener;
  persistence and audit failures have dedicated counters.
- In the LAN/VPC profile, all HTTP routes also require a source address in the
  configured CIDRs and a peer registered in `PeerDirectory`. Forwarding headers
  do not establish network membership. The loopback profile retains its existing
  CA-authenticated monitoring routes.
- Shutdown drains HTTP requests, stops the gossip worker, and commits a final
  snapshot. Mutations are rejected after shutdown begins.

## Tested release gate

```bash
go test -race -count=1 ./pkg/agtp/discovery/... ./examples/agtp-discover-consumer
```

The integration test opens three real ports and verifies:

1. 100 agents converge from node A through node B to node C.
2. A finds C through an authenticated multi-peer DHT lookup.
3. A is partitioned and deregisters an ANS-bound agent.
4. All three nodes stop and reload their persistent state.
5. Gossip resumes and the tombstone removes the stale record without
   resurrection.
6. One node is replaced while the others retain their state, then catches up
   under protocol version 1.
7. Unknown peers, altered bodies, replay, false Node-IDs, wrong server pins,
   oversized deltas, and oversized requests are rejected.
8. Repeated stable gossip does not increase Presence, tombstone, or routing
   state.

Additional regression tests cover Presence arriving before its ANS binding,
reuse of a withdrawn name at the live-record limit, same-version changes to
withdrawal suppression, snapshot failures and recovery, concurrent start/stop,
and cancellation of a stalled peer request. The DHT test also uses a directory
containing the local node to check that it does not consume a remote peer slot.

`TestGossipFeedsASBAuthenticatedAgentSearch` connects the receiving node directly
to the HTTP consumer's `Catalog`. It verifies replicated search results,
visibility filtering, withdrawal and expiry, and rejection of missing proofs
or an altered query. The consumer still performs its own DISCOVER authorization;
successful peer replication does not authorize a search caller.

LAN policy tests use real local TLS connections with explicitly configured
CIDRs. They cover stable endpoints, peer registration, DHT lookup, gossip, and
restart. The opt-in interface test binds to a private IP assigned to this host:

```bash
ASB_DISCOVERY_LAN_TEST_ADDR=<local-LAN-IP> \
  go test -race -count=1 ./pkg/agtp/discovery/peer -run '^TestLANInterfaceDiscovery$'
```

This exercises the non-loopback transport on one machine. A release claiming
operation across three hosts still needs deployment-specific checks of routing,
firewalls, certificates, restart, and partition recovery on those hosts.

The bounded soak is opt-in locally and runs for 30 seconds in the CI
`product-security` gate:

```bash
ASB_DISCOVERY_SOAK=1 ASB_DISCOVERY_SOAK_DURATION=30s \
  go test -race -count=1 ./pkg/agtp/discovery/peer -run TestPeerServiceSoak
```

## Trust and compatibility boundary

This profile trusts each configured peer as a coordinator authorized to merge
records for the local population. It does not verify an individual AGTP Agent
Certificate or an AGTP record signature. Peer certificates and ASB binding
keys remain separate and are joined only by verifier-local `PeerDirectory`
policy.

Rolling replacement is supported while all nodes use peer protocol version 1.
A future incompatible protocol version requires an explicit dual-version
compatibility implementation and test before rollout.

Tombstone GC is receiver-local. Identical gossip does not restart retention
while a marker is held, but receiving it again after local GC or reloading a
snapshot starts a new local retention period. Peers can therefore keep finite
markers circulating; eventual reclamation across the cluster is not guaranteed.
`MaxTombstones` bounds storage, and a full store rejects new withdrawals until
capacity is available. Monitor the tombstone count and admission errors. A
global reclamation guarantee would require a separate retention protocol.

Protocol version 1 digests contain versions, not suppression floors. Gossip
therefore includes every retained tombstone to propagate stronger suppression
at the same version. This adds traffic proportional to the bounded marker count.

The LAN/VPC configuration is described in
[`agtp-discovery-lan.md`](agtp-discovery-lan.md). Automatic enrollment, DNS-based
peer discovery, NAT/proxy remapping, cross-administrator federation, external
key management, multi-process shared state, and general AGTP wire interoperability
remain outside this profile.
