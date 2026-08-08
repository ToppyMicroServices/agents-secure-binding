# Three-node discovery product profile

This profile fixes the supported release scope to three Go nodes on one host
and at most 100 live agents. Each node listens on a separate loopback TLS port.

## Release contract

- Three nodes use a Kademlia-style XOR routing table with at most two peers per
  node.
- `REPLICATE` exchanges Presence and ANS digests and deltas periodically.
- `FIND_NODE` performs authenticated multi-peer lookup.
- Every peer connection uses TLS 1.3 mutual authentication and a pinned server
  certificate.
- Every `REPLICATE` and `FIND_NODE` request carries a Manager-issued Identity
  Grant and an Agent-signed Session Binding.
- ASB binds the action, sender Node-ID, receiver Node-ID, path, body hash,
  server-issued nonce, client certificate, and accepted TLS session.
- Presence, tombstones, ANS bindings, and routing peers use checksummed atomic
  snapshots. Replay state uses a separate durable fail-closed cache.
- Request bytes, live records, tombstones, peers, and per-peer request rate are
  bounded. Audit JSONL rotates at a configured byte limit.
- `/healthz` and `/metrics` are available through the same mTLS listener;
  persistence and audit failures have dedicated counters.
- Shutdown drains HTTP requests, stops the gossip worker, and commits a final
  snapshot. Mutations are rejected after shutdown begins.

## Tested release gate

```bash
go test -race -count=1 ./pkg/agtp/discovery/...
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

The longer bounded soak is opt-in:

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

The current release scope is loopback only. Cross-host discovery, automatic PKI
enrollment, external key management, multi-process shared state, and general
AGTP wire interoperability remain outside this profile.
