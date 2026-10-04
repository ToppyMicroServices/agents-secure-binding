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
- At most 64 accepted TCP connections enter TLS; further connections wait in
  the kernel backlog. Peer responses are bounded before HTTP header parsing to
  the configured body limit plus 64 KiB for headers and framing. The body limit
  defaults to 1 MiB, and connection I/O retains the configured timeout.
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
The optional epoch profile below uses protocol version 2. It deliberately
rejects version 1 peers and does not support a mixed-version rolling migration.

Tombstone GC is receiver-local. Identical gossip does not restart retention
while a marker is held, but receiving it again after local GC or reloading a
snapshot starts a new local retention period. Peers can therefore keep finite
markers circulating; eventual reclamation across the cluster is not guaranteed.
`MaxTombstones` bounds storage, and a full store rejects new withdrawals until
capacity is available. Monitor the tombstone count and admission errors. A
global reclamation guarantee is not provided by version 1. The optional
coordinated epoch procedure below reclaims retired populations explicitly.

Protocol version 1 digests contain versions, not suppression floors. Gossip
therefore includes every retained tombstone to propagate stronger suppression
at the same version. This adds traffic proportional to the bounded marker count.

## Optional coordinated epoch reclamation

`peer.Config.Epoch` enables this profile when positive. Zero remains the v1
default. A positive epoch uses peer protocol 2 and snapshot payload version 2;
old binaries reject that snapshot version. The HTTP routes, trusted peer list,
ASB permissions, and TLS requirements remain the same. This is a library
configuration, not an automatic cluster controller or a remotely callable reset.

All peers must have the same operator-maintained epoch. Replication and DHT
requests include it in the exact body authenticated by ASB. Receivers reject a
different epoch or protocol before merging any data. Clients require the reply
to echo the request's epoch and protocol over the authenticated TLS connection.
Saved routing identities do not bypass these checks. A partitioned old peer can
neither reintroduce its old live records nor circulate old tombstones into the
new epoch.

Within an epoch, tombstones have no time-based GC. Set `TombstoneRetention` to
zero; a nonzero value is rejected in this profile. The existing `MaxTombstones`
limit still rejects a new withdrawal at capacity. Suppression floors, including
indefinite markers, are retained until a newer record supersedes them or the
operator deliberately retires the entire population. Capacity alerts should
therefore trigger a planned epoch change before withdrawals reach the limit.

To migrate from v1 or reclaim an existing epoch:

1. Stop admission and publishers across the configured peers. Stop each node
   and save its existing snapshot as an operational backup. Plan a discovery
   outage: **all live Presence records and ANS bindings will be removed**, not
   just deletion markers. Keep ASB replay state and audit files.
2. Choose one strictly larger positive epoch for every peer. Preserve that
   value in deployment configuration independently of snapshot backups. Never
   reuse an epoch or restore an older configuration to match an old snapshot.
3. For each existing snapshot, set `Epoch` to the new value and supply
   `ReclaimFromEpoch` pointing to its exact current epoch (`0` for v1). Set
   `TombstoneRetention: 0`. `NewNode` audits the request and atomically persists
   the new empty population before returning a node that can start. Trusted
   routing entries are retained. Missing or mismatched source snapshots fail.
4. Remove `ReclaimFromEpoch` after the migration commits. It is a one-time
   instruction: reusing it against the new snapshot fails instead of clearing
   newly announced records. If startup reports a persistence error, inspect the
   saved epoch with `StateStore.Load`; the atomic replacement may have completed
   before a directory-sync error. Retry only the matching case. Do not delete
   the state file to silence the error.
5. Start all peers with the same new epoch and re-announce only records and
   names confirmed by the current authoritative publishers. Verify convergence
   and authenticated lookup before resuming search traffic. Do not bulk import
   old snapshot records with a new epoch label.

A new node without a previous snapshot needs `Epoch` and the one-time
`InitializeEpoch: true` instruction; its empty epoch is persisted during
`NewNode`. Remove that instruction afterward. It is rejected if a snapshot
already exists and cannot be combined with `ReclaimFromEpoch`. Without either
instruction, missing positive-epoch state is treated as state loss and startup
fails. A restart with the same epoch keeps current state.
A different epoch in a restored snapshot fails closed unless the exact one-time
migration instruction is supplied. All epoch comparisons are unsigned monotonic
values; the maximum value cannot be advanced and must not wrap.

Reclamation retains one epoch scalar and the bounded current population, rather
than an ever-growing list of retired Agent-IDs. This gives bounded local deletion
history across repeated coordinated changes. It does **not** promise continuous
availability, automatic cluster-wide completion, rollback resistance when both
configuration and state are restored together, rollback detection for an older
snapshot from the same epoch, or protection against an
authorized coordinator deliberately re-announcing stale data. Such a coordinator
already has authority to publish the local population. Organization rollout and
physical power-loss recovery still require deployment qualification.

`TestEpochReclamationRejectsPartitionedPeerAndRestoredSnapshot` covers a real
three-node TLS partition, rejection across epochs, removal of old names,
re-announcement, repeated restart, and an old snapshot. The remaining `TestEpoch*`
cases cover one-time migration, version validation, full marker capacity across
successive epochs, failed startup, and protocol mismatch. These belong to the
Linux discovery test gate; static compilation alone does not establish that they
passed.

The LAN/VPC configuration is described in
[`agtp-discovery-lan.md`](agtp-discovery-lan.md). Automatic enrollment, DNS-based
peer discovery, NAT/proxy remapping, cross-administrator federation, external
key management, multi-process shared state, and general AGTP wire interoperability
remain outside this profile.
