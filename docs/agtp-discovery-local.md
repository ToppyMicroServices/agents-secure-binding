# Local AGTP discovery slice

This repository contains a small Go implementation of the four discovery
functions needed by the ASB example. It is derived from behavior in the
official AGTP reference implementation at commit
[`90786c426782a986999eb55baccef33866cfc669`](https://github.com/nomoticai/agtp/commit/90786c426782a986999eb55baccef33866cfc669),
not copied line-for-line from its Python code.

The individual AGTP drafts remain the specification source. This package is
not an AGTP wire implementation and does not claim interoperability with a
general AGTP deployment.

| Function | Specification behavior represented | Go implementation in this repository | Not implemented here |
| --- | --- | --- | --- |
| DISCOVER | Query the live Presence population by capability and visibility | Exact canonical capability match, stable ordering, limit, AGTP-shaped result | Natural-language matching, trust/governance ranking, cross-scope query, signed AGTP response envelope |
| Presence | Announce, update, expire, withdraw, and filter live records | Monotonic versions, finite leases, public/owner/explicit/invisible visibility, tombstones, digest/delta anti-entropy, persistent three-node gossip | General AGTP wire messages and individual Agent Certificate verification |
| DHT | Locate discovery peers with Kademlia-style XOR routing | 256 k-buckets, nearest-peer selection, real-port authenticated multi-peer `FIND_NODE`, persistent bounded routing | S/Kademlia disjoint paths and cross-host routing |
| ANS | Register and resolve name-to-Agent-ID bindings using Presence as live state | Register, refresh, resolve by name or Agent-ID, deregister with Presence withdrawal, persistent delta replication | Cross-authority federation, governance signatures, and full Agent Manifest Documents |

## Security boundary

ASB authenticates the HTTP `DISCOVER` caller and binds the exact query to the
accepted TLS session. The authenticated Agent-ID is then used for selective
visibility. A deployment-local resolver may add an owner domain, but cannot
replace that Agent-ID.

Presence and ANS mutation APIs are library APIs for an already-authorized local
coordinator. The bounded peer service authenticates network `REPLICATE` and
`FIND_NODE` actions with mTLS, certificate pinning, ASB action/session binding,
durable replay state, and verifier-local peer policy.

Withdrawal retention is receiver policy. A tombstone is retained for at least
24 hours by default and at least through the known live-record lease. A record
without a finite lease produces an indefinite suppression marker. Since the
reference store is in memory, “indefinite” disables time-based GC but does not
survive process restart.

## Files

- `pkg/agtp/discovery/presence.go`: Presence, DISCOVER, visibility, tombstones,
  and anti-entropy.
- `pkg/agtp/discovery/dht.go`: XOR routing and iterative peer lookup.
- `pkg/agtp/discovery/ans.go`: ANS bindings coupled to Presence.
- `pkg/agtp/discovery/peer`: persistent three-port service, periodic gossip,
  ASB peer authentication, limits, metrics, and audit.
- `examples/agtp-discover-consumer`: ASB-authenticated HTTP entry point.

The fixed product scope and release gate are documented in
[`agtp-discovery-product-profile.md`](agtp-discovery-product-profile.md).
