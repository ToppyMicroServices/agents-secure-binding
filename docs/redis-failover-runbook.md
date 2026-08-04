# Redis/Valkey replay failover runbook

Status: the repository includes a reproducible self-operated Redis Sentinel
qualification gate beginning with `v1.1.0`. That gate does not replace a run
against the selected managed service or production discovery endpoint.

## Topology

All ASB verifier instances connect to one stable private Redis/Valkey primary
endpoint over certificate-verified TLS 1.3. The endpoint is external to the
ASB process but must not be exposed to the public Internet. A development
instance may run on the same host; that arrangement is not multi-node HA.

Use either:

- a managed single-region HA service that maintains a stable primary endpoint;
  or
- a self-operated primary and replicas with Sentinel, plus a client/proxy that
  implements Sentinel discovery and role verification.

`production.RedisSetNXStore` uses one fixed address and does not implement
Sentinel discovery or Redis Cluster `MOVED`/`ASK` redirects. A deployment that
does not provide a stable endpoint must add and test that discovery layer
before using this adapter.

## Replication acknowledgement

Configure a same-connection `WAIT` after the successful replay `SET NX PX`:

```go
redisStore := production.RedisSetNXStore{
    Address:                         "replay.internal.example:6379",
    KeyPrefix:                       "asb:protected-change:v1:",
    TLSConfig:                       redisTLSConfig,
    OperationTimeout:                2 * time.Second,
    RequiredReplicaAcknowledgements: 1,
    ReplicationTimeout:              500 * time.Millisecond,
}
```

Insufficient acknowledgements, timeout, disconnect, TLS failure, authentication
failure, or protocol error rejects the ASB request. The initial `SET` may
already exist when `WAIT` fails, so a retry may also be rejected. This is a
deliberate fail-closed availability trade-off.

Redis replication remains asynchronous. `WAIT` reduces the practical lost-write
window but does not make Redis a strongly consistent CP store and cannot prove
zero replay across every failover. If zero lost replay writes are mandatory,
replace the replay backend with a strongly consistent conditional-insert store.

## Real failover gate

### Reproducible Sentinel gate

Run the same gate used by GitHub Actions:

```sh
ASB_FAILOVER_ARTIFACT_DIR=/secure/asb-failover-evidence \
  ./scripts/redis-sentinel-failover.sh
```

The script starts one TLS 1.3 primary, two TLS 1.3 replicas, and three Redis
Sentinels. It writes a fresh replay record using `SET NX PX` and
same-connection `WAIT 1`, stops the primary, waits for Sentinel to promote a
replica, restarts the ASB test command against the promoted primary, and
requires the original record to remain rejected as replay. It then requires a
fresh post-promotion write to receive a replica acknowledgement. The evidence
artifact contains the resolved container-image digest, timestamps, promoted
node, and replay-key fingerprint; it contains no raw replay key or TLS private
key.

This is real Redis process and primary-failure evidence. The test command
selects the promoted node explicitly after Sentinel election, so it does not
qualify stable-endpoint convergence, Sentinel client discovery, network
partitions, host loss, or a managed provider SLA.

### Selected deployment gate

Run both phases from a host that can reach the private endpoint. Supply ACL
credentials through `ASB_REDIS_USERNAME` and `ASB_REDIS_PASSWORD`, never as
command-line arguments.

Before failover:

```sh
go run ./cmd/redis-failover-redteam \
  --phase seed \
  --state-file /secure/asb-redis-failover.json \
  --address replay.internal.example:6379 \
  --server-name replay.internal.example \
  --ca-file /secure/redis-ca.pem \
  --required-replicas 1 \
  --replication-timeout 500ms \
  --ttl 30m
```

After the seed reports success, trigger a planned primary failover through the
selected service's control plane or Sentinel. Wait only until the stable
endpoint reports the promoted primary as writable, then run:

```sh
go run ./cmd/redis-failover-redteam \
  --phase verify \
  --state-file /secure/asb-redis-failover.json \
  --address replay.internal.example:6379 \
  --server-name replay.internal.example \
  --ca-file /secure/redis-ca.pem \
  --required-replicas 1 \
  --replication-timeout 500ms \
  --ttl 30m
```

The verify phase passes only when the seeded key still exists and is rejected
as replay. It fails if the key was lost, the evidence TTL expired, replication
acknowledgement is insufficient, or the service is unavailable.

Before a commercial HA or failure-tolerance claim, repeat the selected
deployment gate at these cut points:

1. immediately after the primary returns `SET OK`;
2. while `WAIT` is outstanding;
3. during stable-endpoint/DNS convergence;
4. with an old-primary/new-primary network partition;
5. after an ASB process restart; and
6. during TLS certificate and ACL credential rotation.

Record service/version, topology, persistence mode, replica count, requested
and observed acknowledgements, failover start/end time, ASB error class, and
the replay-key fingerprint. Do not record Redis passwords, client private keys,
or the raw replay state file.

Primary references:

- <https://redis.io/commands/WAIT/>
- <https://redis.io/docs/latest/operate/oss_and_stack/management/replication/>
- <https://redis.io/docs/latest/develop/reference/sentinel-clients/>
