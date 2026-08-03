# Redis/Valkey replay failover runbook

Status: deployment qualification for `protected-change-v1`; local protocol
tests do not replace a run against the selected multi-node service.

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

Repeat the gate at these cut points:

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
