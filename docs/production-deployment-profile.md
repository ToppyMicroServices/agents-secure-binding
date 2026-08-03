# Production deployment profile: protected-change-v1

Status: the baseline is supported beginning with `v1.0.0`. The Azure SEV-SNP
bridge and Redis replica-acknowledgement additions documented below are
unreleased candidates pending live qualification and a minor release.

This is one concrete Direct-Agent v1 deployment profile. Its reference
consumer is a tenant-configuration change service, not Split-Knowledge. The
service applies a change only when the grant, Agent proof, accepted TLS 1.3
session, exact change, fresh signed attestation result, verifier nonce, local
policy, and shared replay state all agree.

## Fixed choices

| Item | protected-change-v1 choice |
| --- | --- |
| Transport | mutually authenticated TLS 1.3; no 0-RTT acceptance |
| Grant signing | Ed25519 / JWT `EdDSA`; locally configured Manager key IDs |
| Session proof signing | Ed25519 / JWT `EdDSA`; Agent key named by grant `cnf.kid` |
| Audience | exact protected-change endpoint configured by the verifier |
| Token profile | Direct-Agent v1: `sbaip.identity-grant` and `sbaip.session-binding` |
| Exporter label | fixed `Attestation` label |
| Exporter context | `asb.direct-agent.production.v1 NUL nonce NUL canonical_action` |
| Action digest | SHA-256 of canonical protected-change JSON |
| Trust and revocation | fresh role-specific `production.TrustSource` snapshot on every acceptance |
| Attestation | v1.0 baseline: Ed25519-signed `asb-attestation-result/v1`; unreleased extension: pinned-issuer Azure SEV-SNP MAA bridge |
| Replay | v1.0 baseline: Redis/Valkey `SET NX PX`; unreleased extension: same-connection `WAIT`; certificate-verified TLS and fail closed |
| Outcome | consumer-owned durable, idempotent store keyed by `change_id` |

Manager, Agent, and attestation-verifier keys are separate trust domains. A key
ID is never accepted in another role merely because its signature verifies.

## Exact protected action

The consumer accepts this request shape and rejects unknown JSON members:

```json
{
  "change_id": "change-0001",
  "tenant": "tenant-01",
  "setting": "feature-x",
  "enabled": true
}
```

The bound canonical action is the JSON encoding of these ordered fields:

```json
{
  "profile": "asb.protected-change/v1",
  "method": "POST",
  "resource": "config://tenant-01/feature-x",
  "change_id": "change-0001",
  "enabled": true
}
```

Changing the Boolean value, tenant, setting, change identifier, method, or
resource changes the accepted context and causes the session proof to fail.

## Trust and revocation

`production.Profile` loads two snapshots for each request:

1. the Manager snapshot verifies the grant issuer, audience, algorithm, `kid`,
   signature, lifetime, and grant `jti` revocation state; and
2. the Agent snapshot verifies the session proof issuer, audience, algorithm,
   `kid`, signature, lifetime, and proof `jti` revocation state.

A trust-source error, unknown key, disabled key, revoked token, missing key, or
role collision rejects the action. A deployment may implement `TrustSource`
with an atomically replaced local snapshot or a remote registry, but it must
return an error rather than silently using unbounded stale data.

## Attestation policy

The profile requires a `production.AttestationResult`. The signed payload
contains:

- result version and unique result ID;
- attestation-verifier key ID;
- exact appraisal policy ID and accepted measurement;
- the binder derived from the authenticated peer key, current TLS exporter,
  canonical action, and verifier nonce; and
- explicit issue and expiry times.

`production.SignedAttestationPolicy` verifies the Ed25519 signature, trusted
and enabled verifier key, policy ID, measurement allowlist, binder, maximum age,
future skew, and expiry. Missing or stale results fail closed. This profile
authenticates an appraisal result; evidence acquisition and hardware-specific
appraisal remain deployment responsibilities.

For the selected Azure SEV-SNP deployment,
`production.AzureMAATokenVerifier` authenticates an RS256 Azure Attestation JWT
against a pinned issuer and deployment-managed key snapshot. It does not follow
token-provided key URLs during acceptance. `production.AzureSNPAttestationBridge`
then enforces exact policy hash, launch measurement, guest SVN, debug and
migration policy, and a signed nonce derived from the exact ASB binder before
issuing the short-lived result. See
[`azure-sev-snp-attestation-bridge.md`](azure-sev-snp-attestation-bridge.md).

## Distributed replay

Configure the shared replay cache with a bounded, certificate-verified TLS
connection:

```go
redisStore := production.RedisSetNXStore{
    Address:                         "replay.internal.example:6379",
    KeyPrefix:                       "asb:protected-change:v1:",
    TLSConfig:                       redisTLSConfig,
    OperationTimeout:                2 * time.Second,
    RequiredReplicaAcknowledgements: 1,
    ReplicationTimeout:              500 * time.Millisecond,
}
replay := identitypolicy.NewSetNXReplayCache(ctx, redisStore)
```

`redisTLSConfig` must use TLS 1.3 or newer, verify the server name and trust
chain, and must not set `InsecureSkipVerify`. Redis ACL credentials or a client
certificate may be used. Replay input is hashed before becoming a Redis key.
The atomic key covers the grant hash, audience, exact action context, and
verifier nonce; the TTL is the earliest grant, proof, or attestation expiry.
Connection, TLS, authentication, protocol, timeout, and store errors all reject
the action. An insufficient `WAIT` acknowledgement also rejects the action. The
write may already exist after that rejection. No local replay fallback is used.

`WAIT` reduces the acknowledged-write loss window but does not make Redis a
strongly consistent store. Real failover qualification is required for the
selected managed or self-operated topology; see
[`redis-failover-runbook.md`](redis-failover-runbook.md). A deployment that
requires zero replay after every possible failover must use a strongly
consistent conditional-insert backend instead of relying on Redis replication.

## Consumer transaction

The acceptance order is:

1. strictly parse and canonicalize the protected action;
2. derive the expected binding from the accepted mTLS session, peer
   certificate, action, and verifier nonce;
3. load current role-specific trust and revocation snapshots;
4. authenticate grant and session proof and enforce confirmation-key binding;
5. compare D3-D6 application policy and every expected binding field;
6. authenticate and appraise the signed attestation result;
7. atomically commit shared replay state; and
8. pass the minimal accepted identity projection to the consumer's idempotent
   outcome store.

The ASB replay commit is an identity-acceptance boundary, not an application
database transaction. A production consumer must use an idempotent durable
outcome record and reconcile failures that occur after identity acceptance.

## Verification

Run the production unit, distributed replay, and concrete consumer tests:

```sh
go test -race -count=1 ./pkg/production ./examples/protected-change-consumer
```

The negative suite covers trust-source outage, unknown or disabled keys,
revoked grant, changed action, wrong local task, wrong TLS session, replay,
attestation binder mismatch, stale attestation, unapproved measurement, and
shared replay-store outage. The Redis/Valkey adapter test races 20 TLS clients
against one key, requires exactly one winner, and requires a replica
acknowledgement for the successful write. The failover command provides a
two-phase seed/verify gate for the selected real service:

```sh
go test -race -count=1 ./cmd/redis-failover-redteam
```

These tests are implementation evidence for the documented profile. A
successful Azure confidential-VM run and a successful multi-node Redis/Valkey
failover run must be recorded separately before claiming those deployment
properties.
