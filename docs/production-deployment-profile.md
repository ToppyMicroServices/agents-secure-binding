# Production deployment profiles

Status: the attested `protected-change-v1` baseline is supported beginning with
`v1.0.0`. Release `v1.1.0` adds the explicit
`software-only-direct-agent-v1` composition and the optional Redis/Valkey
replica-acknowledgement setting. The Azure SEV-SNP bridge remains outside the
supported product API pending live hardware qualification.

This is one concrete Direct-Agent v1 deployment profile. Its reference
consumer is a tenant-configuration change service, not Split-Knowledge. The
service applies a change only when the grant, Agent proof, accepted TLS 1.3
session, exact change, fresh signed attestation result, verifier nonce, local
policy, and shared replay state all agree.

## Software-only Direct-Agent v1

`software-only-direct-agent-v1` is the supported production choice when the
operator accepts the software host, process isolation, and signing-key custody
as its platform trust boundary. It does not claim that the verifier measured
the boot chain, workload image, firmware SVN, debug state, or migration state.

This is a separate fail-closed composition, not an optional-attestation switch
on `production.Profile`:

```go
profile := production.SoftwareOnlyProfile{
    GrantAuthority:   managerAuthority,
    BindingAuthority: agentAuthority,
    IdentityPolicy:   expectedPolicy,
    ReplayCache:      distributedReplay,
}

expectedBinding, err := production.SoftwareBindingFromTLS(
    acceptedTLSState,
    authenticatedPeerLeaf,
    canonicalAction,
    verifierNonce,
)
```

Both authority policies must set a positive `MaxTokenLifetime` and a
non-negative `ClockSkew`. Production verification requires `iat`, requires
`exp` to be later than `iat`, and rejects a token whose `exp - iat` exceeds the
role-specific maximum. A typical bounded deployment uses a longer grant limit
and a shorter session-proof limit:

```go
managerAuthority.MaxTokenLifetime = 10 * time.Minute
managerAuthority.ClockSkew = 5 * time.Second
agentAuthority.MaxTokenLifetime = 2 * time.Minute
agentAuthority.ClockSkew = 5 * time.Second
```

The profile retains all of these mandatory gates:

- role-separated Manager and Agent trust sources, exact issuer, audience,
  algorithm, key ID, required issue time, bounded lifetime, and revocation
  checks;
- the authenticated peer public key, accepted TLS 1.3 exporter, exact
  canonical action digest, and verifier nonce;
- verifier-local D3-D6 identity and authorization policy; and
- a fail-closed distributed replay commit before identity acceptance.

The request type contains no attestation result. Both the locally derived
binding and the Agent-signed session proof must omit
`attestation_binder_sha256`; a non-empty value is rejected. Software-only
replay keys use the domain `asb.production.software-only.v1`, separate from the
attested profile. Replay expiry is bounded by the earlier grant or session
proof expiry.

Use the attested profile instead when the relying party must verify a platform
or workload measurement across an administrative boundary, enforce firmware
or guest SVN, prohibit debug or migration state using signed platform facts,
or satisfy a contract or regulation requiring remote hardware evidence. Those
conditions are deployment requirements; they are not requirements for a
Split-Knowledge substrate whose accepted threat model trusts its service host.

The non-Split-Knowledge `protected-change` consumer exercises this profile over
live mutually authenticated TLS 1.3 and includes rejection tests for changed
actions and unexpected attestation material.

## Attested protected-change v1

## Fixed choices

| Item | protected-change-v1 choice |
| --- | --- |
| Transport | mutually authenticated TLS 1.3; no 0-RTT acceptance |
| Grant signing | Ed25519 / JWT `EdDSA`; locally configured Manager key IDs |
| Session proof signing | Ed25519 / JWT `EdDSA`; Agent key named by grant `cnf.kid` |
| Audience | exact protected-change endpoint configured by the verifier |
| Token profile | Direct-Agent v1: `sbaip.identity-grant` and `sbaip.session-binding` |
| Token freshness | `iat` required; verifier-local maximum lifetime and clock skew per authority role |
| Exporter label | fixed `Attestation` label |
| Exporter context | `asb.direct-agent.production.v1 NUL nonce NUL canonical_action` |
| Action digest | SHA-256 of canonical protected-change JSON |
| Trust and revocation | fresh role-specific `production.TrustSource` snapshot on every acceptance |
| Attestation | Ed25519-signed `asb-attestation-result/v1`; experimental pinned-issuer Azure SEV-SNP MAA bridge |
| Replay | Redis/Valkey `SET NX PX`; v1.1 optional same-connection `WAIT`; certificate-verified TLS and fail closed |
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
outcome record, bind that record to the accepted identity projection, and
reconcile failures that occur after identity acceptance. A post-acceptance
timeout must remain `INDETERMINATE` until an authenticated outcome lookup proves
execution or no effect; it must not trigger a blind retry.

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

The repository's Redis Sentinel workflow performs a real multi-process
primary-stop and replica-promotion run. This qualifies the self-operated test
topology, not a managed service's endpoint convergence, persistence contract,
or SLA. A successful Azure confidential-VM run and a successful failover run
against any selected commercial deployment must be recorded separately before
claiming those deployment-specific properties.
