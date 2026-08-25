# Supported API and compatibility policy

This policy applies beginning with release `v1.0.0`. Release `v1.1.0` adds the
software-only production composition and replica-acknowledged replay without
changing the supported v1 token shape.

## Supported surface

The supported Go API is:

- `pkg/production`: the attested `Profile` and attestation-free
  `SoftwareOnlyProfile` production compositions, accepted TLS binding
  derivation, signed attestation-result policy, and TLS-protected Redis/Valkey
  SETNX replay adapter with optional same-connection `WAIT` acknowledgement;
- `pkg/clients`: Direct-Agent v1 JWT verification through
  `JWTVerifyOptions`, `VerifyIdentityGrantJWT`, `VerifySessionBindingJWT`, and
  `VerifySessionIdentityJWT`; and
- `pkg/atls/identitypolicy`: Direct-Agent v1 policy, binding, and replay
  interfaces used by the supported production composition.

The supported wire profile is Direct-Agent profile version `1` with
`sbaip.identity-grant` and `sbaip.session-binding` token types. The fixed
production exporter label is `Attestation`; application context and a
verifier-issued nonce are combined by `production.BindingFromTLS` or
`production.SoftwareBindingFromTLS`. The latter keeps the peer-key, TLS
exporter, request-context, and nonce binding but requires
`attestation_binder_sha256` to be absent from both expected and signed binding
values.

The supported v1.1 operational surface also includes
`cmd/redis-failover-redteam` and `scripts/redis-sentinel-failover.sh`. These
qualify replay-record survival for a selected topology; they are not a Redis
discovery client and do not create a zero-loss replication guarantee.

The following remain experimental or outside the supported product API:

- draft-06-inspired v2 entrypoints and types;
- `pkg/agtp`, gateway-route, cache, and diversion-policy adapters;
- the Azure Attestation bridge, pending live hardware qualification and a
  later explicit API-support decision;
- the inherited Manager, Agent, CVM, HAL, proxy, and CLI runtime surfaces;
- examples, test harnesses, formal models, and document structure; and
- hardware-specific evidence acquisition and appraisal implementations.

An exported Go identifier outside the supported list is not implicitly stable.

## A2A Security Test Kit candidate

The main branch contains an unreleased, self-contained ASB binding tester. Its
default Direct-Agent v1 profile runs eight fixed scenarios and can emit a
machine-readable report described by
`schemas/a2a-security-test-report-v1.schema.json`. The candidate also includes
strict report decoding and validation in `pkg/a2asecuritytest`.

This surface is not part of the v1.1 compatibility promise. Until it is
released as a supported product surface, its command flags, Go package, and
report schema may change. The experimental multi-host runner can exercise a
configured alternate Agent B that implements the fixed repository profile. It
is not a general target scanner or A2A conformance suite, and `draft06-v2`
remains experimental. The candidate `pkg/llmruntime` adapter and
`llm-conversation` workflow are also outside the v1.1 compatibility promise.

## Compatibility rules

Tags follow semantic versioning.

- Patch releases preserve the supported source API and v1 wire shape. A patch
  may reject input that was previously accepted when the input is invalid,
  ambiguous, insecure, or outside the documented profile.
- Minor releases may add optional APIs or fields. Existing supported calls and
  valid v1 messages continue to work without source changes.
- Breaking supported API or wire changes require a new major version and a new
  versioned verification entrypoint. They are not introduced by silently
  changing v1 parsing or binding behavior.
- Stable APIs deprecated during v1 remain available through the v1 major line
  unless retaining them creates a concrete security vulnerability. Any
  security exception is documented in the release notes and security advisory.
- The supported build baseline for v1 is Go 1.26.x. A later toolchain floor
  is announced in release notes before it becomes the default-branch minimum.

Only the latest v1 minor release receives routine fixes. The immediately prior
minor receives critical security fixes for 90 days after the newer minor is
released. Release artifacts and their source commit remain available after the
support window.

## Deployment compatibility

Production deployments must keep Manager, Agent, and attestation-verifier key
roles separate. Key rotation is compatible when old and new key IDs overlap in
the locally accepted trust snapshot for the intended migration window.
Disabling a key ID or revoking a token ID intentionally causes requests that
depend on it to fail.

Both production compositions require a positive verifier-local
`AuthorityPolicy.MaxTokenLifetime` for each Manager and Agent role. Production
tokens must carry `iat`, must expire after issuance, and must not exceed that
role-specific lifetime; `ClockSkew` must be non-negative. This production
hardening does not change the Direct-Agent v1 claim names or the lower-level
`pkg/clients` wire parser. Typed-nil trust, attestation, and replay interfaces
are treated as missing configuration and fail closed.

Replay storage is compatible with Redis or Valkey servers that implement
`SET key value NX PX ttl` over TLS. Store unavailability is an authentication
failure; there is no in-memory fallback in either production profile. The
v1.1 replica-acknowledgement option additionally requires
`WAIT numreplicas timeout` on the same connection. `WAIT` compatibility does
not imply strong consistency or zero-loss failover behavior.

The two production compositions are intentionally distinct. An attested
`Profile` cannot be changed into a `SoftwareOnlyProfile` by omitting an
attestation result, and the software-only request type has no attestation
field. Moving a deployment between them is an explicit policy and
configuration change, not wire-compatible fallback behavior.
