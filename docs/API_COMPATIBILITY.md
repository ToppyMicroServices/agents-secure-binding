# Supported API and compatibility policy

This policy applies beginning with release `v1.0.0`.

## Supported surface

The supported Go API is:

- `pkg/production`: production composition, signed attestation-result policy,
  accepted TLS binding derivation, and TLS-protected Redis/Valkey SETNX replay
  adapter;
- `pkg/clients`: Direct-Agent v1 JWT verification through
  `JWTVerifyOptions`, `VerifyIdentityGrantJWT`, `VerifySessionBindingJWT`, and
  `VerifySessionIdentityJWT`; and
- `pkg/atls/identitypolicy`: Direct-Agent v1 policy, binding, and replay
  interfaces used by the supported production composition.

The supported wire profile is Direct-Agent profile version `1` with
`sbaip.identity-grant` and `sbaip.session-binding` token types. The fixed
production exporter label is `Attestation`; application context and a
verifier-issued nonce are combined by `production.BindingFromTLS`.

The following remain experimental or outside the supported product API:

- draft-06-inspired v2 entrypoints and types;
- `pkg/agtp`, gateway-route, cache, and diversion-policy adapters;
- the unreleased Azure Attestation bridge and Redis failover command, until a
  minor release explicitly adds them to the supported surface;
- the inherited Manager, Agent, CVM, HAL, proxy, and CLI runtime surfaces;
- examples, test harnesses, formal models, and document structure; and
- hardware-specific evidence acquisition and appraisal implementations.

An exported Go identifier outside the supported list is not implicitly stable.

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
- The supported build baseline for v1.0 is Go 1.26.x. A later toolchain floor
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

Replay storage is compatible with Redis or Valkey servers that implement
`SET key value NX PX ttl` over TLS. Store unavailability is an authentication
failure; there is no in-memory fallback in the production profile. The
unreleased replica-acknowledgement option additionally requires
`WAIT numreplicas timeout` on the same connection. `WAIT` compatibility does
not imply strong consistency or zero-loss failover behavior.
