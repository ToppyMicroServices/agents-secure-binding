# Changelog

## v2.0.0-rc.1

- Move the public Go module and imports to the canonical `/v2` path.
- Inject platform-neutral evidence sources and verifiers into aTLS, and move
  Cocos-specific composition to its own nested integration module.
- Add experimental direct SNP and TDX `v0.1.0` modules and harden signed EAT,
  CoRIM, and legacy appraisal compatibility paths.
- Add macOS and Linux release gates for the ASB core, nested modules, Cocos
  development workspace, signed tags, and `GOWORK=off` operation.

- Reject typed-nil replay, trust-source, and attestation implementations as
  missing configuration; built-in replay caches now fail closed on nil
  receivers.
- Require `iat` and verifier-local maximum token lifetimes in both production
  compositions, with bounded clock-skew policy.
- Require a verified mTLS client chain in the protected-change consumer and
  bind its reference outcome record to the accepted identity projection.
- Document `INDETERMINATE` post-acceptance outcomes and authenticated
  reconciliation without blind retry.

This release candidate does not assert production readiness for the SNP or TDX
modules or the Cocos integration. Live hardware qualification is incomplete.

## v1.1.0

- Add an explicit attestation-free `SoftwareOnlyProfile` with a separate
  request type, TLS/action binding helper, replay domain, and fail-closed
  rejection of attestation binders.
- Add live mutually authenticated TLS integration coverage through the
  non-Split-Knowledge protected-change consumer.
- Add a pinned-issuer Azure SEV-SNP Attestation token bridge with exact ASB
  binder challenge, measurement, policy, SVN, debug, migration, key, and
  freshness checks.
- Add optional same-connection Redis/Valkey `WAIT` acknowledgement after a
  successful replay insert.
- Add a two-phase real Redis/Valkey failover qualification command and
  a TLS 1.3 Redis Sentinel primary-failure CI gate.
- Add deployment runbooks for Azure hardware attestation and replay HA while
  keeping live hardware and managed-provider qualification outside the stable
  API claim.

## v1.0.0

- Add the supported Direct-Agent v1 production composition.
- Add role-separated trust and revocation snapshots that fail closed on source
  errors.
- Add signed attestation-result appraisal with exact binder, policy,
  measurement, freshness, and verifier-key checks.
- Add a TLS-only Redis/Valkey SETNX replay adapter with bounded operations.
- Add the protected-change HTTPS consumer and positive/negative E2E tests.
- Define the supported API and compatibility policy.

The v1.0.0 release covers the verifier-side Direct-Agent v1 core and the
documented protected-change deployment profile. It does not make the
experimental draft-06 v2, gateway runtime, inherited Cocos runtime, or
hardware evidence acquisition part of the supported product API.
