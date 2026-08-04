# Changelog

## Unreleased

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
