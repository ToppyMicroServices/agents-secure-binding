# Security Hardening Proposal: Renewable local trust without state loss

## Decision

Choose a credential and bootstrap-token lifecycle that preserves the approval database,
receipts, operation identifiers, and fail-closed behavior.

## Executive Recommendation

Option 1, **offline atomic generation rotation**, stops the local service, stages and validates a
complete trust generation, and atomically activates it while leaving state untouched. Option 2,
**online overlapping generations**, lets several processes drain old credentials during a
bounded overlap. I recommend Option 1 for the current single-host preview. Option 2 becomes
preferable only when the deployment has multiple independently restarted processes or a stated
zero-downtime requirement.

## Evidence

I inspected the initialization and load paths and the usage guide. The fixed one-year trust set,
absence of the CA key, and persistent UI token are observed facts; the need for generation-level
replacement follows from those facts.

| Evidence | Finding or document | What it establishes |
| --- | --- | --- |
| `ASB-HARD-004` | fixed local trust set | Certificates share a one-year expiry, the CA key is discarded, the UI token persists, and no rotation command exists. |

Sources: `internal/humanapp/credentials.go`, `cmd/asb-human/main.go`, and
`docs/local-human-approval.md`.

## Current Design And Failure Mode

Initialization creates a complete private directory once. When certificates expire, loading
fails. Creating a new data directory also creates a new database context, so following that path
can strand history. A disclosed bootstrap token remains valid until the directory is replaced.
The structural issue is that mutable credential lifetime and durable application history share
one initialization boundary even though they require different retention policies.

## Desired Invariants

- Credential or token rotation never deletes or silently replaces `state.db`, WAL files, receipts,
  or original operation identifiers.
- A partially written generation cannot become active.
- The application either loads one complete generation or fails closed.
- Token rotation invalidates the old token after a documented restart boundary.
- Rotation status reports expiry and generation without exposing secrets.

## Constraints And Non-Goals

The local CA signing key remains absent at rest; rotation creates a new trust generation instead
of renewing individual leaves. This proposal does not introduce remote enrollment, a public PKI,
or multi-user Human identity. Secure backup of the directory remains an operator responsibility.

## Before Architecture

[Before architecture](../diagrams/renewable-local-trust-before.mmd) shows why replacing the whole
directory is unsafe: credentials and durable history currently meet at the application directory.
The design should separate their lifecycle without pretending they have different trust owners.

## Options

### Option 1: Offline atomic generation rotation

Add `credential status`, `credential rotate`, and `token rotate` maintenance commands. With the
service stopped, rotation acquires an exclusive maintenance lock, creates a new versioned
credential directory, verifies every key pair and trust relation, fsyncs files and the containing
directory, and atomically swaps a small active-generation pointer. The database and receipts are
never moved. Keep one previous generation for a bounded rollback window and remove it only after
a successful restart and explicit cleanup.

This matches the single-host model and preserves the deliberate no-CA-key-at-rest property.
Downtime is the time needed to stop, rotate, and restart. File locking and atomic replacement
must be implemented separately for Unix and Windows and tested on the supported filesystems.
Rollback switches the pointer to the previous validated generation; it does not roll back data.

[Option 1 architecture](../diagrams/renewable-local-trust-offline-rotation-after.mmd)

| Change | Before | After | Security consequence | Cost |
| --- | --- | --- | --- | --- |
| Credential lifetime | fixed at initialization | versioned, atomically replaceable generation | expiry no longer forces history abandonment | maintenance command and restart |
| UI token | persistent file | independently rotated secret | disclosed bootstrap link can be invalidated | active sessions need an explicit invalidation rule |
| Recovery | new directory guidance | previous validated generation | bounded credential rollback without DB rollback | protects another private generation temporarily |

### Option 2: Online overlapping trust generations

Maintain current and next trust bundles. Processes advertise the generation they loaded, accept
both roots during a bounded overlap, switch their presented leaf, and acknowledge readiness.
Only after every required participant acknowledges does the controller retire the old root and
token generation. Durable state remains independent.

The strongest case is a multi-process or highly available deployment where coordinated downtime
is unacceptable. The cost is a larger trust window and a new controller protocol. A compromised
old credential remains useful until retirement, and partial acknowledgement needs an operator
policy. Rollback reactivates the old generation while it is still within the overlap period.

[Option 2 architecture](../diagrams/renewable-local-trust-online-overlap-after.mmd)

| Change | Before | After | Security consequence | Cost |
| --- | --- | --- | --- | --- |
| Trust roots | one fixed root | current and next roots during overlap | supports live migration | temporarily trusts more keys |
| Coordination | restart all local roles | generation acknowledgement | avoids planned outage | controller state and timeout policy |
| Token invalidation | file replacement | generation-bound sessions | old token/session retirement is observable | web session format and migration |

## Comparison

| Dimension | Option 1 | Option 2 |
| --- | --- | --- |
| Security | short, explicit maintenance boundary; one active generation | broader temporary trust set and controller authority |
| Performance | no steady-state cost | dual-chain/session checks during overlap |
| Memory | one active and one bounded rollback generation on disk | two live trust bundles and acknowledgement state |
| Reliability | planned outage; simple atomic recovery | no planned outage, but partial rollout states exist |
| Operability | status, stop, rotate, restart, verify | scheduling, monitoring, deadline, and retirement policy |
| Migration | contained file-layout change | protocol and session migration across participants |

## Recommendation

I recommend Option 1 for the local preview because its deployment already assumes one trusted
host and loopback participants. A zero-downtime or multi-host requirement would change that
recommendation. Token rotation should be delivered independently so an exposed bootstrap link
does not wait for certificate expiry.

## Evidence Coverage And Residual Risk

| Evidence | Coverage | Residual risk |
| --- | --- | --- |
| `ASB-HARD-004` — fixed trust set | addressed by either option | directory backup can still expose every active private key and token |

Rotation cannot revoke copies already taken from a compromised host. The operator still needs a
secure backup, access-control, and incident-response policy.

## Migration And Rollout

Introduce a version-2 credential layout that can still read version 1. The first rotation copies
no database content; it writes a new generation and switches only after validation. Keep the
version-1 files until a successful restart and backup. Rollback must be tested before cleanup is
enabled.

## Validation Plan

Test interruption after every staged write and before/after pointer replacement. Confirm that
the application either loads the old complete generation or the new complete generation. Test
expired old certificates, token invalidation, unchanged database hashes, receipt readability,
Windows ACL preservation, and restore from a full backup. Measure maintenance duration on the
largest supported credential directory.

## Implementation Work Packages

- Define the versioned credential layout, generation metadata, and status output.
- Implement cross-platform maintenance locking, staged writes, fsync, validation, and swap.
- Add independent token rotation and session invalidation semantics.
- Add v1-to-v2 migration, rollback, fault-injection, and backup/restore tests.

## Open Questions

- Is a brief maintenance window acceptable for every supported local profile?
- How many previous generations and how many days of rollback are required?
- Are browser sessions valid across restart today, and should rotation invalidate all of them?
- Which Windows filesystems and ACL inheritance policies must be supported?
