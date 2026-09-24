# Security Hardening Proposal: Durable audit retention beyond online limits

## Decision

Choose how terminal approval history leaves the bounded SQLite working set without losing
retry, replay, provenance, or audit guarantees.

## Executive Recommendation

Option 1, **verified export without reclamation**, creates restorable evidence but preserves the
current fail-closed caps. Option 2, **verified compaction with identifier tombstones**, exports a
canonical batch and transactionally replaces eligible terminal rows with a minimal permanent
index. I recommend shipping Option 1 first as the prerequisite. Enable Option 2 only after its
restore, old-retry, duplicate-ID, and crash tests pass and the operator configures an archive
destination.

## Evidence

I inspected the schema and transaction paths. The caps and fail-closed behavior are explicit;
there is no observed deletion of terminal operation or mutation-result rows.

| Evidence | Finding or document | What it establishes |
| --- | --- | --- |
| `ASB-HARD-005` | bounded local store | The store retains terminal history and original mutation results until fixed caps reject new work. |

Sources: `internal/humanapp/store.go` and `docs/local-human-approval.md`.

## Current Design And Failure Mode

Keeping every original response makes retries deterministic and avoids silent audit loss. It
also makes uptime proportional to a fixed number of historical mutations. Deleting rows by age
would be unsafe: an old command identifier could be reused, and an old retry could become a new
mutation. The structural condition is that online recovery state and long-term audit history are
represented by the same full rows.

## Desired Invariants

- Pending, unresolved, or externally uncertain work is never archived or deleted.
- Every compacted batch is durably written, hashed, and restore-checked before online deletion.
- Retired operation and command identifiers cannot be reused.
- Old retries return the documented retained result or a permanent retired response; they never
  execute again.
- Audit records preserve canonical request, decision, identity, result, and ordering metadata.
- Capacity status is observable before admission stops.

## Constraints And Non-Goals

An archive hash proves integrity relative to the manifest, not independent custody or durable
media. This proposal does not choose cloud storage, legal retention, deletion policy, or a
multi-tenant database. SQLite remains the online single-host store.

## Before Architecture

[Before architecture](../diagrams/durable-audit-retention-before.mmd) shows why the current safe
choice eventually stops admission. The proposed boundary keeps that fail-closed behavior unless
a complete archive protocol succeeds.

## Options

### Option 1: Verified export without reclamation

Use SQLite's online backup API or a stopped-service snapshot to produce a consistent export.
Write a manifest containing schema version, first and last record keys, counts, timestamps,
source database identity, and SHA-256 digests. Fsync the archive and verify it by restoring into
a temporary database and running integrity and semantic checks. Add `capacity status` warnings.
Do not delete online records.

This is the safest first step and provides recovery evidence. It does not solve indefinite
admission because the same caps remain. Rollback is simply to stop scheduling exports; the
online database was not modified.

[Option 1 architecture](../diagrams/durable-audit-retention-export-after.mmd)

| Change | Before | After | Security consequence | Cost |
| --- | --- | --- | --- | --- |
| Backup | manual complete-directory copy | canonical verified export | reproducible restore evidence | archive storage and verification time |
| Capacity | visible only near failure | status and thresholds | operators can act before fail-closed admission | monitoring configuration |
| Reclamation | none | none | no new retry semantics | finite online lifetime remains |

### Option 2: Verified compaction with identifier tombstones

After Option 1 verification, select only terminal records older than a configured retry horizon.
Write a canonical archive batch, fsync it, restore-check it, and record its digest in SQLite.
Within one transaction, replace full operation and command rows with tombstones containing the
identifier, request digest, terminal state, minimal response or permanent-retired marker, archive
batch ID, and decision time. Never compact pending or uncertain work. Keep tombstones for at
least the maximum identifier-reuse horizon; for unbounded external identifiers, keep them
permanently or use a collision-resistant set with an exact fallback.

This reclaims large payloads while preserving replay and provenance boundaries. It adds archive
custody as a dependency for full audit retrieval. A manifest or restore failure leaves online
rows untouched. Rollback disables new compaction; already compacted rows are restored from the
verified batch through a tested import path.

[Option 2 architecture](../diagrams/durable-audit-retention-compaction-after.mmd)

| Change | Before | After | Security consequence | Cost |
| --- | --- | --- | --- | --- |
| Terminal rows | full records forever | archive plus exact tombstone | prevents duplicate execution after compaction | new schema and archive lookup |
| Admission capacity | fixed lifetime | reclaimed payload capacity | supports long-running service | compaction scheduling and backpressure |
| Audit retrieval | one SQLite query | online index plus archive | full evidence remains recoverable if archive is present | archive availability and tooling |

## Comparison

| Dimension | Option 1 | Option 2 |
| --- | --- | --- |
| Security | preserves current online semantics | preserves semantics only if tombstone and archive protocol are correct |
| Performance | backup I/O, no request-path change | smaller DB; periodic export/compaction I/O and possible archive reads |
| Memory | temporary restore database and buffers | same plus tombstone index and archive catalog |
| Reliability | finite capacity still causes planned refusal | adds archive dependency but removes fixed payload lifetime |
| Operability | capacity alerts and archive custody | retention, compaction, restore drills, and archive incident response |
| Migration | additive | schema migration and tested rehydration required |

## Recommendation

I recommend a two-gate rollout: make Option 1 production-quality first, then deliver Option 2
behind an explicit retention configuration. There is not enough evidence to choose an archive
provider or legal retention period. Until one is configured and tested, the current fail-closed
caps should remain.

## Evidence Coverage And Residual Risk

| Evidence | Coverage | Residual risk |
| --- | --- | --- |
| `ASB-HARD-005` — bounded local store | Option 1 improves evidence but leaves capacity; Option 2 addresses long-term payload capacity | tombstone growth, archive loss, and legal retention remain deployment concerns |

A permanent exact tombstone set also grows. Its per-record size is bounded and smaller, but an
unbounded service still needs an explicit identifier-retention model or external durable index.

## Migration And Rollout

Add schema and export support without enabling deletion. Run repeated backup/restore drills and
compare record counts and digests. Introduce dry-run compaction reports, then compact a disposable
copy, then enable small batches with pause and rollback controls. Never compact during a schema
upgrade or while archive verification is unavailable.

## Validation Plan

Inject crashes before archive write, after fsync, after catalog insertion, and during compaction.
Verify no record is lost and no batch is double-applied. Replay old command and operation IDs
before and after restart. Corrupt or remove the archive and confirm that audit retrieval fails
closed without executing a command. Benchmark request latency and database size at the current
caps and after representative compaction.

## Implementation Work Packages

- Add capacity/status reporting and a consistent export format with manifest and hashes.
- Add restore and semantic verification tooling plus scheduled backup hooks.
- Add archive catalog, exact tombstone schema, eligibility query, and transactional compaction.
- Add retry/replay, crash, corruption, import, and long-run capacity tests.

## Open Questions

- What is the required retry horizon, and can operation identifiers ever be reused?
- Which archive destination, encryption, and custody policy is selected?
- What legal or product retention and deletion periods apply?
- What maximum tombstone growth and restore time are acceptable?
