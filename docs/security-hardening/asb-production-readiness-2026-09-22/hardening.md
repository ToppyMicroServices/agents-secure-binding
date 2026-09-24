# Security Hardening Review: ASB production-readiness boundaries

## Evidence Basis

I inspected the current service units, process-control helpers, local approval credentials,
SQLite retention behavior, and the existing validation record. The evidence is source-based
and bound to the collection digest in `hardening.json`. The working tree contains other
uncommitted work, so this review does not describe a released revision.

## Constraints

The current software-only behavior must keep failing closed. Existing approval records,
receipts, and operation identifiers must survive credential maintenance and storage
maintenance. A local test or cross-build is not a production or hardware qualification.
No latency, memory, recovery-time, or operator-budget target was supplied, so those effects
remain validation items rather than measured claims.

## Opportunity Portfolio

| Opportunity | Evidence | Options | Recommendation | Proposal |
| --- | --- | --- | --- | --- |
| Contain services and descendant processes | systemd identity and socket ownership; Windows direct-child termination (`ASB-HARD-001`–`003`) | One shared identity and post-start Job; split identities and fail-closed Job launch | Use split identities and a suspended-launch Job path when untrusted computations are supported | [Runtime containment](proposals/runtime-containment.md) |
| Renew local trust without losing history | one-year fixed trust set and persistent bootstrap token (`ASB-HARD-004`) | Offline atomic generation swap; online overlap | Use offline atomic rotation for the single-host preview | [Renewable local trust](proposals/renewable-local-trust.md) |
| Retain audit history beyond online caps | fixed fail-closed record limits (`ASB-HARD-005`) | Verified export only; verified compaction with tombstones | Add export first, then enable compaction only after restore and retry tests pass | [Durable audit retention](proposals/durable-audit-retention.md) |
| Make qualification an evidence-producing gate | explicit preview-only validation boundary (`ASB-HARD-006`) | Repository qualification bundle; independent lab track | Build the repository bundle now; require a lab track only for externally certified claims | [Qualification evidence gate](proposals/qualification-evidence-gate.md) |

## Recommendation Summary

The four changes reinforce one boundary: a decision is only trustworthy while the runtime,
credentials, durable history, and qualification evidence remain attributable to the same
bounded deployment. I recommend the stronger runtime design because ASB explicitly runs
untrusted algorithms. For the single-host Human approval preview, offline credential rotation
is simpler and safer than overlapping trust generations. Storage reclamation should follow a
verified export, with permanent tombstones for retired identifiers. Qualification should emit
a machine-readable bundle, but the repository must continue to say “unqualified” until each
selected real environment produces and passes that bundle.

## Next Decisions

Implementation can start without changing public protocol APIs. The remaining operator choices
are the service-account names and package ownership policy, the archive destination and retention
period, the supported Windows versions, and the concrete qualification targets. Live SNP/TDX,
disk-loss, browser, and managed-provider claims require access to those environments; source work
alone cannot close them.
