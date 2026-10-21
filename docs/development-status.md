# Development status

Scope reviewed on 22 October 2026 against main
`d925f72ff6313bd2271b084fe8519d1b0f0c4112`.

The current supported implementation and the implemented preview features are
complete for this development increment. The owner chose to keep qualification
for a selected operator, provider or deployment as separate work. This does not
promote previews to stable APIs or declare a production deployment qualified.
The [API compatibility policy](API_COMPATIBILITY.md) remains authoritative.

## Completed implementation

| Area | Implemented and checked scope |
| --- | --- |
| Supported Direct-Agent API | Exact request/TLS binding, authority and replay checks, attested and software-only compositions |
| Human approval preview | Four distinct decisions; only approval permits a change; uncertain execution outcomes remain separate |
| Human Coordination preview | Single-host SQLite transactions, operation recovery, durable outbox, Linux relay persistence and read-only reconciliation with a synthetic provider |
| Model provenance | GGUF and Safetensors/LoRA verification with the documented runtime restrictions; external model APIs without verifiable evidence are rejected |
| Evidence handling | Required attestation rejects missing, malformed and sample evidence; GCP direct-SNP and the narrower Azure MAA checks have recorded live results |
| Distribution tooling | Debian builders and lifecycle tests, apt signature/rotation checks, fresh unsigned metadata preparation and a fail-closed Pages publication workflow |

See the [Human acceptance mapping](human-coordination-integration-status.md),
[approved model bundles](llm-model-bundles.md), and
[live attestation record](live-attestation-validation.md) for their exact limits.

The required `product-security` job invokes `make human-coordination-gate`.
Its package list includes the bounded Human red-team packages, and it runs both
independent Python transcript verifiers. The standalone
`human-coordination-red-team` status is not separately required by the ruleset.
No branch protection change is needed to make the existing bounded checks
mandatory.

## Verified main checkpoint

All eight workflows below succeeded for the inspected commit. These links are
evidence for that revision; a later change must pass its own required checks.

| Workflow | Successful run |
| --- | --- |
| CI | [39463461527](https://github.com/ToppyMicroServices/agents-secure-binding/actions/runs/39463461527) |
| Security Red Team | [39463461581](https://github.com/ToppyMicroServices/agents-secure-binding/actions/runs/39463461581) |
| Local Human Approval | [39463461829](https://github.com/ToppyMicroServices/agents-secure-binding/actions/runs/39463461829) |
| ASB Discovery Linux | [39463461611](https://github.com/ToppyMicroServices/agents-secure-binding/actions/runs/39463461611) |
| Redis Sentinel Failover | [39463461689](https://github.com/ToppyMicroServices/agents-secure-binding/actions/runs/39463461689) |
| Attestation Modules | [39463461807](https://github.com/ToppyMicroServices/agents-secure-binding/actions/runs/39463461807) |
| Push on main | [39463461901](https://github.com/ToppyMicroServices/agents-secure-binding/actions/runs/39463461901) |
| Cocos dependency graph update | [39463474367](https://github.com/ToppyMicroServices/agents-secure-binding/actions/runs/39463474367) |

The repository had zero open Dependabot alerts when checked on 22 October.
Routine dependency-update proposals are maintenance work, not evidence of an
unfinished feature. The published stable release remains `v1.1.1`; the latest
v2 prerelease remains `v2.0.0-rc.2`. This closeout does not create a new tag or
include current-branch features retroactively in either release.

The [Debian workflow](../.github/workflows/debian-distribution.yaml) checks the
final packages from each candidate revision, including installation, upgrade
from a different source, persistent state, removal, signature rejection and key
rotation. Its ephemeral signing keys do not qualify production apt publication.

## Separate operator qualification

These items remain unqualified and are not marked complete by the development
closeout tracked in `asb-ksh`:

| Remaining work | Tracking |
| --- | --- |
| Selected Human delivery provider, authenticated outcome lookup, deployment recovery/SLOs and live telemetry privacy | `asb-ljs.8`, remaining deployment scope of `asb-ljs.15` and `asb-ljs` |
| Managed Redis/Valkey provider failover and persistence guarantees | `asb-vdf.3`, `asb-vdf` |
| Managed KMS/HSM key custody, rotation and disablement | `asb-vdf.4` |
| Full Azure bridge acceptance using independently approved measurement/SVN/MAA policy; remaining hardware profiles | `asb-vdf.2`, `asb-33l` |
| Discovery across three real LAN/VPC hosts | `asb-itc` |
| Organization-owned S3 deployment and operational acceptance | `asb-tqe` |
| Production apt signing key, backup recovery, signed HTTPS publication and renewal | `asb-z3q` |

APT is **not published**. The [publication runbook](asb-apt-publication.md)
requires an independently selected production key and reviewed signer policy.
Old CI metadata is not an installable production repository.

The [Azure follow-up](https://github.com/ToppyMicroServices/agents-secure-binding/pull/75#issuecomment-6314234974)
accepted two fresh tokens and rejected fourteen negative cases at the token
verifier/challenge boundary. It did not qualify full bridge or protected-action
acceptance. The [cleanup record](https://github.com/ToppyMicroServices/agents-secure-binding/pull/75#issuecomment-6316120725)
confirms removal of VM, disk, IP and Network Watcher resources. The
[latest billing check](https://github.com/ToppyMicroServices/agents-secure-binding/pull/75#issuecomment-6319311496)
still lacks an Azure usage amount; the USD 5 estimate is not a final bill.
