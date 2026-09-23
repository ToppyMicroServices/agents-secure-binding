# Local analysis context

This analysis was prepared from an isolated local working tree for the branch
named below.

- Target revision: `41e37c018c34744fcca45a6f9581c77e03366224`
- Branch: `feat/asb-software-completion`
- Source drift: present; the inspected files include uncommitted changes.
- Evidence collection digest: `2678cb9bda353dc32e8a0dd932e296022cb4b0af970c3daea7109bbde42b811c`
- Collection rule: SHA-256 each listed file, then hash sorted `path\0digest\n` records.

## Evidence registry

| Evidence | Observed source fact | Source |
| --- | --- | --- |
| `ASB-HARD-001` | The agent and computation-runner systemd units do not declare `User=` or `Group=`. | `init/systemd/agents-secure-binding-agent.service`, `init/systemd/computation-runner.service` |
| `ASB-HARD-002` | The computation runner creates its Unix socket with mode `0600`, so a separate agent identity cannot connect without an ownership design. | `cmd/computation-runner/main.go` |
| `ASB-HARD-003` | Windows termination kills only the direct process; the source says untrusted descendants require a Job Object. | `agent/algorithm/process_windows.go` |
| `ASB-HARD-004` | Local credentials expire after one year, the CA key is not retained, and the bootstrap token is a persistent file. There is no rotation command. | `internal/humanapp/credentials.go`, `docs/local-human-approval.md` |
| `ASB-HARD-005` | The local store fails closed at fixed operation, mutation-result, and replay limits and performs no terminal-history compaction. | `internal/humanapp/store.go`, `docs/local-human-approval.md` |
| `ASB-HARD-006` | Existing validation is explicitly a Developer Preview and excludes credential renewal, disk-loss recovery, broad browser coverage, and live SNP/TDX qualification. | `docs/local-human-approval-validation.md`, `docs/asb-completion-plan.md` |

## Evidence inventory

| SHA-256 | Path |
| --- | --- |
| `094cde769828aaf6454e400db2d27c7c0ae15f2752949b437d5a63a2ea971f8e` | `agent/algorithm/process_unix.go` |
| `6f70cad9b6e0c9e41c24d9a860cb9ef4b2a465ad95dd5c4d6ef88c07c7eff3b3` | `agent/algorithm/process_windows.go` |
| `0b1b504d896ddc46b885833e81e86434ad362d6069ae0ee928f78fd3e130949e` | `cmd/asb-human/main.go` |
| `05903d69e17b2f9f81ef71bbd007c22e12b17885891d8610e29374bc974ff1b6` | `cmd/computation-runner/main.go` |
| `d418e9a160d7f2f645011207eef91ea816e7dbff0ab4b07bf0b413033ec292b0` | `docs/asb-completion-plan.md` |
| `600aa94786e22a3c764e728fad04a44386a85135a43b7c8c51e1e24f9763d402` | `docs/local-human-approval-validation.md` |
| `38b365191aa428768db474c44e70981004f0a1eec9110565b72f31d1c44f1991` | `docs/local-human-approval.md` |
| `11fc1119b3f3f495c19feb01bd5f113623ff26a948698c96e748e92d75153f25` | `init/systemd/agents-secure-binding-agent.service` |
| `0e99fbbe4d7ed91ee6b6afdefa7d791bff34d64ffdc1c673f805b558816388da` | `init/systemd/computation-runner.service` |
| `686a1137650bb63f5c433872cba49d2c6beb365753148c8e464a4401a7e08d22` | `internal/humanapp/credentials.go` |
| `8b812688a1d6417e145517fc3eac82f83a315c1783b95f9861e5d9cec7ba3691` | `internal/humanapp/store.go` |

## Scope boundary

The analysis identifies implementation choices. It is not evidence that any option has
been implemented, deployed, or qualified. The dirty source tree must be re-hashed before
implementation starts; relevant drift returns the affected proposal to review.
