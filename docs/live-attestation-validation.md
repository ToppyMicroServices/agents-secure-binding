# Live attestation validation

## Status — 2026-10-17

**Live hardware and live Azure validation have not run.** No hardware quote or
Azure Attestation token was acquired in this attempt. Local tests below must
not be counted as live qualification.

The starting revision is `239d2d4842b04f078c18df1bb999fc3e81d4dcfc`.
Environment discovery on 2026-10-17 found:

| Check | Observed result |
| --- | --- |
| Repository self-hosted runners | GitHub API returned `total_count: 0`. |
| Hardware workflow history | No runs were returned for `hardware-attestation-red-team.yaml`. |
| Local execution host | Darwin, arm64. |
| Local Azure CLI | `az` was not found in PATH. Azure CLI is not required if an already configured VM is available through another connection. |
| Execution target and appraisal inputs | No designated SNP/TDX host, Azure confidential VM, approved MAA issuer/key snapshot, or approved measurement/policy locations were supplied. |

The live run is waiting for these execution inputs. A test must use an
independently approved measurement and policy; deriving its allowlist from the
evidence under test would not validate the intended deployment.

## Preparation findings

The existing hardware command already collected reports for two challenges
and required both to pass full module verification. It now also exercises
malformed evidence, modified signatures, NoCC/CC/embedded samples, and samples
relabeled as the configured hardware platform. Named outcomes and SHA-256
fingerprints are included in successful full-verification summaries. Both
fresh controls must succeed before any rejection is counted as a passing run.

The direct SNP provider returns protobuf evidence. The qualification command
now preserves those bytes in its signed envelope instead of passing them to a
claim extractor that expects an ABI report. The configured module remains
responsible for report parsing, cryptographic verification, and appraisal.

Microsoft documents the guest client's nonce at
`x-ms-runtime.client-payload.nonce`, encoded with standard Base64. ASB previously
read only the plain top-level nonce. The bridge now normalizes the documented
signed claim after JWT authentication, rejects conflicting or malformed
values, and still requires an exact match with the expected ASB challenge.
This is a documented-format compatibility repair, not a successful Azure run.
[Microsoft guest-token example](https://learn.microsoft.com/en-us/azure/confidential-computing/skr-flow-confidential-vm-sev-snp#prepare-the-release-policy)

## Local regression results

These checks passed on 2026-10-17 in the isolated
`test/live-required-attestation` worktree. They validate local code and test
fixtures; none acquired evidence from hardware or Azure.
The selected Go toolchain was `go1.26.9 darwin/arm64`; golangci-lint was
`2.11.1` (built with Go 1.26.9).

| Working directory | Check | Result |
| --- | --- | --- |
| Repository root | `go test -race -count=1 ./pkg/production` | PASS |
| Repository root | `go vet ./pkg/production` | PASS |
| Repository root | `golangci-lint run ./pkg/production` | 0 issues |
| `integrations/cocos` | `GOWORK=off go test -race -count=1 ./cmd/hardware-attestation-redteam` | PASS |
| `integrations/cocos` | `GOWORK=off go vet ./cmd/hardware-attestation-redteam` | PASS |
| `integrations/cocos` | `GOWORK=off golangci-lint run ./cmd/hardware-attestation-redteam` | 0 issues |
| `integrations/cocos` | `GOWORK=off go mod tidy -diff` | No diff |

The Azure fixtures cover nested and matching dual nonce claims, 28 malformed
or mismatched nonce cases, unsigned tokens, and modified signed payloads. The
hardware command tests cover exact provider-byte preservation, signature-only
mutation, all 13 expected decisions, and failure of either positive control.
The harness control-flow test uses a fake verifier, explicitly separate from
the concrete verifier exercised by a live run. A successful live summary has
named verdicts and fingerprints; a failed run currently exits without writing
that summary, so its exit status and workflow log must also be retained.

## Evidence required to complete this record

For direct hardware, run the existing manual workflow or command with a
designated confidential host and its approved CoRIM/platform policy. Preserve
the resulting fingerprint summary, exact tested revision, platform, runner
environment, policy/key fingerprints, and run time.

For Azure, acquire fresh tokens inside the designated confidential VM for two
independent ASB session/action binders. Verify the signature, pinned issuer and
keys, age, policy hash, measurement, SVN, debug/migration policy, and challenge
through the bridge. Require success for the matching binder and rejection for
the other binder, modified tokens, malformed inputs, and sample evidence.
Record the guest-client/library versions and non-sensitive fingerprints.

Do not publish raw JWTs, quotes containing deployment-specific information,
private keys, or credentials. Failure to acquire or verify a fresh positive
control is a failed or unexecuted qualification, never proof that negative
cases passed. Follow the [Azure bridge procedure](azure-sev-snp-attestation-bridge.md)
for the live token path.
