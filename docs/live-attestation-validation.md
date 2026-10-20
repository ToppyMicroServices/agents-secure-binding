# Live attestation validation

## Status — 2026-10-21 JST

**GCP direct-SNP full module qualification passed: 2 fresh controls accepted,
11 invalid/stale/sample cases rejected.** Azure MAA and Intel TDX remain
unvalidated. The machine-readable [evidence record](live-attestation-validation.json)
contains named verdicts, source/binary/policy fingerprints, failed diagnostic
results, cloud regression output and resource cleanup counts.

The fixed R6 run used one `n2d-highcpu-2` AMD Milan SEV-SNP VM in
`us-central1-c`, with VMPL 0, two launch VMSAs, Secure Boot, no service account,
and a 10 GiB standard boot disk. Its guest record reports success at
`2026-10-20T16:47:41Z`. The controller completed deletion and inventory checks
at `2026-10-20T16:51:59Z`: **0 VMs, 0 disks, 0 reserved IP addresses**.
The ephemeral external IP was released with the VM. The 30-minute automatic
deletion limit was retained as a fallback to explicit cleanup.

| Live case | Result |
| --- | --- |
| Fresh session A and fresh session B | Both accepted with full module verification |
| Session A evidence with session B binding | Rejected |
| Malformed EAT and modified EAT signature | Both rejected |
| Modified SNP report signature and malformed report | Both rejected |
| NoCC, CC JSON and embedded vTPM samples | All rejected |
| The same three samples relabeled as SNP | All rejected |

The harness ran with `-platform snp -vmpl 0 -require-full-verification`,
`-corim-policy approved-policy/approved.corim.cbor`, and
`-platform-policy approved-policy/platform-policy.json`. Both fresh controls
passed before the rejection cases could count as successful. The output has
`full_module_verification: true`; the separate QEMU host-data appraisal
contract was not configured (`appraisal_contract_check: false`). The local EAT
signer is a qualification fixture around real SNP reports, not a deployed
network service identity. The hardware log retained a provider warning about
missing VCEK/VLEK data pages; the full verification still completed successfully.

No Upgrade was performed. One VM and one test job ran at a time. The billing
console still showed a Free Trial account after cleanup, with month-to-date
gross cost **JPY 27**, savings **JPY 27**, and net cost **JPY 0**. This is a
billing snapshot, subject to reporting lag, not a final invoice. The total
USD 5 limit was retained throughout; no ongoing VM, disk or reserved-IP charge
remains from this task.

## GCP CoRIM mismatch and repair — 2026-10-21 JST

The R4 run (2026-10-19 UTC) reached CoRIM appraisal after the direct-SNP
signature, AMD certificate/CRL, challenge and platform-policy checks, but failed
its first fresh positive control with `no matching reference value found in
CoRIM for SNP`. R5 reproduced that failure and recorded the policy comparison.
Neither failed run counts as a successful negative test.

The approved and reported measurement SHA-256 values were both
`0534d2f220aeef2b474d2a21e7bb1af361ae21c3e100b28c626dde6ee9c01b14`.
The Google-signed guest-policy allowance was `0x70000`; the report used
`0x30000`. The only differing bit, bit 18, is `MIGRATE_MA`: the VM disables a
capability that the baseline permits. `go-sev-guest` accepts that restriction,
while ASB's CoRIM policy key intentionally requires an exact integer match.
The preparation helper had incorrectly duplicated the allowance as an exact
CoRIM value.

The new `integrations/cocos/cmd/gcp-firmware-policy` command keeps the signed
allowance in `platform-policy.json`, alongside exact measurement/VMPL and
mandatory AMD certificate and CRL verification. It places the approved
measurement in CoRIM without the erroneous exact policy constraint. Both
outputs are required. The general CoRIM generator and exact-match appraiser
are unchanged.

The root certificate is independently pinned to Google's production root.
The endorsement signature is verified before its per-VMSA measurement can
become a reference value. The candidate report measurement is only a lookup
candidate, not its own source of approval. This establishes firmware launch
identity under the stated policy. It does not establish model, application,
kernel or host-data identity, or enforce an independently approved TCB/guest-SVN
floor. It does not qualify Azure MAA, Intel TDX or a network aTLS handshake.

## Cloud regression checks

The following checks passed sequentially in Google Cloud Shell on 2026-10-20
UTC (2026-10-21 JST), with `GOWORK=off`, `GOMAXPROCS=1`,
`GOMEMLIMIT=512MiB` and `GOFLAGS=-p=1`:

- `go test -p=1 -parallel=1 -count=1 -v ./cmd/gcp-firmware-policy`
- `go vet ./cmd/gcp-firmware-policy`
- `go mod tidy -diff` (no diff after adding required dependency records)
- `go build -p=1 -trimpath -o ../../../gcp-policy-helper-fixed ./cmd/gcp-firmware-policy`

The synthetic paired-policy regression accepts equal and stricter migration
policies. It rejects debug, wrong VMPL, a modified measurement and migration
when the signed platform policy prohibits it. Existing helper controls reject
an untrusted root, malformed/tampered endorsements, a wrong measurement or VMSA
count, missing configuration, debug permission, invalid timestamps and an
expired signer; an existing output directory is preserved.

The initial cloud test stopped at missing transitive checksums for the newly
tracked helper. `go mod tidy` added `github.com/pkg/errors` and `golang.org/x/exp`
at already selected versions, followed by the passing rerun above. No local
build or test was run during this resumed investigation. Local file inspection,
formatting, hashing and Git operations were used.

## Initial discovery — 2026-10-17/18

At this stage, live hardware and Azure validation had not run. The local tests
listed below were preparation only. The later GCP run above supersedes that
hardware status; Azure validation remains unexecuted.

The starting revision is `239d2d4842b04f078c18df1bb999fc3e81d4dcfc`.
Environment discovery on 2026-10-17 found:

| Check | Observed result |
| --- | --- |
| Repository self-hosted runners | GitHub API returned `total_count: 0`. |
| Hardware workflow history | No runs were returned for `hardware-attestation-red-team.yaml`. |
| Local execution host | Darwin, arm64. |
| Local Azure CLI | `az` was not found in PATH. Azure CLI is not required if an already configured VM is available through another connection. |
| Execution target and appraisal inputs | No designated SNP/TDX host, Azure confidential VM, approved MAA issuer/key snapshot, or approved measurement/policy locations were supplied. |

At discovery, the live run was waiting for these execution inputs. A test must use an
independently approved measurement and policy; deriving its allowlist from the
evidence under test would not validate the intended deployment.

## Provisioning attempt — 2026-10-18

The owner authorized a total USD 5 limit for a temporary GCP direct-SNP VM
and an Azure confidential VM, followed by deletion of their VMs, disks, and
IP addresses. After the owner reported excessive local load and an abrupt
stop, work resumed with one operation at a time. No local build or test was
run during this resumed attempt. Future local Go commands are limited to
`GOMAXPROCS=1`, `go ... -p=1`, and test parallelism of one.

| Check or action | Observed result |
| --- | --- |
| Azure authentication | Azure CLI 2.90.0 authenticated successfully; the selected subscription was enabled. |
| Azure service registration | Registered `Microsoft.Compute` and `Microsoft.Quota`. These operations did not create a VM. |
| Central India quota | Regional vCPU limit 10, usage 0; `standardDCASv5Family` limit 0, usage 0. Requesting a limit of 2 returned `QuotaNotAvailableForResource`. |
| East US fallback quota | Regional vCPU limit 10, usage 0; `standardDCASv5Family` limit 0, usage 0. Requesting a limit of 2 returned the same error. |
| GCP authentication | The selected account was signed out. Sign-in stopped at a CAPTCHA identity challenge; no project or billing target was confirmed. |
| Azure resource inventory after the attempts | `az resource list` returned zero resources, including zero VMs, managed disks, and public IP addresses. |
| Provisioning and cleanup | No VM, disk, or IP was created on either provider by this task; there was no test resource to delete. |
| Live evidence and verdicts | NOT RUN. No fresh hardware report or MAA token was collected; neither live success nor live rejection was established. |

No billable test resource was created. A billing export or final invoice was
not checked. The quota errors are provisioning failures, not evidence that
ASB rejected an invalid attestation. Azure documents support requests as the
next route for `QuotaNotAvailableForResource`.
[Azure quota error reference](https://learn.microsoft.com/en-us/rest/api/quota/#troubleshooting-quota-api-errors)

PR #75 at `90a04122cf7e900940660dd170d54ead540b4042` had 39 successful
checks when inspected on 2026-10-18. Those checks cover the preparation code;
they do not establish live qualification. At that point the PR remained a draft pending
the requested live results. Any subsequent commit needs its own CI check.

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

## Remaining platform qualification

The GCP direct-SNP result applies only to the recorded configuration. Other
hardware profiles, including Intel TDX, need their own approved policy and live
positive/negative qualification.

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
