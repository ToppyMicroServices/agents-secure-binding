# ASB attestation module boundary

Status: implemented for the v2 release candidate. The boundary and deterministic
fixtures can be tested without confidential-computing hardware. The SNP and TDX
modules remain experimental `v0.x`; neither has completed live qualification.

## Ownership

ASB owns session and identity binding. It derives `REPORT_DATA` and the nonce
from the accepted TLS 1.3 session, verifies the exported-authenticator binder,
and fails closed when evidence is present without an injected verifier.

The platform modules own quote parsing, endorsement and collateral checks, TCB
and debug policy, measurements, and comparison with the `REPORT_DATA` supplied
by ASB. A deployment selects one platform locally. Peer evidence cannot select
an appraiser.

The Cocos-specific composition is a separate nested module:

```text
ASB v2 core
  -> eaattestation.EvidenceSource and EvidenceVerifier only

integrations/cocos
  -> ASB v2 interfaces
  -> modules/attestation/snp or modules/attestation/tdx
  -> legacy EAT and CoRIM compatibility appraisers
```

The platform-neutral ASB core package set must not import `integrations/cocos`
or either nested platform module. This keeps the IETF-facing protocol path
testable on a MacBook and ordinary CI without Cocos or vendor hardware
dependencies. The repository root still contains legacy platform and runtime
packages; the core boundary check is not a claim that every root package is
platform-neutral.

`integrations/cocos` verifies the signed EAT envelope and then verifies the raw
hardware evidence. An EAT signature does not replace quote authentication,
endorsement validation, collateral and revocation checks, or local platform
policy.

## Current evidence

The SNP module accepts the provider's `sevsnp.Attestation` protobuf and the AMD
ABI report with an optional certificate table. Its deterministic fixture covers
successful signature and policy verification plus negative binding, signature,
measurement, and debug-policy cases. This fixes the former direct-SNP format
mismatch, but it is not a live AMD result.

The TDX module has a deterministic QuoteV4 authentication and local-policy
success fixture. A strict collateral fixture reaches TCB appraisal and is
rejected for a TCB mismatch. There is no strict collateral success fixture and
no live TDX result.

The compatibility appraisers use repository-local CoMID measurement keys.
They are not IETF-assigned code points and do not define a portable SNP or TDX
CoMID profile.

## Test lanes

MacBook and ordinary CI:

```sh
make test-asb-core
(cd modules/attestation/snp && GOWORK=off go test -race ./... && GOWORK=off go vet ./...)
(cd modules/attestation/tdx && GOWORK=off go test -race ./... && GOWORK=off go vet ./...)
(cd integrations/cocos && GOWORK=off go test -race ./... && GOWORK=off go vet ./...)
```

These tests use fixtures and injected collateral. They do not collect a quote
from `/dev/sev-guest` or a TDX guest device.

Live qualification belongs to a separate self-hosted CI or RunPod-style lane.
The runner is usable only if the guest exposes the required device and the
verifier can retrieve matching vendor collateral. A GPU instance name alone is
not evidence of SNP or TDX availability. Qualification must retain the runner
image, platform policy, verifier version, collateral result, and test hashes.

Passing offline tests supports the module boundary and deterministic appraisal
claims only. It does not make the platform modules production-ready.
