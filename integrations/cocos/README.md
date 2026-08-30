# Cocos attestation integration for ASB

This nested Go module keeps the legacy Cocos evidence envelope and platform
appraisal composition outside the ASB v2 core. It adapts Cocos evidence
collection and verification to the platform-neutral interfaces in
`pkg/atls/eaattestation`.

The integration is experimental. It is not production-qualified, and no live
AMD SEV-SNP or Intel TDX hardware qualification has been completed for this
version. Passing its offline tests does not establish current vendor
collateral availability, deployment key custody, launch-policy correctness, or
production readiness.

## Boundary

ASB owns TLS-exporter, session, nonce, identity, and replay binding. This module
owns the Cocos-specific composition around signed EAT envelopes, local CoRIM
reference values, and the selected platform verifier.

- `evidencesource` implements `eaattestation.EvidenceSource` over the minimal
  legacy Cocos attestation-client method.
- `platformmodule` implements `eaattestation.EvidenceVerifier` and delegates
  direct quote verification to the independent SNP or TDX module.

The public `evidencesource` and `platformmodule` adapter surface supports direct
AMD SEV-SNP and Intel TDX evidence only. SNP-vTPM, standalone vTPM, and Azure
evidence cannot be selected through those adapters. The moved legacy Cocos
commands still contain unrelated runtime compatibility code; that code is not
part of the attestation-module support claim.

The deployment selects one platform from trusted local configuration. A
platform name supplied by peer evidence cannot select a verifier.

The moved runtime command reads `ASB_ATTESTATION_PLATFORM` (`snp`, `tdx`,
`auto`, or `none`). `auto` probes direct SNP and TDX devices only and ignores
vTPM and cloud-metadata signals; if both direct devices appear, startup fails
until one is selected explicitly.

## Dependency and development wiring

This module resolves published ASB v2, SNP, and TDX module versions without
local `replace` directives. Repository development may use the root `go.work`,
but release checks run with `GOWORK=off` so the nested module is verified
independently.

Run the hardware-independent tests with the workspace disabled:

```sh
GOWORK=off go test ./...
```

Build the moved Cocos commands independently from the root release build:

```sh
make -C integrations/cocos
```

The agent binary is written to
`integrations/cocos/build/agents-secure-binding-agent`. Legacy files under
root `init/systemd` still refer to that binary name, but they are inherited
packaging inputs and are not built by the ASB root `make` target.

These tests use deterministic fixtures and do not access `/dev/sev-guest`,
`/dev/tdx_guest`, a TPM, AMD KDS, or Intel PCS.

## Remaining release steps

The first Cocos tag uses ASB `v2.0.0-rc.1`, SNP `v0.1.0`, and TDX `v0.1.1`.
After these versions are recorded in `go.mod` and `go.sum`:

1. Pass `make check-cocos-release` and pull-request CI.
2. Merge the dependency update.
3. Run the manual `Attestation Release Gate` with target `cocos` on the exact
   merged commit and confirm that it succeeds.
4. Sign and push `integrations/cocos/v0.1.0`.
5. Wait for the tag-triggered Cocos gate before creating a release.

The Cocos tag remains experimental. It does not establish live SNP or TDX
qualification or production readiness.
