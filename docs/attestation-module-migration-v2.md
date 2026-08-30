# Attestation module migration for ASB v2

## Decision

ASB v2 accepts injected platform-neutral evidence sources and verifiers. It no
longer constructs a hardware verifier from a policy path or selects a platform
from peer evidence.

The public dependency graph is intentionally one-way:

```text
modules/attestation/snp v0.x ----\
                                      -> integrations/cocos v0.x
modules/attestation/tdx v0.x ----/                ^
                                                   |
ASB root /v2 --------------------------------------+
```

ASB root has no dependency on the Cocos integration or the two platform
modules. Before the ASB v2 release candidate existed,
`integrations/cocos/go.mod` used local replacements for development. The Cocos
module now resolves the published root and platform versions without local
replacements.

## API migration

The v1 evidence provider accepted a concrete attestation-service client and a
platform. In v2, adapt the deployment client to `EvidenceSource` and inject it:

```go
source, err := evidencesource.NewEvidenceSource(attestationClient, localPlatform)
if err != nil {
    return err
}

provider, err := atls.NewProvider(source)
```

The v1 `atls.NewEvidenceVerifier(policyPath)` constructor is removed. A path
does not specify an EAT trust key, issuer, platform, collateral source,
revocation behavior, or measurement policy. Cocos deployments construct
`platformmodule.NewEvidenceVerifier` in the external integration module and
inject it through `eaattestation.VerificationPolicy`.

There is no v1-shaped v2 overload. Applications that need the old constructor
can remain on the v1.1.x line while updating their composition root.

The root `make` target no longer builds the Cocos agent. Build the moved
command with `make -C integrations/cocos agent`; it preserves the
`agents-secure-binding-agent` binary name used by the inherited systemd
packaging files. The standalone ingress command was removed because the Cocos
agent owns and starts the per-computation ingress proxy.

## Current release state

The platform-neutral root is published as the `v2.0.0-rc.1` prerelease. The
experimental platform modules are published as SNP `v0.1.0` and TDX `v0.1.1`.
The Cocos module resolves these published versions without local replacements.

Before the first Cocos tag, pass `make check-cocos-release` and pull-request CI,
then merge the dependency update. Run the manual `Attestation Release Gate`
with target `cocos` on the exact merged commit. Only after that gate succeeds,
sign and push `integrations/cocos/v0.1.0` and wait for its tag-triggered gate.

The root RC and the Cocos tag do not establish live SNP or TDX qualification or
production readiness.
