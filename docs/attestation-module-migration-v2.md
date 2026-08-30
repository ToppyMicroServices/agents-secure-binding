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
modules. During development, `integrations/cocos/go.mod` uses local replacements
because the ASB v2 release candidate does not yet exist. Those replacements are
not permitted in a Cocos module release.

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

## Release order

1. Merge the boundary and module changes after pull-request CI passes.
2. Run the `Attestation Release Gate` manually with target `all` on the merged
   commit. This runs the root and nested-module preflight plus the Cocos
   development gate; the Cocos release gate remains blocked while replacements
   are present.
3. Sign and push `modules/attestation/snp/v0.1.0` and
   `modules/attestation/tdx/v0.1.0` on the same immutable merged commit.
4. Wait for each tag-triggered gate to verify the annotated tag, its target
   commit, `main` ancestry, module metadata, and tests.
5. Verify the root with `GOWORK=off`; its module graph must contain no Cocos,
   SNP-module, or TDX-module dependency.
6. Sign and push `v2.0.0-rc.1`. Wait for its tag-triggered gate to succeed, then
   create the prerelease from that existing remote tag:

   ```sh
   gh release create v2.0.0-rc.1 \
     --verify-tag --prerelease --latest=false \
     --title "v2.0.0-rc.1" \
     --notes "Release candidate only. SNP, TDX, and Cocos hardware qualification is incomplete; no production-ready claim is made."
   ```

7. After the root RC exists, replace the temporary Cocos development versions
   with the published root and platform versions, remove all replacements, and
   pass `make check-cocos-release` plus pull-request CI.
8. Sign and push `integrations/cocos/v0.1.0`, then wait for its tag-triggered
   gate to succeed before creating any Cocos release.

The root RC release notes must say that hardware qualification is incomplete.
The RC does not assert that SNP, TDX, or the Cocos integration is
production-ready.
