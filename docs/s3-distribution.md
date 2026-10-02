# Linux S3 distribution candidate

`asb-s3-v0.1.0-rc.1` is the first **S3 component distribution candidate**.
It does not change the ASB Go module version or promote other ASB components.
The [ASB-wide Linux distribution plan](asb-linux-distribution.md) identifies
the other tools, libraries and optional service profiles.
This document does not announce a published release. The archive contains the
exact live-qualified binary from [run 36711947746](https://github.com/ToppyMicroServices/agents-secure-binding/actions/runs/36711947746),
plus operations documentation, service files, an invalid-placeholder configuration
example, a target acceptance template and dependency notices. It includes no
credentials, private fixtures, keys, databases or object contents.

## Platform and evidence

The reference platform is **Ubuntu 24.04, amd64, systemd**. The ELF binary uses
`/lib64/ld-linux-x86-64.so.2`; it is not a static or universal Linux build.
Install AWS CLI v2 separately; reference qualification used 2.36.49.
The unit needs a dedicated `asb-s3` user, local durable storage and an externally
managed OIDC token projector. Other distributions, architectures and identity
issuers need their own acceptance evidence.

The binary SHA-256 is
`2cbe370f759d7f5cb7da2b19b2057d7f26b540bde05b6e330a478eea55420c19`.
Its source is `1b971fb9f73e9cc46906dd3db79a0c150aa70ec8`, with Go 1.26.6.
The embedded `vcs.modified=true` remains visible. The qualification workflow
created untracked evidence before building; this candidate makes no clean-VCS
or reproducible-binary claim. Packaging copies these bytes without rebuilding.
A new build needs its own qualification; matching source alone does not transfer
the tests. [qualification.json](../packaging/s3/qualification.json) records
the bounded Linux/AWS results and original report digests.

## Prepare and verify

Maintainers obtain the binary from the recorded GitHub artifact
`asb-s3-linux-36711947746`. Run from a reviewed checkout with Go 1.26.6:

```sh
mkdir -p build/s3-distribution
gh run download 36711947746 --repo ToppyMicroServices/agents-secure-binding \
  --name asb-s3-linux-36711947746 --dir build/s3-distribution/reference
python3 scripts/package-s3.py create \
  --binary build/s3-distribution/reference/asb-s3 \
  --output build/s3-distribution/asb-s3-v0.1.0-rc.1-linux-amd64.tar.gz
```

The packager refuses different binary bytes or changed qualified service files.
It records the packaging commit separately and copies license/notice files for
the binary's nine module dependencies and Go runtime. It checks the Go module
cache; missing modules may be downloaded through Go's configured proxy.
The source links and `modules.json` identify exact versions and module checksums;
this is an inventory, not a standardized SBOM or a vulnerability attestation.
The output must not already exist. A dirty packaging tree is recorded and must
be resolved before signing a distribution intended for others.

An authorized maintainer signs the final archive, using their full signing-key
fingerprint. A Git commit signature alone does not sign a binary archive.

```sh
gpg --armor --detach-sign --local-user FULL_SIGNING_KEY_FINGERPRINT \
  build/s3-distribution/asb-s3-v0.1.0-rc.1-linux-amd64.tar.gz
```

Recipients obtain the public key and expected fingerprint through a trusted
channel. A key delivered beside the archive does not establish trust by itself.
From an independently trusted checkout, verify **before extracting**:

```sh
python3 scripts/package-s3.py verify asb-s3-v0.1.0-rc.1-linux-amd64.tar.gz \
  --signature asb-s3-v0.1.0-rc.1-linux-amd64.tar.gz.asc \
  --trusted-signer FULL_TRUSTED_PRIMARY_OR_SIGNING_KEY_FINGERPRINT
tar -xzf asb-s3-v0.1.0-rc.1-linux-amd64.tar.gz
```

Keep both files in a private, non-writable-by-others staging directory throughout
verification and extraction. The verifier checks the loaded archive bytes,
authorized signer, complete file inventory, hashes and modes. It refuses links,
path traversal, duplicate members and oversized bundles, and does not extract
or execute anything. The qualification record must equal the one in the trusted
checkout; use the reviewed packaging revision for this candidate. Signed
verification also rejects a dirty or unspecified packaging-tree state.
Verification without the signature options checks only
integrity and reports `signature_verified: false`; it does not authenticate a
download. Never trust a verifier from an unauthenticated archive.

## Installation, recovery and release decision

Inside the extracted directory, install `bin/asb-s3` in place of the build step
in the [operations runbook](least-privilege-s3-product.md#provision-a-linux-host).
Use its dedicated-user, file-permission, identity-projector and systemd steps.
Fill the configuration placeholders and provide separately authorized profiles,
mandates and PKI. Do not start the example unchanged. Installation never grants
new IAM permissions or recreates execution history.

For an upgrade, drain and stop the old service, retain a sealed backup and the
old binary hash, verify the replacement, then follow the recorded configuration
and recovery procedure. Do not roll a journal back or run copied authorities
concurrently. If compatibility has not been demonstrated for a different binary,
stop and review it; a code rollback does not permit execution-history rollback.
The runbook covers fencing, `UNKNOWN` inspection, backup and namespace-rotating
restore. The [target acceptance record](s3-deployment-acceptance.md) remains
separate from reference qualification.

Before publication, review the final archive and signature, its packaging commit,
included notices and Linux distribution check result. Publish those exact bytes
under the S3 component version with their digest and source, without rebuilding.
GitHub Actions artifacts can expire and are not a permanent release channel.
Publication and organization rollout are explicit later decisions.
