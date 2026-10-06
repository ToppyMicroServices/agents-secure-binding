# ASB apt publication on GitHub Pages

The selected GitHub Pages destination is
`https://www.toppymicros.com/agents-secure-binding`.
This project [inherits the organization's custom domain](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/about-custom-domains-and-github-pages).
On 2026-10-05 the
repository Pages API returned that URL with `build_type: workflow` and HTTPS
enforced. No DNS or organization-site configuration was changed. The verifier
uses this exact destination and rejects redirects.

The publication workflow is manual and accepts only a reviewed archive from an
`apt-preview-...` release. Configuring Pages does not establish that signed
packages have been deployed or that public delivery has passed verification.

## Trust and key custody

Keep the encrypted archive signing key outside this checkout and outside
GitHub Actions. Do not reuse the ephemeral CI keys as a production identity.
The narrow supported profile uses a dedicated standalone signing key, without
subkeys. A rotation may temporarily authorize two such keys.

Commit `packaging/debian/archive-signers.json` only after selecting the real
key. It must have exactly these fields:

| Field | Value |
| --- | --- |
| `schema` | `asb.apt-pages-policy/v1` |
| `base_url` | `https://www.toppymicros.com/agents-secure-binding` |
| `signers` | One or two complete uppercase 40-character fingerprints |
| `keyring_sha256` | SHA-256 of the exact exported public keyring bytes |

The policy is a reviewed trust anchor, not metadata supplied by the archive.
An unconfigured policy blocks publication. The public keyring must contain
exactly those standalone public keys; secret key material and extra keys are
rejected. Keep an independently protected backup and record its restoration
test before relying on this key for continuing releases. No backup is assumed
to exist merely because key generation succeeded.

## Prepare and review

Use the manual **ASB unsigned apt release preparation** workflow on `main` to
prepare fresh metadata from an existing successful **ASB Debian distribution**
run. Supply that run's numeric ID and its full source commit:

```sh
gh workflow run apt-release-prepare.yaml --ref main \
  -f qualification_run_id="$QUALIFIED_RUN" -f source_commit="$SOURCE_COMMIT"
```

The source must already be an ancestor of the workflow's `main` commit. The
preparation job checks the authenticated GitHub API run record, repository,
workflow path, successful completion and exact source. It selects one unexpired
artifact named `asb-debian-RUN_ID`, verifies its GitHub SHA-256 and size, and
reads only the new-source package set and matching Linux lifecycle evidence.
Missing checks, changed package bytes, unsafe archive members and ambiguous
artifact identities fail preparation.

Download `asb-apt-unsigned-PREPARATION_RUN_ID` from the successful preparation
run. It contains `repository/`, the candidate and lifecycle records in
`evidence/`, `prepare-report.json` and `SHA256SUMS`. Check the source/run IDs,
package hashes and checksum inventory before signing. The report binds the
original qualification artifact to the prepared files. This uses GitHub's
artifact identity and the recorded Linux results; it is not independent proof
of a reproducible build.

Metadata is created on Linux with seven days of validity. Preparation uses the
qualified package bytes without rebuilding or installing them and has no
signing key or publication permission. Existing package and component limits
continue to apply. An expired CI snapshot cannot be reused as a fresh signed
repository; prepare a new unsigned snapshot from the qualified payload.

Sign `repository/` offline with the dedicated key, then run the existing
signature verifier against the independently selected public keyring. See
[Debian packages](asb-debian-packages.md) for the component scopes and
prepare/sign/verify commands. The `asb-apt-repository.py prepare` command also
remains available on Linux for an operator-managed preparation environment.

The following commands use operator-provided paths and identifiers:

```sh
python3 scripts/asb-apt-pages.py stage \
  --policy packaging/debian/archive-signers.json --source-commit "$SOURCE_COMMIT" \
  --repository "$SIGNED_REPOSITORY" --keyring "$PUBLIC_KEYRING" --output "$SITE"
python3 scripts/asb-apt-pages.py pack \
  --policy packaging/debian/archive-signers.json --source-commit "$SOURCE_COMMIT" \
  --site "$SITE" --output "$ARCHIVE_DIRECTORY/asb-apt-site.tar"
```

Record the reported whole-archive SHA-256 independently. Inspect the generated
page and final archive. Publish only this tar file as the selected release
asset. The archive contains the apt repository, public keyring, source file,
generated page and inventory. It cannot include arbitrary HTML, credentials,
logs, symlinks or extra files. All verification and packing use private captured
snapshots to bind the checked signatures to the actual bytes.

## Deploy and inspect the public result

Keep GitHub Pages configured with the Actions source, and restrict the
`github-pages` deployment environment to the protected `main` branch.
Dispatch `ASB apt Pages publication` on `main` with the release tag, archive
hash and qualified source commit. The source must be an ancestor of the
publication workflow's commit.

The preparation job has read access only. It authenticates the archive against
the committed policy before uploading a Pages artifact. Only the deployment
job receives `pages:write` and `id-token:write`. A separate job verifies the
saved archive again and compares every published file over HTTPS, rejecting
redirects, changed content and extra response bytes. A successful deployment
with a failed readback is **not verified publication**; inspect the saved
per-attempt evidence before reporting availability.

Finally, inspect the rendered page and retain the workflow ID, archive hash,
public fingerprint, source commit and HTTPS evidence. The workflow does not
send email, create AWS resources, install a service, or upload private keys.

## Continuing operation

Metadata expires within seven days. Renew and resign it before expiry using
the same reviewed payload, or qualify a new source and package version. The
workflow does not renew signatures automatically. Do not disable apt date or
signature checks to work around expired metadata.

Key rotation needs an overlapping public keyring update before publishing
metadata signed only by the new key. Removing the old key is a separate
operator action. A still-valid older signed repository can be replayed within
its validity window; these checks do not establish a global monotonic release
counter. GitHub Pages availability and an operator's long-term recovery
procedures remain separate from the bounded Linux CI tests.

CI exercises the actual signed package archive using ephemeral keys and does
not publish it. Its report explicitly records that HTTPS delivery and the
production key are not exercised.
