# ASB apt publication on GitHub Pages

The selected destination is
`https://toppymicroservices.github.io/agents-secure-binding`.
The publication workflow is manual and accepts only a reviewed archive from an
`apt-preview-...` release. This documents a publication path, not a claim that
the site or a production signing key has already been configured.

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
| `base_url` | `https://toppymicroservices.github.io/agents-secure-binding` |
| `signers` | One or two complete uppercase 40-character fingerprints |
| `keyring_sha256` | SHA-256 of the exact exported public keyring bytes |

The policy is a reviewed trust anchor, not metadata supplied by the archive.
An unconfigured policy blocks publication. The public keyring must contain
exactly those standalone public keys; secret key material and extra keys are
rejected. Keep an independently protected backup and record its restoration
test before relying on this key for continuing releases. No backup is assumed
to exist merely because key generation succeeded.

## Prepare and review

Use the final Linux-built packages and their successful lifecycle report with
`scripts/asb-apt-repository.py prepare`. Review their source commit and hashes,
then sign that repository offline using the chosen key. See
[Debian packages](asb-debian-packages.md) for the component scopes and existing
prepare/sign/verify commands.

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

Enable GitHub Pages with the Actions source for this repository, and restrict
the `github-pages` deployment environment to the protected `main` branch.
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
