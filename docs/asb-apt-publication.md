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

Keep private signing keys outside this checkout and outside GitHub Actions.
An existing hardware-backed OpenPGP signing subkey can sign the archive without
exporting its private key or changing its PIN. Do not reuse the ephemeral CI
keys as a production identity. A dedicated archive key separates its rotation
and revocation from Git signing, but APT does not require a new key.

Commit `packaging/debian/archive-signers.json` only after selecting the real
key. The original standalone-key profile has exactly these fields:

| Field | Value |
| --- | --- |
| `schema` | `asb.apt-pages-policy/v1` |
| `base_url` | `https://www.toppymicros.com/agents-secure-binding` |
| `signers` | One or two complete uppercase 40-character fingerprints |
| `keyring_sha256` | SHA-256 of the exact exported public keyring bytes |

For signing subkeys, use `schema: asb.apt-pages-policy/v2` and add
`subkey_primaries`, a mapping from each approved signing-subkey fingerprint to
its primary-key fingerprint. `signers` still contains only the exact keys
allowed to sign the archive. The keyring must contain those subkeys and their
specified primary keys, with no other keys or subkeys. The primary key binds
the subkey's identity; it is not thereby authorized to sign the archive.
The generated APT source also pins each signing fingerprint with `!` so client
verification uses the same exact signer restriction.

The policy is a reviewed trust anchor, not metadata supplied by the archive.
An unconfigured policy blocks publication. Secret key material and extra keys
are rejected. GnuPG verifies signatures and subkey bindings; a matching email
address alone does not select a trusted signer. Key recovery remains an
operator responsibility. Record a tested backup or replacement-key plan for
continued releases; successful publication does not establish recoverability.

The current policy selects the existing `okutomi@pm.me` signing subkey:

- Primary: `47AF4750A71D3D1641AB857A867DD812CCE94EBF`.
- Allowed signer: `EC470317CE4DA1F9237B3D7840FF815AEF7C0197`.

Export only the required public pair from the operator's existing keyring:

```sh
gpg --batch --export-options export-minimal \
  --export-filter 'drop-subkey=fpr <> EC470317CE4DA1F9237B3D7840FF815AEF7C0197' \
  --export 47AF4750A71D3D1641AB857A867DD812CCE94EBF > asb-archive.gpg
```

This filters the exported public file; it does not delete or modify keys in
the operator's keyring or hardware token. Check its hash against the committed
policy before staging. Sharing this signer with Git also shares its expiry
and revocation lifecycle. The current approval does not assert a tested backup.

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

Sign `repository/` locally with the approved key, then run the existing
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

After HTTPS byte verification, an isolated APT client fetches the published
index using the generated source and verifies the four expected package
versions. It preserves APT's signature and date checks, installs no packages,
and records its log and result with the publication evidence.

Finally, inspect the rendered page and retain the workflow ID, archive hash,
public fingerprint, source commit and HTTPS evidence. The workflow does not
send email, create AWS resources, install a service, or upload private keys.

## Continuing operation

Metadata expires within seven days. Renew and resign it before expiry using
the same reviewed payload, or qualify a new source and package version. The
workflow does not renew signatures automatically. Do not disable apt date or
signature checks to work around expired metadata.

Key rotation needs an overlapping public keyring update before publishing
metadata signed only by the new key. With v2 exact-signer pinning, also deliver
an authenticated source update containing both `A!` and `B!` fingerprints;
adding B to the keyring alone does not authorize it. After verifying B-signed
updates, remove A from both the keyring and the source. This is a separate
operator action. A still-valid older signed repository can be replayed within
its validity window; these checks do not establish a global monotonic release
counter. GitHub Pages availability and an operator's long-term recovery
procedures remain separate from the bounded Linux CI tests.

Pre-publication package qualification CI exercises the signed package archive
using ephemeral keys and does not publish it. Its report records that HTTPS
delivery and the production key are not exercised. The separate manual Pages
workflow verifies the production-signed archive and its public HTTPS delivery.
