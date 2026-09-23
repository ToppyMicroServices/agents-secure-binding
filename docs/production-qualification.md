# Production qualification bundles

`scripts/asb-qualification.py` binds a named profile to a source commit, Git
tree, target environment, required checks, redacted logs, and SHA-256 manifest.
A dirty working tree, a wrong target OS, an unavailable required executable, a
failed check, or secret-like output makes the qualification result fail.
The profile must be tracked, below the source root, and byte-identical to its
`HEAD` version. The output directory must be outside the source tree. A dirty
tree is rejected before any profile command runs.
Checks run in a temporary detached worktree for the recorded commit. The
qualification does not execute commands from the caller's mutable checkout.

Run a profile on the target it claims to exercise:

```text
python3 scripts/asb-qualification.py run \
  --profile qualification/profiles/local-human-preview.json \
  --source-root . \
  --output /private/qualification/asb-local-human
```

A successful run records `status: passed`, but it remains an unsigned evidence
bundle with `qualificationClaim: false`. On the qualification target, an
authorized operator can turn that evidence into a claim by signing it with a
full OpenPGP fingerprint:

```text
python3 scripts/asb-qualification.py sign \
  --bundle /private/qualification/asb-local-human \
  --signing-key FULL_OPENPGP_FINGERPRINT
```

Sign only a freshly produced bundle kept under private custody. The signer
attests to the recorded checks; the signing command does not rerun them.

Verify a signed claim from a separate checkout or host, with the authorized
signer configured explicitly:

```text
python3 scripts/asb-qualification.py verify \
  --bundle /private/qualification/asb-local-human \
  --trusted-signer FULL_OPENPGP_FINGERPRINT
```

The output contains `qa-report.json`, a canonical copy of the profile, bounded
stdout/stderr logs, and `SHA256SUMS`. A signed claim also contains
`SHA256SUMS.asc`. The verifier rejects missing, added, modified, unsigned, or
wrong-signer claim files. Unsigned passing and failed bundles remain verifiable
as non-claim evidence without `--trusted-signer`; their `qualificationClaim`
stays false.

The checked-in profiles are intentionally narrow:

- `local-human-preview` exercises the local Human application on the recorded
  macOS, Linux, or Windows runtime.
- `linux-service` requires a Linux target with systemd and checks the dedicated
  service-user units.
- `windows-runner` must run on Windows. A macOS/Linux cross-build does not pass
  this profile.

Live SNP/TDX, managed Redis/Valkey, browser, disk-loss, and provider profiles
must be added only with concrete target commands and acceptance criteria. The
harness does not create those environments and does not turn a preview result
into independent certification. Store bundles in a private evidence location;
even redacted test logs may contain operational metadata.
