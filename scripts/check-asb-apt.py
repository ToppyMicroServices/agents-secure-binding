#!/usr/bin/env python3
"""Qualify apt delivery in disposable Linux containers using ephemeral test keys."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import uuid

spec = importlib.util.spec_from_file_location("asb_apt", Path(__file__).with_name("asb-apt-repository.py"))
apt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(apt)

EXERCISE = r'''
set -eu
export DEBIAN_FRONTEND=noninteractive
mark() { printf 'ASB_APT_PHASE=%s\n' "$1"; }
mkdir -p /etc/apt/keyrings
rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*
source_repo() {
  cat >/etc/apt/sources.list.d/asb.sources <<EOF
Types: deb
URIs: file:/repositories/$1
Suites: asb-preview
Components: main
Architectures: amd64
Signed-By: /etc/apt/keyrings/asb-archive.gpg
Check-Valid-Until: yes
Check-Date: yes
EOF
  rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb
}
update() { apt-get -o APT::Update::Error-Mode=any -o Acquire::Retries=0 update; }
reject_update() {
  mark "$1"
  source_repo "$2"
  if update >/tmp/apt-rejection 2>&1; then exit 31; fi
  if ! grep -E -i "$3" /tmp/apt-rejection >/dev/null; then cat /tmp/apt-rejection; exit 33; fi
}
cp /keys/a.gpg /etc/apt/keyrings/asb-archive.gpg
chmod 644 /etc/apt/keyrings/asb-archive.gpg
mark authenticated-install
source_repo initial
update
apt-get install -y --no-install-recommends asb asb-human asb-s3
test "$(dpkg-query -W -f='${Version}' asb-tools)" = "$ASB_VERSION_INITIAL"
test ! -e /etc/systemd/system/asb-s3.service
test ! -e /usr/lib/systemd/system/asb-s3.service
test ! -e /etc/asb-s3/config.json
mark retain-human-state
export HOME=/tmp/asb-apt-home
mkdir -m 700 "$HOME"
state=/tmp/asb-human-persisted
server_pid=
stop_server() {
  kill -INT "$server_pid"
  wait "$server_pid"
  server_pid=
}
trap 'if test -n "$server_pid"; then kill -KILL "$server_pid" 2>/dev/null || :; fi' EXIT
start_server() {
  : >/tmp/asb-ready
  asb-human serve --data-dir "$state" --core-listen 127.0.0.1:0 --web-listen 127.0.0.1:0 >/tmp/asb-ready 2>/tmp/asb-private-login &
  server_pid=$!
  attempts=0
  address=
  while test -z "$address"; do
    kill -0 "$server_pid"
    address=$(sed -n 's/.*"core_address":"\([^"]*\)".*/\1/p' /tmp/asb-ready)
    attempts=$((attempts + 1))
    test "$attempts" -le 300
    if test -z "$address"; then sleep 0.1; fi
  done
}
start_server
asb-human agent --data-dir "$state" --core-address "$address" --operation-id apt-preserved --enabled=true >/tmp/asb-proposal
receipt="$state/receipts/proposal-apt-preserved.json"
test -f "$receipt"
stop_server
find "$state" -type f -exec sha256sum {} + | sort >/tmp/state-before
find "$state" -printf '%y %m %u %g %p\n' | sort >/tmp/modes-before
mkdir -p /var/lib/asb-s3
printf 'operator state\n' >/var/lib/asb-s3/marker
reject_update unannounced-key-rejected upgrade 'NO_PUBKEY|public key is not available'
mark overlap-keyring-upgrade
cp /keys/ab.gpg /etc/apt/keyrings/asb-archive.gpg
source_repo upgrade
update
apt-get install -y --no-install-recommends asb asb-human asb-s3
for package in asb asb-tools asb-human asb-s3; do
  test "$(dpkg-query -W -f='${Version}' "$package")" = "$ASB_VERSION_UPGRADE"
done
find "$state" -type f -exec sha256sum {} + | sort >/tmp/state-after
cmp /tmp/state-before /tmp/state-after
find "$state" -printf '%y %m %u %g %p\n' | sort >/tmp/modes-after
cmp /tmp/modes-before /tmp/modes-after
test "$(cat /var/lib/asb-s3/marker)" = 'operator state'
mark receipt-recovers-after-upgrade
start_server
asb-human inspect --data-dir "$state" --core-address "$address" --receipt "$receipt" >/tmp/asb-recovered
grep -q '"state":"PENDING_REVIEW"' /tmp/asb-recovered
stop_server
mark retired-key-removed
cp /keys/b.gpg /etc/apt/keyrings/asb-archive.gpg
source_repo upgrade
update
reject_update old-key-rejected old-key 'NO_PUBKEY|public key is not available'
reject_update unknown-key-rejected unknown-key 'NO_PUBKEY|public key is not available'
reject_update unsigned-rejected unsigned 'not signed|signatures'
reject_update signature-tamper-rejected signature-tamper 'invalid|signature|BADSIG'
reject_update index-tamper-rejected index-tamper 'Hash Sum mismatch|unexpected size'
reject_update expired-metadata-rejected expired 'expired'
reject_update future-metadata-rejected future 'not valid yet'
mark package-tamper-rejected
source_repo package-tamper
update
if apt-get install -y --reinstall --no-install-recommends asb-tools >/tmp/package-rejection 2>&1; then exit 32; fi
grep -E -i 'Hash Sum mismatch|unexpected size' /tmp/package-rejection >/dev/null
mark final-installed-state
test "$(dpkg-query -W -f='${Version}' asb-tools)" = "$ASB_VERSION_UPGRADE"
test ! -e /etc/systemd/system/asb-s3.service
test ! -e /usr/lib/systemd/system/asb-s3.service
printf 'ASB_APT_PASS\n'
'''


def run(*args: str) -> bytes:
    return subprocess.check_output(args, stderr=subprocess.PIPE, timeout=300)


def create_key(home: Path, label: str) -> str:
    home.mkdir(mode=0o700)
    run("gpg", "--homedir", str(home), "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
        "--quick-generate-key", f"ASB ephemeral apt {label} <apt-{label}@example.invalid>", "ed25519", "sign", "1d")
    output = run("gpg", "--homedir", str(home), "--batch", "--with-colons", "--list-keys").decode()
    identities = [line.split(":")[9] for line in output.splitlines() if line.startswith("fpr:")]
    if len(identities) != 1:
        raise ValueError("unexpected ephemeral key count")
    return apt.fingerprint(identities[0])


def sign_fixture(repository: Path, home: Path, identity: str) -> None:
    """Negative fixtures intentionally bypass the production date gate."""
    for name, kind in (("InRelease", "--clearsign"), ("Release.gpg", "--detach-sign")):
        target = repository / apt.DIST / name
        target.unlink(missing_ok=True)
        run("gpg", "--homedir", str(home), "--batch", "--local-user", identity + "!", "--digest-algo", "SHA256",
            "--output", str(target), kind, str(repository / apt.DIST / "Release"))


def check(args: argparse.Namespace) -> dict:
    if sys.platform != "linux":
        raise ValueError("apt integration checks run only on Linux")
    evidence_directory = args.output.with_suffix(".evidence")
    if any(path.exists() or path.is_symlink() for path in (args.output, evidence_directory)):
        raise ValueError("refuse to replace existing evidence")
    if not args.image or args.image.startswith("-"):
        raise ValueError("invalid image reference")
    try:
        image = json.loads(run("docker", "image", "inspect", args.image))[0]
    except subprocess.CalledProcessError:
        run("docker", "pull", args.image)
        image = json.loads(run("docker", "image", "inspect", args.image))[0]
    if image.get("Os") != "linux" or image.get("Architecture") != "amd64":
        raise ValueError("apt test image must be Linux amd64")
    now = int(datetime.now(timezone.utc).timestamp())
    name = "asb-apt-qa-" + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="asb-apt-qa-") as temporary:
        directory = Path(temporary)
        repositories, keys = directory / "repositories", directory / "keys"
        repositories.mkdir(mode=0o755)
        keys.mkdir(mode=0o755)
        homes, identities = {}, {}
        try:
            for label in ("a", "b", "c"):
                homes[label] = directory / ("gnupg-" + label)
                identities[label] = create_key(homes[label], label)
                (keys / (label + ".gpg")).write_bytes(run("gpg", "--homedir", str(homes[label]), "--batch", "--export-options", "export-minimal", "--export", identities[label]))
            (keys / "ab.gpg").write_bytes((keys / "a.gpg").read_bytes() + (keys / "b.gpg").read_bytes())
            results = {}
            for label, artifacts, evidence, signer in (("initial", args.initial, args.initial_lifecycle, "a"),
                                                        ("upgrade", args.upgrade, args.upgrade_lifecycle, "b")):
                target = repositories / label
                apt.prepare(argparse.Namespace(artifacts=artifacts, lifecycle=evidence, created=now - 1, expires=now + 3600, output=target))
                apt.sign(argparse.Namespace(repository=target, gnupg_home=homes[signer], signer=identities[signer]))
                results[label] = apt.verify(argparse.Namespace(repository=target, keyring=keys / (signer + ".gpg"), signer=[identities[signer]]))
            if results["initial"]["source_commit"] != results["upgrade"]["source_commit"]:
                raise ValueError("this gate qualifies a same-source package revision transition")
            run("dpkg", "--compare-versions", results["initial"]["version"], "lt", results["upgrade"]["version"])
            # Determinism means unsigned metadata, not timestamped OpenPGP signatures.
            repeated = repositories / "repeat"
            apt.prepare(argparse.Namespace(artifacts=args.upgrade, lifecycle=args.upgrade_lifecycle, created=now - 1, expires=now + 3600, output=repeated))
            for relative, payload in apt.metadata(apt.inspect_repository(repeated)).items():
                if payload != (repositories / "upgrade" / relative).read_bytes():
                    raise ValueError("metadata preparation is not deterministic")
            shutil.rmtree(repeated)
            negatives = ("old-key", "unknown-key", "unsigned", "signature-tamper", "index-tamper", "expired", "future", "package-tamper")
            for label in negatives:
                shutil.copytree(repositories / "upgrade", repositories / label)
            sign_fixture(repositories / "old-key", homes["a"], identities["a"])
            sign_fixture(repositories / "unknown-key", homes["c"], identities["c"])
            for filename in ("InRelease", "Release.gpg"):
                (repositories / "unsigned" / apt.DIST / filename).unlink()
            target = repositories / "signature-tamper" / apt.DIST / "InRelease"
            target.write_bytes(target.read_bytes().replace(b"Origin: ASB", b"Origin: BAD", 1))
            for target in (repositories / "index-tamper" / apt.DIST / Path(apt.INDEX).parent).rglob("*"):
                if target.is_file():
                    target.write_bytes(target.read_bytes() + b"tampered")
            for label, created, expires in (("expired", now - 7200, now - 3600), ("future", now + 3600, now + 7200)):
                target = repositories / label
                manifest = apt.strict_json(apt.read(target / apt.DIST / "manifest.json"))
                manifest.update(created=created, expires=expires)
                for relative, payload in apt.metadata(manifest).items():
                    (target / relative).write_bytes(payload)
                sign_fixture(target, homes["b"], identities["b"])
            target = next((repositories / "package-tamper/pool/main/a/asb").glob("asb-tools_*.deb"))
            with target.open("ab") as stream:
                stream.write(b"tampered")
            for label in negatives:
                try:
                    apt.verify(argparse.Namespace(repository=repositories / label, keyring=keys / "b.gpg", signer=[identities["b"]]))
                except (ValueError, OSError, subprocess.SubprocessError):
                    pass
                else:
                    raise ValueError("repository verifier accepted negative fixture: " + label)
            # Only public keys and snapshots are mounted. Test private keys never
            # enter the container or uploaded evidence and are destroyed below.
            for path in keys.iterdir():
                path.chmod(0o644)
            checked = subprocess.run(
                ["docker", "run", "--rm", "--interactive", "--name", name, "--network", "none",
                 "--mount", f"type=bind,src={repositories},dst=/repositories,readonly",
                 "--mount", f"type=bind,src={keys},dst=/keys,readonly", "--env", "ASB_VERSION_INITIAL=" + results["initial"]["version"],
                 "--env", "ASB_VERSION_UPGRADE=" + results["upgrade"]["version"], "--entrypoint", "/bin/sh", image["Id"], "-s"],
                input=EXERCISE.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600, check=False)
            phases = [line.removeprefix(b"ASB_APT_PHASE=").decode() for line in checked.stdout.splitlines() if line.startswith(b"ASB_APT_PHASE=")]
            if checked.returncode or not checked.stdout.endswith(b"ASB_APT_PASS\n"):
                # These streams contain only apt diagnostics and phase markers;
                # private Human login links and receipt content are redirected.
                diagnostic = (checked.stdout[-3000:] + checked.stderr[-3000:]).decode(errors="replace")
                raise ValueError(f"isolated apt check failed at {phases[-1] if phases else 'start'} (exit {checked.returncode}): {diagnostic}")
            tools = {name: run(name, "--version").decode().splitlines()[0] for name in ("gpg", "gpgv", "dpkg-deb")}
            # Retain the actual signed metadata and public test keyrings. Package
            # bytes remain in the two original candidate artifacts, avoiding a
            # second copy of each executable in the evidence upload.
            evidence_directory.mkdir(parents=True)
            for label in ("initial", "upgrade"):
                shutil.copytree(repositories / label / "dists", evidence_directory / label / "dists")
            (evidence_directory / "keyrings").mkdir()
            for label in ("a", "b", "ab"):
                shutil.copyfile(keys / (label + ".gpg"), evidence_directory / "keyrings" / (label + ".gpg"))
            metadata_evidence = {str(path.relative_to(evidence_directory)): apt.sha(apt.read(path))
                                 for path in sorted(evidence_directory.rglob("*")) if path.is_file()}
            return {"schema": "asb.apt-lifecycle/v1", "passed": True, "repositories": results,
                    "checks": {phase: True for phase in phases} | {"deterministic_unsigned_metadata": True, "independent_verifier_rejects_all_negative_fixtures": True},
                    "image_requested": args.image, "image_id": image["Id"], "image_repo_digests": image.get("RepoDigests", []),
                    "container_network": "none", "tools": tools, "ephemeral_test_key_fingerprints": identities,
                    "metadata_evidence": {"directory": evidence_directory.name, "sha256": metadata_evidence},
                    "limits": ["ephemeral CI keys; no production key or hosting", "same-source Debian revision upgrade; no schema migration",
                               "container-root test identity; no host installation or systemd", "file transport; HTTPS hosting unqualified",
                               "expiry bounds stale metadata; signed older unexpired metadata may still be replayed", "no AWS or physical power-loss test"]}
        finally:
            subprocess.run(["docker", "rm", "--force", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)
            for home in homes.values():
                subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "all"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("initial", "initial-lifecycle", "upgrade", "upgrade-lifecycle", "output"):
        parser.add_argument("--" + flag, type=Path, required=True)
    parser.add_argument("--image", default="ubuntu:24.04")
    args = parser.parse_args()
    try:
        result = check(args)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x") as stream:
            json.dump(result, stream, indent=2, sort_keys=True)
            stream.write("\n")
        print(json.dumps({"passed": True, "evidence": str(args.output)}))
        return 0
    except (ValueError, OSError, KeyError, TypeError, IndexError, subprocess.SubprocessError) as error:
        print(f"apt check rejected: {error if not isinstance(error, subprocess.SubprocessError) else 'subprocess failed'}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
