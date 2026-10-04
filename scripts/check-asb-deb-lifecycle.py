#!/usr/bin/env python3
"""Exercise final Debian candidates inside a disposable Linux container."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import uuid


EXERCISE = r'''
set -eu
mark() { printf 'ASB_DEB_PHASE=%s\n' "$1"; }
export HOME=/tmp/asb-lifecycle-home
mkdir -m 700 "$HOME"
mkdir -p /var/lib/asb-s3
printf 'existing operator state\n' >/var/lib/asb-s3/retained-marker
set -- /packages/*.deb
mark install
apt-get install -y --no-install-recommends "$@"
test ! -e /etc/asb-s3/config.json
test ! -e /etc/systemd/system/asb-s3.service
test ! -e /usr/lib/systemd/system/asb-s3.service
test ! -e /lib/systemd/system/asb-s3.service
mark command-smoke
agents-secure-binding-cli --help >/tmp/cli-help
asb-leastprivilege demo >/tmp/finite-demo
if asb-leastprivilege solve >/tmp/invalid-solve 2>&1; then exit 21; fi
if asb-leastprivilege-proof check >/tmp/invalid-proof 2>&1; then exit 22; fi
if asb-s3 serve --config /tmp/missing-asb-config.json >/tmp/invalid-s3 2>&1; then exit 23; fi
asb-human self-test --timeout 1m >/tmp/human-self-test
mark create-retained-state
state=/tmp/asb-human-persisted
server_pid=
stop_server() {
  if test -n "$server_pid"; then
    kill -INT "$server_pid"
    wait "$server_pid"
    server_pid=
  fi
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
asb-human agent --data-dir "$state" --core-address "$address" --operation-id deb-preserved --enabled=true >/tmp/asb-proposal
receipt="$state/receipts/proposal-deb-preserved.json"
test -f "$receipt"
stop_server
find "$state" -type f -exec sha256sum {} + | sort >/tmp/state-before
find "$state" -printf '%y %m %u %g %p\n' | sort >/tmp/state-modes-before
test -s /tmp/state-before
verify_state() {
  find "$state" -type f -exec sha256sum {} + | sort >/tmp/state-after
  cmp /tmp/state-before /tmp/state-after
  find "$state" -printf '%y %m %u %g %p\n' | sort >/tmp/state-modes-after
  cmp /tmp/state-modes-before /tmp/state-modes-after
  test "$(cat /var/lib/asb-s3/retained-marker)" = 'existing operator state'
}
# Stop between unpack and configure; this is a package lifecycle cut point,
# not a power-loss or different-schema upgrade experiment.
mark unpack-configure
dpkg --unpack "$@"
dpkg --configure -a
verify_state
mark remove
dpkg --remove asb asb-tools asb-human asb-s3
verify_state
test ! -e /usr/bin/asb-human
test ! -e /usr/bin/asb-s3
mark reinstall
apt-get install -y --no-install-recommends "$@"
verify_state
mark purge
dpkg --purge asb asb-tools asb-human asb-s3
verify_state
mark reinstall-after-purge
apt-get install -y --no-install-recommends "$@"
verify_state
mark recover-retained-receipt
start_server
asb-human inspect --data-dir "$state" --core-address "$address" --receipt "$receipt" >/tmp/asb-recovered
grep -q '"state":"PENDING_REVIEW"' /tmp/asb-recovered
stop_server
printf 'ASB_DEB_LIFECYCLE_PASS\n'
'''


def regular(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("artifact is not a regular file")
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise ValueError("artifact exceeds limit")
    return value


def command(*args: str) -> bytes:
    return subprocess.check_output(args, timeout=300)


def check(args: argparse.Namespace) -> dict:
    if sys.platform != "linux":
        raise ValueError("run the lifecycle check on Linux")
    if args.output.exists() or args.output.is_symlink():
        raise ValueError("refuse to replace existing lifecycle evidence")
    report = json.loads(regular(args.artifacts / "debian-candidates.json", 1024 * 1024))
    expected = {"asb", "asb-tools", "asb-human", "asb-s3"}
    if (report.get("schema") != "asb.debian-candidates/v1" or len(report.get("packages", [])) != 4 or
            {item["package"] for item in report["packages"]} != expected):
        raise ValueError("lifecycle gate requires all four package candidates")
    if not args.image or args.image.startswith("-"):
        raise ValueError("invalid Docker image reference")
    try:
        image = json.loads(command("docker", "image", "inspect", args.image))[0]
    except subprocess.CalledProcessError:
        command("docker", "pull", args.image)
        image = json.loads(command("docker", "image", "inspect", args.image))[0]
    if image.get("Os") != "linux" or image.get("Architecture") != "amd64":
        raise ValueError("lifecycle image must be Linux amd64")
    container = "asb-deb-qa-" + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="asb-deb-qa-") as temporary:
        directory = Path(temporary)
        for item in report["packages"]:
            filename = item["file"]
            if Path(filename).name != filename or not re.fullmatch(r"[a-z0-9+~._-]+\.deb", filename):
                raise ValueError("invalid candidate filename")
            payload = regular(args.artifacts / filename, 256 * 1024 * 1024)
            if len(payload) != item["bytes"] or hashlib.sha256(payload).hexdigest() != item["sha256"]:
                raise ValueError("final Debian candidate differs from recorded bytes")
            (directory / filename).write_bytes(payload)
        try:
            checked = subprocess.run(
                ["docker", "run", "--rm", "--interactive", "--name", container, "--network", "none",
                 "--mount", f"type=bind,src={directory},dst=/packages,readonly", "--entrypoint", "/bin/sh", image["Id"], "-s"],
                input=EXERCISE.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600, check=False,
            )
            if checked.returncode != 0 or not checked.stdout.endswith(b"ASB_DEB_LIFECYCLE_PASS\n"):
                # Never emit the private login link, keys, or fixture documents.
                phases = re.findall(rb"^ASB_DEB_PHASE=([a-z-]+)$", checked.stdout, re.MULTILINE)
                phase = phases[-1].decode() if phases else "container-start"
                raise ValueError(f"container lifecycle failed at {phase} (exit {checked.returncode}); no passing record written")
        finally:
            subprocess.run(["docker", "rm", "--force", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)
    return {
        "schema": "asb.debian-lifecycle/v1", "passed": True, "source_commit": report["source_commit"],
        "version": report["version"], "packages": report["packages"], "image_requested": args.image,
        "image_id": image["Id"], "image_repo_digests": image.get("RepoDigests", []), "container_network": "none",
        "checks": {name: True for name in ("apt_install", "local_command_smoke", "invalid_configuration_denied", "human_self_test", "unpack_then_configure", "remove_preserves_state", "purge_preserves_state", "reinstall_preserves_state", "human_receipt_recovers")},
        "limits": ["same-version replacement only", "container-root test identity", "S3 preservation uses an operator marker, not a live journal", "no systemd activation", "no real AWS", "no physical power loss", "no host package installation"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image", default="ubuntu:24.04")
    args = parser.parse_args()
    try:
        result = check(args)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x") as stream:
            json.dump(result, stream, indent=2, sort_keys=True)
            stream.write("\n")
        print(json.dumps({"passed": True, "evidence": str(args.output), "image_id": result["image_id"]}))
        return 0
    except (ValueError, OSError, KeyError, TypeError, IndexError, subprocess.SubprocessError) as error:
        print(f"Debian lifecycle rejected: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
