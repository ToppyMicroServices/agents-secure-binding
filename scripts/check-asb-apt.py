#!/usr/bin/env python3
"""Qualify apt delivery in disposable Linux containers using ephemeral test keys."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.util
import io
import json
import os
import re
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile
import uuid

spec = importlib.util.spec_from_file_location("asb_apt", Path(__file__).with_name("asb-apt-repository.py"))
apt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(apt)

spec = importlib.util.spec_from_file_location("asb_deb", Path(__file__).with_name("build-asb-deb.py"))
deb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deb)

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
printf '%s  /usr/bin/asb-human\n' "$ASB_HUMAN_INITIAL_SHA256" | sha256sum --check --status
test ! -e /etc/systemd/system/asb-s3.service
test ! -e /usr/lib/systemd/system/asb-s3.service
test ! -e /etc/asb-s3/config.json
mark previous-taskcoord-implementation-state
printf 'ASB_TASKCOORD_INITIAL='
/probes/initial --mode seed --database /tmp/asb-taskcoord-upgrade/coord.db
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
schema_before=$(dd if="$state/human-approval.sqlite" bs=1 skip=60 count=4 status=none | od -An -tx1 | tr -d ' \n')
test "$schema_before" = 00000001
printf 'ASB_HUMAN_SCHEMA_INITIAL=%s\n' "$schema_before"
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
printf '%s  /usr/bin/asb-human\n' "$ASB_HUMAN_UPGRADE_SHA256" | sha256sum --check --status
test "$ASB_HUMAN_INITIAL_SHA256" != "$ASB_HUMAN_UPGRADE_SHA256"
mark distinct-source-binary-installed
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
schema_after=$(dd if="$state/human-approval.sqlite" bs=1 skip=60 count=4 status=none | od -An -tx1 | tr -d ' \n')
test "$schema_after" = "$schema_before"
printf 'ASB_HUMAN_SCHEMA_UPGRADE=%s\n' "$schema_after"
mark unchanged-human-schema-confirmed
mark taskcoord-schema-upgrade
printf 'ASB_TASKCOORD_UPGRADE='
/probes/upgrade --mode verify --database /tmp/asb-taskcoord-upgrade/coord.db
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


def validate_sources(args: argparse.Namespace, initial: dict, upgrade: dict) -> dict:
    for expected, record in ((args.initial_source, initial), (args.upgrade_source, upgrade)):
        if not re.fullmatch(r"[0-9a-f]{40}", expected) or record.get("source_commit") != expected:
            raise ValueError("candidate source differs from the explicit reviewed commit")
    if args.initial_source == args.upgrade_source:
        raise ValueError("cross-source upgrade requires distinct commits")
    checkout = str(args.source_checkout.resolve())

    def git(*arguments):
        return run("git", "-C", checkout, *arguments).decode().strip()

    if git("rev-parse", "HEAD") != args.upgrade_source or git("status", "--porcelain", "--untracked-files=normal"):
        raise ValueError("upgrade source must be the current clean checkout")
    trees = {label: git("rev-parse", source + "^{tree}") for label, source in (("initial", args.initial_source), ("upgrade", args.upgrade_source))}
    if any(not re.fullmatch(r"[0-9a-f]{40}", tree) for tree in trees.values()) or trees["initial"] == trees["upgrade"]:
        raise ValueError("cross-source upgrade requires distinct source trees")
    git("merge-base", "--is-ancestor", args.initial_source, args.upgrade_source)
    human_changes = git("diff", "--name-only", args.initial_source, args.upgrade_source, "--", "cmd/asb-human", "internal/humanapp")
    return {"initial_commit": args.initial_source, "upgrade_commit": args.upgrade_source,
            "initial_tree": trees["initial"], "upgrade_tree": trees["upgrade"], "ancestor_verified": True,
            "clean_upgrade_checkout": True, "human_entrypoint_sources_changed": bool(human_changes)}


def inspect_human_package(directory: Path, expected_source: str) -> dict:
    """Read final archive/build metadata without executing its Linux program."""
    candidate = apt.strict_json(apt.read(directory / "debian-candidates.json"))
    if candidate.get("source_commit") != expected_source:
        raise ValueError("Human package candidate source mismatch")
    records = [item for item in candidate.get("packages", []) if item.get("package") == "asb-human"]
    if len(records) != 1:
        raise ValueError("one explicit asb-human candidate is required")
    record = records[0]
    if not re.fullmatch(r"asb-human_[a-z0-9+~._-]+_amd64\.deb", record["file"]):
        raise ValueError("invalid Human package filename")
    payload = apt.read(directory / record["file"], apt.MAX_PACKAGE)
    if len(payload) != record["bytes"] or apt.sha(payload) != record["sha256"] or not payload.startswith(b"!<arch>\n"):
        raise ValueError("Human package bytes differ from candidate evidence")
    members, offset = {}, 8
    while offset < len(payload):
        header = payload[offset:offset + 60]
        if len(header) != 60 or header[58:60] != b"`\n":
            raise ValueError("invalid Debian ar header")
        name = header[:16].decode().strip().rstrip("/")
        size = int(header[48:58])
        offset += 60
        if size < 0 or offset + size > len(payload) or name in members:
            raise ValueError("invalid or duplicate Debian ar member")
        members[name] = payload[offset:offset + size]
        offset += size
        if size % 2:
            if payload[offset:offset + 1] != b"\n":
                raise ValueError("invalid Debian ar padding")
            offset += 1
    if offset != len(payload) or list(members) != ["debian-binary", "control.tar.gz", "data.tar.gz"] or members["debian-binary"] != b"2.0\n":
        raise ValueError("unsupported Debian archive shape")
    files, payload_files, total, binary, inventory_data = {}, {}, 0, None, None
    inventory_path = "usr/share/doc/asb-human/inventory.json"
    binary_path = "usr/bin/asb-human"
    with tarfile.open(fileobj=io.BytesIO(members["data.tar.gz"]), mode="r|gz") as archive:
        for member in archive:
            name = member.name.removeprefix("./").rstrip("/") or "."
            if (member.uid != 0 or member.gid != 0 or name.startswith("/") or ".." in PurePosixPath(name).parts
                    or not (member.isdir() or member.isfile())):
                raise ValueError("unsafe Human package member")
            if member.isdir():
                if member.mode != 0o755:
                    raise ValueError("unexpected Human package directory mode")
                continue
            if (name in files or not (name == binary_path or name.startswith("usr/share/doc/asb-human/"))
                    or member.mode != (0o755 if name == binary_path else 0o644)):
                raise ValueError("unexpected Human package payload path or mode")
            total += member.size
            if member.size < 0 or total > apt.MAX_PACKAGE or len(files) >= 4096:
                raise ValueError("Human archive exceeds payload bound")
            data = archive.extractfile(member).read(member.size + 1)
            if len(data) != member.size:
                raise ValueError("truncated Human package payload")
            files[name] = apt.sha(data)
            payload_files[name] = data
            if name == binary_path:
                binary = data
            elif name == inventory_path:
                inventory_data = data
    if binary is None or inventory_data is None:
        raise ValueError("Human package lacks binary or inventory")
    inventory = apt.strict_json(inventory_data)
    if (inventory.get("schema") != "asb.debian-payload/v1" or inventory.get("package") != "asb-human"
            or inventory.get("source_commit") != expected_source or inventory.get("version") != candidate["version"]
            or inventory.get("files") != {name: digest for name, digest in files.items() if name != inventory_path}
            or set(inventory.get("binaries", {})) != {"asb-human"}):
        raise ValueError("Human payload inventory/source mismatch")
    expected = inventory["binaries"]["asb-human"]
    if expected.get("sha256") != apt.sha(binary) or expected.get("bytes") != len(binary):
        raise ValueError("Human binary inventory differs")
    # The current builder's independent final-archive checker also checks the
    # old artifact: exact member set, parent modes, root ownership, canonical
    # control/md5 inventory, and the absence of maintainer scripts.
    controls = {}
    with tarfile.open(fileobj=io.BytesIO(members["control.tar.gz"]), mode="r|gz") as archive:
        for member in archive:
            if member.isdir():
                continue
            name = member.name.removeprefix("./")
            if not member.isfile() or name in controls or name not in ("control", "md5sums") or not 0 <= member.size <= 1024 * 1024:
                raise ValueError("unexpected Human package control file")
            controls[name] = archive.extractfile(member).read(member.size + 1)
    if set(controls) != {"control", "md5sums"}:
        raise ValueError("Human package lacks canonical control files")
    fields = apt.parse_control(controls["control"].decode())
    expected_control = deb.control("asb-human", candidate["version"], fields["Maintainer"], sum(map(len, payload_files.values())))
    deb.validate_static_elf(binary)
    with tempfile.TemporaryDirectory(prefix="asb-human-build-info-") as temporary:
        archive_path = Path(temporary) / "asb-human.deb"
        archive_path.write_bytes(payload)
        deb.inspect_deb(archive_path, payload_files, expected_control)
        path = Path(temporary) / "asb-human"
        path.write_bytes(binary)
        path.chmod(0o600)
        info, modules = deb.build_info(path, expected_source, dict(os.environ, GOENV="off", GOWORK="off", GOTOOLCHAIN="local"))
    if (info.get("main_path") != deb.MODULE + "/cmd/asb-human"
            or any(expected.get(key) != value for key, value in info.items())
            or sorted(modules, key=lambda item: item["path"]) != inventory.get("modules")):
        raise ValueError("Human embedded build metadata differs from inventory")
    return {"source_commit": expected_source, "version": candidate["version"], "package_sha256": record["sha256"],
            "binary_sha256": apt.sha(binary), "binary_bytes": len(binary), "inventory_files_checked": len(files),
            "embedded_build": info, "final_archive_structure_checked": True, "executed_by_inspector": False}


def build_taskcoord_probes(args: argparse.Namespace, directory: Path) -> dict:
    """Compile one test helper against two clean modules, without modifying them."""
    checkouts = {"initial": args.initial_checkout.resolve(), "upgrade": args.source_checkout.resolve()}
    sources = {"initial": args.initial_source, "upgrade": args.upgrade_source}
    helper = checkouts["upgrade"] / "scripts/fixtures/taskcoord-upgrade/main.go"
    helper_bytes = apt.read(helper)
    environment = dict(os.environ, GOENV="off", GOWORK="off", GOFLAGS="", CGO_ENABLED="0", GOOS="linux",
                       GOARCH="amd64", GOAMD64="v1", GOTOOLCHAIN=deb.TOOLCHAIN)
    directory.mkdir(mode=0o755)
    result = {"helper_sha256": apt.sha(helper_bytes), "helper_path": "scripts/fixtures/taskcoord-upgrade/main.go", "builds": {}}
    for label, checkout in checkouts.items():
        if (run("git", "-C", str(checkout), "rev-parse", "HEAD").decode().strip() != sources[label]
                or run("git", "-C", str(checkout), "status", "--porcelain", "--untracked-files=normal").strip()):
            raise ValueError("probe must use the explicit clean module checkout")

        def go(*arguments):
            return subprocess.check_output(["go", *arguments], cwd=checkout, env=environment, stderr=subprocess.PIPE, timeout=300)

        if go("env", "GOVERSION").decode().strip() != deb.TOOLCHAIN:
            raise ValueError("unexpected probe compiler")
        module = apt.strict_json(go("list", "-mod=readonly", "-m", "-json"))
        resolved = Path(go("list", "-mod=readonly", "-f", "{{.Dir}}", deb.MODULE + "/pkg/taskcoord/sqlitestore").decode().strip()).resolve()
        if module.get("Path") != deb.MODULE or Path(module.get("Dir", "")).resolve() != checkout or resolved != checkout / "pkg/taskcoord/sqlitestore":
            raise ValueError("probe dependency did not resolve to the selected source checkout")
        binary = directory / label
        go("build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o", str(binary), str(helper))
        payload = apt.read(binary, apt.MAX_PACKAGE)
        deb.validate_static_elf(payload)
        if run("git", "-C", str(checkout), "status", "--porcelain", "--untracked-files=normal").strip():
            raise ValueError("probe build changed a reviewed source checkout")
        result["builds"][label] = {"source_commit": sources[label], "module_path": module["Path"],
            "resolved_store_path": "pkg/taskcoord/sqlitestore", "store_implementation_sha256": apt.sha(apt.read(resolved / "store.go")),
            "sha256": apt.sha(payload), "bytes": len(payload), "go_version": deb.TOOLCHAIN,
            "buildvcs": False, "role": "test-only external helper; not a distribution executable"}
    if result["builds"]["initial"]["store_implementation_sha256"] == result["builds"]["upgrade"]["store_implementation_sha256"]:
        raise ValueError("TaskCoord implementation did not change between selected sources")
    if result["builds"]["initial"]["sha256"] == result["builds"]["upgrade"]["sha256"]:
        raise ValueError("TaskCoord probe executable bytes did not change")
    (directory / "main.go").write_bytes(helper_bytes)
    (directory / "build.json").write_bytes(apt.encoded(result))
    return result


def taskcoord_transition(output: bytes) -> dict:
    reports = {}
    for label in ("INITIAL", "UPGRADE"):
        matches = re.findall(rb"^ASB_TASKCOORD_" + label.encode() + rb"=(.+)$", output, re.MULTILINE)
        if len(matches) != 1:
            raise ValueError("missing or duplicate TaskCoord probe evidence")
        item = apt.strict_json(matches[0])
        if (item.get("schema") != "asb.taskcoord-upgrade-probe/v1" or item.get("passed") is not True
                or any(item.get(field) is not True for field in ("participant_preserved", "assignment_preserved", "immutable_retry_preserved"))):
            raise ValueError("incomplete TaskCoord probe evidence")
        reports[label.lower()] = item
    initial, upgrade = reports["initial"], reports["upgrade"]
    if (initial.get("mode") != "seed" or upgrade.get("mode") != "verify" or initial["after"]["schema"] != 1
            or upgrade["before"] != initial["after"] or upgrade["after"]["schema"] != 2
            or initial["after"]["reachability_quarantine_tables"] != 0 or upgrade["after"]["reachability_quarantine_tables"] != 2
            or any(upgrade["after"][key] != initial["after"][key] for key in ("tasks_sha256", "actions_sha256"))
            or any(report["after"]["integrity"] != "ok" for report in reports.values())):
        raise ValueError("TaskCoord source/schema/state transition does not match the supported migration")
    return reports


def human_schema_transition(output: bytes) -> dict:
    schemas = {}
    for label in ("INITIAL", "UPGRADE"):
        matches = re.findall(rb"^ASB_HUMAN_SCHEMA_" + label.encode() + rb"=(.*)$", output, re.MULTILINE)
        if len(matches) != 1 or matches[0] != b"00000001":
            raise ValueError("unsupported or ambiguous Human schema transition")
        schemas[label.lower()] = 1
    return schemas


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
    source_transition = validate_sources(args, apt.strict_json(apt.read(args.initial / "debian-candidates.json")),
                                         apt.strict_json(apt.read(args.upgrade / "debian-candidates.json")))
    human_packages = {label: inspect_human_package(directory, expected) for label, directory, expected in
                      (("initial", args.initial, args.initial_source), ("upgrade", args.upgrade, args.upgrade_source))}
    if human_packages["initial"]["binary_sha256"] == human_packages["upgrade"]["binary_sha256"]:
        raise ValueError("cross-source qualification requires distinct Human executable bytes")
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
        probes = directory / "probes"
        probe_builds = build_taskcoord_probes(args, probes)
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
                 "--mount", f"type=bind,src={keys},dst=/keys,readonly",
                 "--mount", f"type=bind,src={probes},dst=/probes,readonly", "--env", "ASB_VERSION_INITIAL=" + results["initial"]["version"],
                 "--env", "ASB_VERSION_UPGRADE=" + results["upgrade"]["version"],
                 "--env", "ASB_HUMAN_INITIAL_SHA256=" + human_packages["initial"]["binary_sha256"],
                 "--env", "ASB_HUMAN_UPGRADE_SHA256=" + human_packages["upgrade"]["binary_sha256"], "--entrypoint", "/bin/sh", image["Id"], "-s"],
                input=EXERCISE.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600, check=False)
            phases = [line.removeprefix(b"ASB_APT_PHASE=").decode() for line in checked.stdout.splitlines() if line.startswith(b"ASB_APT_PHASE=")]
            if checked.returncode or not checked.stdout.endswith(b"ASB_APT_PASS\n"):
                # These streams contain only apt diagnostics and phase markers;
                # private Human login links and receipt content are redirected.
                diagnostic = (checked.stdout[-3000:] + checked.stderr[-3000:]).decode(errors="replace")
                raise ValueError(f"isolated apt check failed at {phases[-1] if phases else 'start'} (exit {checked.returncode}): {diagnostic}")
            source_transition["human_schema"] = human_schema_transition(checked.stdout)
            source_transition["human_schema_migration_tested"] = False
            taskcoord_evidence = taskcoord_transition(checked.stdout)
            tools = {name: run(name, "--version").decode().splitlines()[0] for name in ("gpg", "gpgv", "dpkg-deb")}
            # Retain the actual signed metadata and public test keyrings. Package
            # bytes remain in the two original candidate artifacts, avoiding a
            # second copy of each executable in the evidence upload.
            evidence_directory.mkdir(parents=True)
            for label in ("initial", "upgrade"):
                shutil.copytree(repositories / label / "dists", evidence_directory / label / "dists")
            shutil.copytree(probes, evidence_directory / "taskcoord-probes")
            for binary in ("initial", "upgrade"):
                (evidence_directory / "taskcoord-probes" / binary).chmod(0o600)
            (evidence_directory / "keyrings").mkdir()
            for label in ("a", "b", "ab"):
                shutil.copyfile(keys / (label + ".gpg"), evidence_directory / "keyrings" / (label + ".gpg"))
            metadata_evidence = {str(path.relative_to(evidence_directory)): apt.sha(apt.read(path, apt.MAX_PACKAGE))
                                 for path in sorted(evidence_directory.rglob("*")) if path.is_file()}
            return {"schema": "asb.apt-lifecycle/v1", "passed": True, "repositories": results,
                    "source_transition": source_transition, "human_packages": human_packages,
                    "taskcoord_upgrade": {"builds": probe_builds, "runtime": taskcoord_evidence},
                    "checks": {phase: True for phase in phases} | {"deterministic_unsigned_metadata": True, "independent_verifier_rejects_all_negative_fixtures": True},
                    "image_requested": args.image, "image_id": image["Id"], "image_repo_digests": image.get("RepoDigests", []),
                    "container_network": "none", "tools": tools, "ephemeral_test_key_fingerprints": identities,
                    "metadata_evidence": {"directory": evidence_directory.name, "sha256": metadata_evidence},
                    "limits": ["ephemeral CI keys; no production key or hosting", "distinct-source package upgrade; unchanged Human schema 1", "separate TaskCoord SDK schema 1 to 2 probe; no general migration guarantee",
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
    parser.add_argument("--initial-source", required=True)
    parser.add_argument("--upgrade-source", required=True)
    parser.add_argument("--source-checkout", type=Path, required=True)
    parser.add_argument("--initial-checkout", type=Path, required=True)
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
    except (ValueError, OSError, KeyError, TypeError, IndexError, tarfile.TarError, subprocess.SubprocessError) as error:
        print(f"apt check rejected: {error if not isinstance(error, subprocess.SubprocessError) else 'subprocess failed'}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
