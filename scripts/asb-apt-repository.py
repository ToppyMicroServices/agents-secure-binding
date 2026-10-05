#!/usr/bin/env python3
"""Prepare, sign and verify a bounded ASB apt repository without publishing it."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from email.utils import formatdate
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

SUITE = "asb-preview"
DIST = Path("dists") / SUITE
INDEX = "main/binary-amd64/Packages"
MAX_METADATA = 4 * 1024 * 1024
MAX_PACKAGE = 256 * 1024 * 1024
MAX_VALIDITY = 7 * 86400
PACKAGES = {"asb": "all", "asb-tools": "amd64", "asb-human": "amd64", "asb-s3": "amd64"}
LIFECYCLE_CHECKS = {"apt_install", "local_command_smoke", "invalid_configuration_denied", "human_self_test",
                    "unpack_then_configure", "remove_preserves_state", "purge_preserves_state",
                    "reinstall_preserves_state", "human_receipt_recovers"}


def read(path: Path, limit: int = MAX_METADATA) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("expected a regular file")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("file exceeds size bound")
    return data


def strict_json(data: bytes) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    result = json.loads(data, object_pairs_hook=pairs)
    if not isinstance(result, dict):
        raise ValueError("expected a JSON object")
    return result


def encoded(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def execute(*args: str) -> bytes:
    return subprocess.check_output(args, stderr=subprocess.PIPE, timeout=120)


def fingerprint(value: str) -> str:
    if not re.fullmatch(r"[0-9A-F]{40}", value):
        raise ValueError("use a complete uppercase OpenPGP fingerprint")
    return value


def validate_dates(created: int, expires: int, now: int | None = None) -> None:
    if type(created) is not int or type(expires) is not int or not 0 < expires - created <= MAX_VALIDITY:
        raise ValueError("metadata validity must be between one second and seven days")
    if now is not None and (created > now + 10 or expires <= now):
        raise ValueError("metadata is expired or dated in the future")


def package_index(packages: list[dict]) -> bytes:
    return "".join(item["control"] + f"Filename: {item['path']}\nSize: {item['bytes']}\nSHA256: {item['sha256']}\n\n"
                   for item in packages).encode()


def metadata(manifest: dict) -> dict[str, bytes]:
    index = package_index(manifest["packages"])
    compressed = io.BytesIO()
    # GzipFile keeps a stable OS byte across Python/zlib versions, unlike some
    # gzip.compress implementations when mtime=0 delegates directly to zlib.
    with gzip.GzipFile(fileobj=compressed, mode="wb", filename="", mtime=0) as stream:
        stream.write(index)
    contents = {INDEX: index, INDEX + ".gz": compressed.getvalue(), "manifest.json": encoded(manifest)}
    release = (f"Origin: ASB\nLabel: ASB preview candidates\nSuite: {SUITE}\nCodename: {SUITE}\n"
               f"Date: {formatdate(manifest['created'], usegmt=True)}\n"
               f"Valid-Until: {formatdate(manifest['expires'], usegmt=True)}\n"
               "Architectures: amd64\nComponents: main\nAcquire-By-Hash: yes\nSHA256:\n")
    for name, payload in sorted(contents.items()):
        release += f" {sha(payload)} {len(payload)} {name}\n"
    result = {str(DIST / name): payload for name, payload in contents.items()}
    for name in (INDEX, INDEX + ".gz"):
        result[str(DIST / Path(name).parent / "by-hash/SHA256" / sha(contents[name]))] = contents[name]
    result[str(DIST / "Release")] = release.encode()
    return result


def validate_manifest(manifest: dict) -> None:
    if set(manifest) != {"schema", "created", "expires", "source_commit", "version", "packages", "lifecycle_sha256"}:
        raise ValueError("unexpected repository manifest fields")
    if manifest["schema"] != "asb.apt-repository/v1" or not re.fullmatch(r"[0-9a-f]{40}", manifest["source_commit"]):
        raise ValueError("invalid repository provenance")
    if not re.fullmatch(r"[0-9][A-Za-z0-9.+~]*-[A-Za-z0-9.+~]+", manifest["version"]):
        raise ValueError("invalid Debian version")
    if not re.fullmatch(r"[0-9a-f]{64}", manifest["lifecycle_sha256"]):
        raise ValueError("invalid lifecycle evidence hash")
    validate_dates(manifest["created"], manifest["expires"])
    entries = manifest["packages"]
    if not isinstance(entries, list) or not 2 <= len(entries) <= 4:
        raise ValueError("unexpected candidate count")
    names = []
    for item in entries:
        if set(item) != {"package", "architecture", "path", "bytes", "sha256", "control"}:
            raise ValueError("unexpected package fields")
        name = item["package"]
        if name not in PACKAGES or item["architecture"] != PACKAGES[name]:
            raise ValueError("unexpected package or architecture")
        if item["path"] != f"pool/main/a/asb/{name}_{manifest['version']}_{item['architecture']}.deb":
            raise ValueError("unexpected package path")
        if type(item["bytes"]) is not int or not 0 < item["bytes"] <= MAX_PACKAGE or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]):
            raise ValueError("invalid package hash or size")
        control = item["control"]
        if not isinstance(control, str) or len(control) > 16384 or "\r" in control or "\x00" in control:
            raise ValueError("invalid package control")
        fields = parse_control(control)
        if fields.get("Package") != name or fields.get("Version") != manifest["version"] or fields.get("Architecture") != item["architecture"]:
            raise ValueError("package control identity mismatch")
        if any(key in fields for key in ("Filename", "Size", "SHA256")):
            raise ValueError("archive-supplied index fields")
        names.append(name)
    if names != sorted(set(names)) or not {"asb", "asb-tools"}.issubset(names):
        raise ValueError("duplicate, unsorted or missing packages")


def parse_control(text: str) -> dict[str, str]:
    if not text.endswith("\n") or "\n\n" in text:
        raise ValueError("invalid control stanza")
    fields = {}
    allowed = {"Package", "Source", "Version", "Architecture", "Maintainer", "Section", "Priority",
               "Installed-Size", "Homepage", "Depends", "Description"}
    last = None
    for line in text.splitlines():
        if line.startswith(" ") and last:
            fields[last] += "\n" + line
            continue
        key, separator, value = line.partition(": ")
        if not separator or key not in allowed or key in fields:
            raise ValueError("duplicate, unknown or invalid control field")
        fields[key], last = value, key
    return fields


def inspect_repository(root: Path) -> dict:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("repository must be a regular directory")
    # Check every ancestor/member before reading, including intermediate symlinks.
    for folder, directories, files in os.walk(root, followlinks=False):
        for name in directories + files:
            member = Path(folder) / name
            mode = member.lstat().st_mode
            if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                raise ValueError("repository contains a symlink or special file")
    manifest = strict_json(read(root / DIST / "manifest.json"))
    validate_manifest(manifest)
    expected = metadata(manifest)
    for item in manifest["packages"]:
        payload = read(root / item["path"], MAX_PACKAGE)
        if len(payload) != item["bytes"] or sha(payload) != item["sha256"]:
            raise ValueError("package differs from authenticated inventory")
        expected[item["path"]] = payload
    allowed_signatures = {str(DIST / "InRelease"), str(DIST / "Release.gpg")}
    actual = {str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()}
    if actual - allowed_signatures != set(expected):
        raise ValueError("repository has missing or extra files")
    for name, payload in expected.items():
        if read(root / name, MAX_PACKAGE) != payload:
            raise ValueError("repository metadata differs from deterministic inventory")
    return manifest


def prepare(args: argparse.Namespace) -> dict:
    if sys.platform != "linux":
        raise ValueError("prepare on Linux; no packages are installed")
    validate_dates(args.created, args.expires, int(datetime.now(timezone.utc).timestamp()))
    if args.output.exists() or args.output.is_symlink():
        raise ValueError("output must be a new directory")
    candidate = strict_json(read(args.artifacts / "debian-candidates.json"))
    evidence_bytes = read(args.lifecycle)
    evidence = strict_json(evidence_bytes)
    if (candidate.get("schema") != "asb.debian-candidates/v1" or evidence.get("schema") != "asb.debian-lifecycle/v1"
            or evidence.get("passed") is not True or evidence.get("source_commit") != candidate.get("source_commit")
            or evidence.get("version") != candidate.get("version") or evidence.get("packages") != candidate.get("packages")
            or set(evidence.get("checks", {})) != LIFECYCLE_CHECKS or any(value is not True for value in evidence["checks"].values())):
        raise ValueError("candidate lacks matching successful Linux lifecycle evidence")
    manifest = {"schema": "asb.apt-repository/v1", "created": args.created, "expires": args.expires,
                "source_commit": candidate["source_commit"], "version": candidate["version"],
                "lifecycle_sha256": sha(evidence_bytes), "packages": []}
    payloads = {}
    for item in sorted(candidate["packages"], key=lambda entry: entry["package"]):
        filename = item["file"]
        if not re.fullmatch(r"[a-z0-9+~._-]+\.deb", filename):
            raise ValueError("invalid candidate filename")
        payload = read(args.artifacts / filename, MAX_PACKAGE)
        if len(payload) != item["bytes"] or sha(payload) != item["sha256"]:
            raise ValueError("candidate differs from lifecycle-tested bytes")
        # Work from an immutable private copy, never race dpkg's input against a
        # mutable candidate path. --field parses metadata without executing code.
        with tempfile.TemporaryDirectory(prefix="asb-apt-control-") as temporary:
            copied = Path(temporary) / "candidate.deb"
            copied.write_bytes(payload)
            control = execute("dpkg-deb", "--field", str(copied)).decode()
        path = "pool/main/a/asb/" + filename
        manifest["packages"].append({key: item[key] for key in ("package", "architecture", "bytes", "sha256")} | {"path": path, "control": control})
        payloads[path] = payload
    validate_manifest(manifest)
    payloads.update(metadata(manifest))
    args.output.mkdir(mode=0o755, parents=True)
    for name, payload in payloads.items():
        target = args.output / name
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(payload)
        target.chmod(0o644)
    for folder, _, _ in os.walk(args.output):
        Path(folder).chmod(0o755)
    inspect_repository(args.output)
    return {"prepared": True, "signed": False, "published": False, "manifest_sha256": sha(encoded(manifest))}


def verify(args: argparse.Namespace) -> dict:
    allowed = {fingerprint(item) for item in args.signer}
    if not allowed:
        raise ValueError("provide an independently approved signer fingerprint")
    keyring = read(args.keyring, 1024 * 1024)
    release = read(args.repository / DIST / "Release")
    # gpgv receives only the supplied keyring, in a fresh home; no ambient trust.
    with tempfile.TemporaryDirectory(prefix="asb-apt-verify-") as temporary:
        home = Path(temporary)
        (home / "keyring.gpg").write_bytes(keyring)
        identities = []
        for signature, detached in (("InRelease", False), ("Release.gpg", True)):
            (home / signature).write_bytes(read(args.repository / DIST / signature))
            (home / "Release").write_bytes(release)
            command = ["gpgv", "--homedir", str(home), "--keyring", str(home / "keyring.gpg"), "--status-fd", "2"]
            if not detached:
                command.extend(["--output", "-"])
            command.append(str(home / signature))
            if detached:
                command.append(str(home / "Release"))
            # Keep authenticated plaintext separate from status/diagnostics.
            # stdout also avoids GnuPG versions that leave named output in a
            # temporary .part file instead of the requested destination.
            checked = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=120)
            status = checked.stderr.decode()
            forbidden = ("BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "KEYEXPIRED", "SIGEXPIRED")
            if any(f"[GNUPG:] {word} " in status for word in forbidden):
                raise ValueError("expired, revoked or invalid repository signature")
            valid = [line.split()[2:] for line in status.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
            if len(valid) != 1 or valid[0][0] not in allowed or valid[0][7] not in ("8", "9", "10"):
                raise ValueError("signature lacks one approved exact signer and SHA-2 digest")
            identities.append(valid[0][0])
            if not detached and checked.stdout != release:
                raise ValueError("InRelease and Release content differ")
        if identities[0] != identities[1]:
            raise ValueError("repository signatures use different keys")
    manifest = inspect_repository(args.repository)
    if metadata(manifest)[str(DIST / "Release")] != release:
        raise ValueError("repository changed after signature verification: authenticated Release differs")
    validate_dates(manifest["created"], manifest["expires"], int(datetime.now(timezone.utc).timestamp()))
    return {"schema": "asb.apt-verification/v1", "passed": True, "signer": identities[0],
            "source_commit": manifest["source_commit"], "version": manifest["version"],
            "manifest_sha256": sha(encoded(manifest)), "packages": [{key: value for key, value in item.items() if key != "control"} for item in manifest["packages"]],
            "expires": manifest["expires"], "published": False}


def sign(args: argparse.Namespace) -> dict:
    identity = fingerprint(args.signer)
    manifest = inspect_repository(args.repository)
    validate_dates(manifest["created"], manifest["expires"], int(datetime.now(timezone.utc).timestamp()))
    if (not args.gnupg_home.is_absolute() or args.gnupg_home.is_symlink() or not args.gnupg_home.is_dir()
            or args.gnupg_home.stat().st_mode & 0o077):
        raise ValueError("provide an explicit private 0700 GnuPG home")
    destinations = [args.repository / DIST / name for name in ("InRelease", "Release.gpg")]
    if any(path.exists() or path.is_symlink() for path in destinations):
        raise ValueError("refuse to replace existing repository signatures")
    with tempfile.TemporaryDirectory(prefix="asb-apt-sign-") as temporary:
        directory = Path(temporary)
        release = directory / "Release"
        release.write_bytes(metadata(manifest)[str(DIST / "Release")])
        for name, kind in (("InRelease", "--clearsign"), ("Release.gpg", "--detach-sign")):
            execute("gpg", "--homedir", str(args.gnupg_home), "--batch", "--no-tty", "--local-user", identity + "!",
                    "--digest-algo", "SHA256", "--output", str(directory / name), kind, str(release))
        # Export only the explicitly selected key; the user's default home is
        # never consulted. Verify all delivered bytes after writing signatures.
        (directory / "signer.gpg").write_bytes(execute("gpg", "--homedir", str(args.gnupg_home), "--batch", "--export-options", "export-minimal", "--export", identity))
        for target in destinations:
            with target.open("xb") as stream:
                stream.write(read(directory / target.name))
            target.chmod(0o644)
        return verify(argparse.Namespace(repository=args.repository, keyring=directory / "signer.gpg", signer=[identity]))


def source(uri: str) -> str:
    parsed = urlsplit(uri)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment
            or any(c.isspace() for c in uri)):
        raise ValueError("repository URI must be an explicit HTTPS URL without credentials, query or fragment")
    return (f"Types: deb\nURIs: {uri}\nSuites: {SUITE}\nComponents: main\nArchitectures: amd64\n"
            "Signed-By: /etc/apt/keyrings/asb-archive.gpg\nCheck-Valid-Until: yes\nCheck-Date: yes\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("prepare")
    command.add_argument("--artifacts", type=Path, required=True)
    command.add_argument("--lifecycle", type=Path, required=True)
    command.add_argument("--created", type=int, required=True)
    command.add_argument("--expires", type=int, required=True)
    command.add_argument("--output", type=Path, required=True)
    command = commands.add_parser("sign")
    command.add_argument("--repository", type=Path, required=True)
    command.add_argument("--gnupg-home", type=Path, required=True)
    command.add_argument("--signer", required=True)
    command = commands.add_parser("verify")
    command.add_argument("--repository", type=Path, required=True)
    command.add_argument("--keyring", type=Path, required=True)
    command.add_argument("--signer", action="append", required=True)
    command = commands.add_parser("source")
    command.add_argument("--uri", required=True)
    args = parser.parse_args()
    try:
        if args.command == "source":
            print(source(args.uri), end="")
        else:
            print(json.dumps({"prepare": prepare, "sign": sign, "verify": verify}[args.command](args), sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError, IndexError, UnicodeError, subprocess.SubprocessError) as error:
        # Do not expose GnuPG stderr, token prompts or private paths in evidence.
        print(f"apt repository rejected: {type(error).__name__}: {error if not isinstance(error, subprocess.SubprocessError) else 'subprocess failed'}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
