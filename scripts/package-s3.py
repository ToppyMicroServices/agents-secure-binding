#!/usr/bin/env python3
"""Package the recorded S3 candidate without rebuilding or executing its binary."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[1]
RECORD = "packaging/s3/qualification.json"
FILES = (
    "LICENSE", RECORD, "packaging/s3/asb-s3.service",
    "packaging/s3/journald-asb-s3.conf", "packaging/s3/config.example.json",
    "packaging/s3/acceptance.example.json", "scripts/package-s3.py",
    "docs/s3-distribution.md", "docs/s3-deployment-acceptance.md",
    "docs/asb-linux-distribution.md", "docs/asb-debian-packages.md",
    "docs/least-privilege-s3-product.md", "docs/least-privilege-aws.md",
    "docs/least-privilege-execution.md", "docs/s3-release-qualification.md",
    "docs/s3-operational-qa.md",
)
MAX_BYTES = 128 * 1024 * 1024
MAX_FILES = 256


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encoded(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def read_regular(path: Path, limit: int = MAX_BYTES) -> bytes:
    # Do not follow an input symlink or block on a FIFO/device.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError(f"not a regular file: {path.name}")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"file exceeds limit: {path.name}")
    return data


def command(*args: str) -> str:
    return subprocess.check_output(args, cwd=ROOT, text=True, timeout=120).strip()


def metadata(binary: Path) -> tuple[str, dict, list, str]:
    lines = command("go", "version", "-m", str(binary)).splitlines()
    version = lines[0].rsplit(": ", 1)[1]
    settings, modules = {}, []
    for line in lines[1:]:
        fields = line.split()
        if fields[0] == "build":
            key, value = fields[1].split("=", 1)
            settings[key] = value
        elif fields[0] == "dep":
            modules.append(dict(path=fields[1], version=fields[2], sum=fields[3]))
        elif fields[0] == "=>":
            raise ValueError("replacement dependencies are not supported")
    return version, settings, modules, "bin/asb-s3: " + version + "\n" + "\n".join(lines[1:]) + "\n"


def notices(modules: list, go_version: str) -> dict[str, bytes]:
    if command("go", "env", "GOVERSION") != go_version:
        raise ValueError("use the recorded Go toolchain to collect its notices")
    command("go", "mod", "verify")
    result = {}
    for module in modules:
        downloaded = json.loads(command("go", "mod", "download", "-json", module["path"] + "@" + module["version"]))
        if downloaded.get("Sum") != module["sum"]:
            raise ValueError("dependency checksum differs from binary metadata")
        directory = Path(downloaded["Dir"])
        selected = [p for p in directory.iterdir() if p.name.upper().startswith(("LICENSE", "NOTICE", "COPYING", "COPYRIGHT", "AUTHORS", "PATENTS"))]
        if not any(p.name == "LICENSE" for p in selected):
            raise ValueError("dependency has no root license")
        for path in selected:
            name = f"licenses/{module['path']}@{module['version']}/{path.name}"
            result[name] = read_regular(path, 1024 * 1024)
    goroot = Path(command("go", "env", "GOROOT"))
    for relative in ("LICENSE", "PATENTS"):
        result["licenses/go/" + relative] = read_regular(goroot / relative)
    for path in sorted((goroot / "src/vendor").rglob("*")):
        if path.name in ("LICENSE", "PATENTS", "NOTICE"):
            result["licenses/go/" + path.relative_to(goroot).as_posix()] = read_regular(path)
    return result


def archive_bytes(files: dict[str, bytes], manifest: dict) -> bytes:
    files = dict(files)
    manifest = dict(manifest, files={
        name: {"sha256": digest(data), "mode": 0o755 if name == "bin/asb-s3" else 0o644}
        for name, data in sorted(files.items())
    })
    files["manifest.json"] = encoded(manifest)
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, data in sorted(files.items()):
                info = tarfile.TarInfo(manifest["candidate"] + "/" + name)
                info.size = len(data)
                info.mode = 0o755 if name == "bin/asb-s3" else 0o644
                archive.addfile(info, io.BytesIO(data))
    return output.getvalue()


def verify_archive(data: bytes, expected_record: dict | None = None) -> dict:
    if len(data) > MAX_BYTES:
        raise ValueError("archive exceeds limit")
    # Bound decompression before tarfile can consume extended-header payloads.
    with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as compressed:
        expanded = compressed.read(MAX_BYTES + 1)
    if len(expanded) > MAX_BYTES:
        raise ValueError("expanded archive exceeds limit")
    files, modes, prefix, total = {}, {}, None, 0
    with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            if (not member.isfile() or not re.fullmatch(r"[A-Za-z0-9/._@+-]+", member.name) or member.name != path.as_posix() or
                    path.is_absolute() or ".." in path.parts or len(path.parts) < 2):
                raise ValueError("unsafe archive member")
            if prefix is None:
                prefix = path.parts[0]
            name = "/".join(path.parts[1:])
            if path.parts[0] != prefix or name in files or len(files) >= MAX_FILES:
                raise ValueError("duplicate, mixed-root or excessive archive members")
            total += member.size
            if total > MAX_BYTES or member.size < 0:
                raise ValueError("expanded archive exceeds limit")
            files[name] = archive.extractfile(member).read()
            modes[name] = member.mode
    manifest = json.loads(files.pop("manifest.json"))
    if manifest.get("schema") != "asb.s3-distribution/v1" or manifest.get("candidate") != prefix:
        raise ValueError("invalid distribution manifest")
    if not re.fullmatch(r"asb-s3-v[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+", prefix):
        raise ValueError("invalid candidate name")
    if set(files) != set(manifest["files"]):
        raise ValueError("missing or added file")
    required = set(FILES) | {"bin/asb-s3", "build-info.txt", "modules.json", "licenses/go/LICENSE"}
    if not required.issubset(files) or modes["manifest.json"] != 0o644:
        raise ValueError("incomplete distribution")
    for name, payload in files.items():
        expected_mode = 0o755 if name == "bin/asb-s3" else 0o644
        if manifest["files"][name] != {"sha256": digest(payload), "mode": expected_mode} or modes[name] != expected_mode:
            raise ValueError(f"file hash or mode mismatch: {name}")
    record = json.loads(files[RECORD])
    if expected_record is None:
        expected_record = json.loads(read_regular(ROOT / RECORD, 1024 * 1024))
    qualified_paths = {
        "packaging/s3/asb-s3.service", "packaging/s3/config.example.json",
        "packaging/s3/journald-asb-s3.conf",
    }
    if (record.get("schema") != "asb.s3-qualified-candidate/v1" or
            set(record.get("qualified_packaging_sha256", {})) != qualified_paths or
            record != expected_record):
        raise ValueError("qualification record differs from trusted checkout")
    if (record["candidate"] != prefix or digest(files["bin/asb-s3"]) != record["binary_sha256"] or
            manifest["binary_source_commit"] != record["source_commit"] or
            manifest["qualification_run"] != record["run_id"]):
        raise ValueError("binary does not match recorded qualification")
    for name, expected in record["qualified_packaging_sha256"].items():
        if digest(files[name]) != expected:
            raise ValueError("service packaging differs from qualified configuration")
    return manifest


def verify_signature(data: bytes, signature: Path, signer: str) -> None:
    signer = signer.upper()
    if not re.fullmatch(r"[A-F0-9]{40}|[A-F0-9]{64}", signer):
        raise ValueError("trusted signer must be a full OpenPGP fingerprint")
    with tempfile.TemporaryDirectory(prefix="asb-s3-signature-") as temporary:
        copy = Path(temporary) / "archive.asc"
        copy.write_bytes(read_regular(signature, 65536))
        checked = subprocess.run(
            ["gpg", "--batch", "--no-auto-key-retrieve", "--status-fd", "1", "--verify", str(copy), "-"],
            input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False,
        )
    fingerprints = set()
    for line in checked.stdout.decode(errors="replace").splitlines():
        if line.startswith("[GNUPG:] VALIDSIG "):
            fingerprints.update(token.upper() for token in line.split() if re.fullmatch(r"[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", token))
    if checked.returncode != 0 or signer not in fingerprints:
        raise ValueError("signature failed or signer is not trusted")


def create(binary: Path, output: Path) -> dict:
    files = {name: read_regular(ROOT / name) for name in FILES}
    record = json.loads(files[RECORD])
    payload = read_regular(binary)
    if digest(payload) != record["binary_sha256"]:
        raise ValueError("binary differs from the live-qualified bytes; do not transfer qualification")
    # Inspect the same bytes whose digest was checked, even if the input changes.
    with tempfile.TemporaryDirectory(prefix="asb-s3-build-info-") as temporary:
        snapshot = Path(temporary) / "asb-s3"
        snapshot.write_bytes(payload)
        version, settings, modules, build_info = metadata(snapshot)
    if (version != record["go_version"] or settings.get("vcs.revision") != record["source_commit"] or
            settings.get("vcs.modified") != "true" or settings.get("GOOS") != "linux" or
            settings.get("GOARCH") != "amd64"):
        raise ValueError("binary build metadata differs from qualification")
    files.update(notices(modules, version))
    files.update({"bin/asb-s3": payload, "build-info.txt": build_info.encode(), "modules.json": encoded(modules)})
    manifest = {
        "schema": "asb.s3-distribution/v1", "candidate": record["candidate"],
        "binary_source_commit": record["source_commit"], "qualification_run": record["run_id"],
        "packaging_commit": command("git", "rev-parse", "HEAD"),
        "packaging_tree_modified": bool(command("git", "status", "--porcelain", "--untracked-files=normal")),
        "platform": "Ubuntu 24.04 / Linux amd64 / systemd",
        "publication_status": "candidate-only", "organization_deployment_qualified": False,
    }
    data = archive_bytes(files, manifest)
    verify_archive(data, record)
    # Exclusive creation prevents silently replacing a reviewed or signed candidate.
    with output.open("xb") as stream:
        stream.write(data)
    return {"candidate": record["candidate"], "archive_sha256": digest(data), "bytes": len(data)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("create")
    build.add_argument("--binary", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("archive", type=Path)
    verify.add_argument("--signature", type=Path)
    verify.add_argument("--trusted-signer")
    args = parser.parse_args()
    try:
        if args.command == "create":
            result = create(args.binary, args.output)
        else:
            if bool(args.signature) != bool(args.trusted_signer):
                raise ValueError("provide both signature and trusted signer")
            data = read_regular(args.archive)
            if args.signature:
                verify_signature(data, args.signature, args.trusted_signer)
            manifest = verify_archive(data)
            if args.signature and manifest.get("packaging_tree_modified") is not False:
                raise ValueError("signed distribution must identify an unmodified packaging tree")
            result = {"candidate": manifest["candidate"], "archive_sha256": digest(data),
                      "files_verified": len(manifest["files"]), "signature_verified": bool(args.signature),
                      "organization_deployment_qualified": False}
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError, IndexError, tarfile.TarError, subprocess.SubprocessError) as error:
        print(f"distribution rejected: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
