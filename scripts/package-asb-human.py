#!/usr/bin/env python3
"""Package and inspect an exact-source Human approval Preview artifact."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import subprocess
import tempfile


spec = importlib.util.spec_from_file_location("asb_deb", Path(__file__).with_name("build-asb-deb.py"))
deb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deb)

SCHEMA = "asb.human-preview/v1"
PLATFORMS = {("linux", "amd64"): "asb-human", ("darwin", "arm64"): "asb-human",
             ("windows", "amd64"): "asb-human.exe"}
ENTRYPOINT = deb.MODULE + "/cmd/asb-human"
REPOSITORY = "https://github.com/ToppyMicroServices/agents-secure-binding"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def expected_binary(source: str, goos: str, goarch: str) -> str:
    require(re.fullmatch(r"[0-9a-f]{40}", source) is not None, "use a full source commit")
    require((goos, goarch) in PLATFORMS, "unsupported artifact platform")
    return PLATFORMS[goos, goarch]


def validate_settings(settings: dict, source: str, goos: str, goarch: str) -> None:
    required = {"GOOS": goos, "GOARCH": goarch, "CGO_ENABLED": "0", "-trimpath": "true",
                "vcs": "git", "vcs.revision": source, "vcs.modified": "false"}
    if goarch == "amd64":
        required["GOAMD64"] = "v1"
    require(isinstance(settings, dict) and all(settings.get(k) == v for k, v in required.items()),
            "binary provenance differs from the requested clean source or platform")


def validate_modules(modules: list) -> None:
    require(isinstance(modules, list) and len(modules) <= 1024, "invalid linked module inventory")
    seen = set()
    for module in modules:
        require(isinstance(module, dict) and set(module) == {"path", "version", "sum"}, "invalid linked module record")
        require(all(isinstance(value, str) for value in module.values()), "invalid linked module values")
        deb.safe_name("licenses/" + module["path"] + "@" + module["version"] + "/LICENSE")
        require(module["path"] not in seen and module["version"].startswith("v")
                and re.fullmatch(r"h1:[A-Za-z0-9+/]{43}=", module["sum"]) is not None,
                "duplicate or unpinned linked module")
        seen.add(module["path"])


def parse_build_info(data: bytes, source: str, goos: str, goarch: str) -> dict:
    expected_binary(source, goos, goarch)
    lines = data.decode().splitlines()
    require(bool(lines) and lines[0].rsplit(": ", 1)[-1] == deb.TOOLCHAIN, "unexpected Go toolchain")
    settings, modules, entrypoint, main_module = {}, [], None, None
    for line in lines[1:]:
        fields = line.split()
        if not fields:
            continue
        kind = fields[0]
        if kind == "=>":
            raise ValueError("replacement modules are outside the Preview artifact profile")
        if kind == "build":
            require(len(fields) == 2 and "=" in fields[1], "invalid build setting")
            key, value = fields[1].split("=", 1)
            require(key not in settings, "duplicate build setting")
            settings[key] = value
        elif kind == "path":
            require(len(fields) == 2 and entrypoint is None, "invalid entrypoint record")
            entrypoint = fields[1]
        elif kind == "mod":
            require(len(fields) in (3, 4) and main_module is None, "invalid main module record")
            main_module = fields[1]
        elif kind == "dep":
            require(len(fields) == 4, "dependency lacks an immutable checksum")
            modules.append(dict(path=fields[1], version=fields[2], sum=fields[3]))
        else:
            raise ValueError("unexpected build information record")
    require(entrypoint == ENTRYPOINT and main_module == deb.MODULE, "unexpected binary entrypoint or module")
    validate_settings(settings, source, goos, goarch)
    validate_modules(modules)
    return {"go_version": deb.TOOLCHAIN, "entrypoint": entrypoint, "build_settings": settings,
            "modules": sorted(modules, key=lambda item: item["path"])}


def usage_document(source: str) -> bytes:
    text = deb.read_regular(deb.ROOT / "docs/asb-human-binary-quickstart.md").decode()
    for ref in ("main", "feat/human-coordination-product-v1"):
        for kind in ("blob", "tree"):
            text = text.replace(f"{REPOSITORY}/{kind}/{ref}/", f"{REPOSITORY}/{kind}/{source}/")
    return text.encode()


def read_portable(path: Path, limit: int = deb.MAX_FILE) -> bytes:
    """Reject links and special files on Unix and Windows without changing bytes."""
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode), "artifact member is not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        actual = os.fstat(stream.fileno())
        require(stat.S_ISREG(actual.st_mode) and (actual.st_dev, actual.st_ino) == (before.st_dev, before.st_ino),
                "artifact member changed while opening")
        data = stream.read(limit + 1)
    require(len(data) <= limit, "artifact member exceeds size bound")
    return data


def unique_object(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate inventory field")
        result[key] = value
    return result


def verify(directory: Path, source: str, goos: str, goarch: str) -> dict:
    binary = expected_binary(source, goos, goarch)
    require(not directory.is_symlink() and directory.is_dir(), "artifact directory must be a real directory")
    raw = read_portable(directory / "inventory.json", 4 * 1024 * 1024)
    inventory = json.loads(raw, object_pairs_hook=unique_object)
    fields = {"schema", "status", "source_commit", "goos", "goarch", "go_version", "entrypoint",
              "build_settings", "modules", "binary", "files", "code_signed", "notarized"}
    require(isinstance(inventory, dict) and set(inventory) == fields, "invalid inventory schema")
    require(inventory["schema"] == SCHEMA and inventory["status"] == "preview"
            and inventory["source_commit"] == source and inventory["goos"] == goos and inventory["goarch"] == goarch
            and inventory["go_version"] == deb.TOOLCHAIN and inventory["entrypoint"] == ENTRYPOINT
            and inventory["code_signed"] is False and inventory["notarized"] is False,
            "inventory source, platform or Preview scope differs")
    require(raw == deb.encoded(inventory), "inventory encoding is not canonical")
    validate_settings(inventory["build_settings"], source, goos, goarch)
    validate_modules(inventory["modules"])
    files = inventory["files"]
    required = {binary, "USAGE.md", "LICENSE", "SHA256SUMS", "licenses/go/LICENSE"}
    require(isinstance(files, dict) and required <= set(files) and len(files) <= 4096, "incomplete file inventory")
    for name, digest in files.items():
        deb.safe_name(name)
        require(name in required or name.startswith("licenses/"), "unexpected inventoried file")
        require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None, "invalid file hash")
    for module in inventory["modules"]:
        prefix = "licenses/" + module["path"] + "@" + module["version"] + "/"
        require(any(name.startswith(prefix) and "/" not in name[len(prefix):]
                    and name[len(prefix):].upper().startswith(("LICENSE", "COPYING")) for name in files),
                "missing linked module license")
    expected = set(files) | {"inventory.json"}
    expected_dirs = {parent.as_posix() for name in expected for parent in PurePosixPath(name).parents}
    actual, actual_dirs = set(), set()
    for folder, dirs, names in os.walk(directory, followlinks=False):
        actual_dirs.add(Path(folder).relative_to(directory).as_posix())
        for name in dirs:
            require(not (Path(folder) / name).is_symlink(), "artifact contains a linked directory")
        for name in names:
            relative = (Path(folder) / name).relative_to(directory).as_posix()
            require(relative in expected, "artifact contains an extra file")
            actual.add(relative)
    require(actual == expected and actual_dirs == expected_dirs, "artifact has missing files or extra directories")
    payloads = {}
    total = 0
    for name in sorted(files):
        payload = read_portable(directory / name, deb.MAX_FILE if name == binary else 8 * 1024 * 1024)
        total += len(payload)
        require(total <= deb.MAX_FILE + deb.MAX_NOTICES + 16 * 1024 * 1024, "artifact exceeds size bound")
        require(deb.sha256(payload) == files[name], "artifact file hash mismatch: " + name)
        if name in required:
            require(bool(payload), "required artifact member is empty")
            payloads[name] = payload
    record = inventory["binary"]
    require(isinstance(record, dict) and set(record) == {"file", "sha256", "bytes"}
            and record["file"] == binary and record["sha256"] == files[binary]
            and type(record["bytes"]) is int and record["bytes"] == len(payloads[binary]), "binary inventory differs")
    require(payloads["SHA256SUMS"] == f"{files[binary]}  {binary}\n".encode(), "binary checksum manifest differs")
    return inventory


def package(binary_path: Path, output: Path, source: str, goos: str, goarch: str) -> dict:
    binary = expected_binary(source, goos, goarch)
    require(platform.system() == "Linux", "package Preview artifacts on the Linux build runner")
    require(binary_path.name == binary, "input binary name differs from platform")
    require(not output.exists() and not output.is_symlink(), "refuse to replace an existing artifact")
    deb.clean_source(source)
    env = dict(os.environ, GOENV="off", GOWORK="off", GOFLAGS="-mod=readonly", GOTOOLCHAIN=deb.TOOLCHAIN)
    require(deb.run("go", "env", "GOVERSION", env=env).decode().strip() == deb.TOOLCHAIN, "unexpected notice toolchain")
    payload = deb.read_regular(binary_path)
    # Inspect a private captured copy so metadata and delivery describe the same bytes.
    with tempfile.TemporaryDirectory(prefix="asb-human-package-") as temporary:
        captured = Path(temporary) / binary
        captured.write_bytes(payload)
        info = parse_build_info(deb.run("go", "version", "-m", str(captured), env=env), source, goos, goarch)
    files = {binary: payload, "USAGE.md": usage_document(source), "LICENSE": deb.read_regular(deb.ROOT / "LICENSE"),
             "SHA256SUMS": f"{deb.sha256(payload)}  {binary}\n".encode(), **deb.collect_notices(info["modules"], env)}
    inventory = {"schema": SCHEMA, "status": "preview", "source_commit": source, "goos": goos, "goarch": goarch,
                 **info, "binary": {"file": binary, "sha256": deb.sha256(payload), "bytes": len(payload)},
                 "files": {name: deb.sha256(data) for name, data in sorted(files.items())},
                 "code_signed": False, "notarized": False}
    files["inventory.json"] = deb.encoded(inventory)
    output.mkdir(parents=True)
    for name, data in files.items():
        deb.safe_name(name)
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(data)
        target.chmod(0o755 if name == binary else 0o644)
    verify(output, source, goos, goarch)
    deb.clean_source(source)
    return inventory


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("package", "verify"))
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--goos", required=True)
    parser.add_argument("--goarch", required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--binary", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "package":
            require(args.binary is not None, "package requires a binary")
            result = package(args.binary, args.directory, args.source_commit, args.goos, args.goarch)
        else:
            require(args.binary is None, "verify does not accept a replacement binary")
            result = verify(args.directory, args.source_commit, args.goos, args.goarch)
        print(json.dumps({"passed": True, "source_commit": result["source_commit"], "binary": result["binary"]}))
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"Preview artifact rejected: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
