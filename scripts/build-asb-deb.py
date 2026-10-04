#!/usr/bin/env python3
"""Build local ASB Debian candidates from one clean Linux source checkout."""

from __future__ import annotations

import argparse
from email.utils import formatdate
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import posixpath
import re
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
from urllib.parse import quote, unquote, urlsplit, urlunsplit


ROOT = Path(__file__).resolve().parents[1]
TOOLCHAIN = "go1.26.6"
MODULE = "github.com/ToppyMicroServices/agents-secure-binding/v2"
PROGRAMS = {
    "asb-tools": {"agents-secure-binding-cli": "./cmd/cli", "asb-leastprivilege": "./cmd/asb-leastprivilege", "asb-leastprivilege-proof": "./cmd/asb-leastprivilege-proof"},
    "asb-human": {"asb-human": "./cmd/asb-human"},
    "asb-s3": {"asb-s3": "./cmd/asb-s3"},
}
DOCS = {
    "asb-tools": ("docs/least-privilege-v1.md", "docs/least-privilege-certificates.md", "docs/least-privilege-execution.md"),
    "asb-human": ("docs/local-human-approval.md", "docs/local-human-approval-validation.md"),
    "asb-s3": ("docs/least-privilege-s3-product.md", "docs/s3-deployment-acceptance.md"),
}
S3_EXAMPLES = ("packaging/debian/asb-s3.service.example", "packaging/s3/config.example.json",
               "packaging/s3/journald-asb-s3.conf", "packaging/s3/acceptance.example.json")
MAX_FILE = 256 * 1024 * 1024
MAX_NOTICES = 64 * 1024 * 1024


def run(*args: str, env: dict | None = None) -> bytes:
    return subprocess.check_output(args, cwd=ROOT, env=env, timeout=900)


def read_regular(path: Path, limit: int = MAX_FILE) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError(f"not a regular file: {path.name}")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"input exceeds bound: {path.name}")
    return data


def encoded(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def package_document(relative: str, destinations: dict[str, str], source: str) -> bytes:
    original = read_regular(ROOT / relative).decode()
    base = PurePosixPath(relative).parent.as_posix()
    destination = PurePosixPath(destinations[relative]).parent.as_posix()

    def rewrite(match: re.Match) -> str:
        target = urlsplit(match.group(2))
        if target.scheme or target.netloc or not target.path:
            return match.group(0)
        repository_path = posixpath.normpath(posixpath.join(base, unquote(target.path)))
        if repository_path.startswith("../") or repository_path.startswith("/") or repository_path == "..":
            raise ValueError("documentation link escapes the source checkout")
        if repository_path in destinations:
            path = quote(posixpath.relpath(destinations[repository_path], destination), safe="/.")
        else:
            kind = "tree" if (ROOT / repository_path).is_dir() else "blob"
            path = f"https://github.com/ToppyMicroServices/agents-secure-binding/{kind}/{source}/{quote(repository_path, safe='/')}"
        return match.group(1) + urlunsplit(("", "", path, target.query, target.fragment)) + match.group(3)

    rewritten = re.sub(r"(\[[^\]\n]*\]\()([^\s)]+)(\))", rewrite, original)
    note = ("> Debian package copy. Repository-relative build and test commands require a checkout of "
            f"[source revision {source}](https://github.com/ToppyMicroServices/agents-secure-binding/tree/{source}). "
            "Installed executables are under `/usr/bin`.\n\n")
    return (note + rewritten).encode()


def safe_name(name: str) -> None:
    path = PurePosixPath(name)
    if (not re.fullmatch(r"[A-Za-z0-9/._@!+~-]+", name) or path.is_absolute() or
            ".." in path.parts or name != path.as_posix() or not path.parts):
        raise ValueError("unsafe package path")


def validate_static_elf(data: bytes) -> None:
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("binary is not a little-endian ELF64 executable")
    header = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    kind, machine, phoff, phsize, phcount = header[0], header[1], header[4], header[8], header[9]
    if kind != 2 or machine != 62 or phsize != 56 or not phcount or phoff + phcount * phsize > len(data):
        raise ValueError("unsupported Linux amd64 ELF layout")
    for index in range(phcount):
        if struct.unpack_from("<I", data, phoff + index * phsize)[0] in (2, 3):
            raise ValueError("dynamic executable requires a separately qualified dependency profile")


def clean_source(expected: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", expected):
        raise ValueError("source commit must be a full lowercase SHA-1")
    if run("git", "rev-parse", "HEAD").decode().strip() != expected:
        raise ValueError("checkout does not match requested source commit")
    if run("git", "status", "--porcelain", "--untracked-files=normal").strip():
        raise ValueError("package build requires a clean checkout")


def build_info(binary: Path, source: str, env: dict) -> tuple[dict, list]:
    lines = run("go", "version", "-m", str(binary), env=env).decode().splitlines()
    if not lines or lines[0].rsplit(": ", 1)[-1] != TOOLCHAIN:
        raise ValueError("unexpected Go toolchain")
    settings, dependencies, main_path = {}, [], None
    for line in lines[1:]:
        fields = line.split()
        if not fields:
            continue
        if fields[0] == "build":
            key, value = fields[1].split("=", 1)
            settings[key] = value
        elif fields[0] == "path":
            main_path = fields[1]
        elif fields[0] == "dep":
            if len(fields) != 4 or not fields[3].startswith("h1:"):
                raise ValueError("dependency lacks an immutable module checksum")
            dependencies.append(dict(path=fields[1], version=fields[2], sum=fields[3]))
        elif fields[0] == "=>":
            raise ValueError("replacement modules are outside this package profile")
    required = {"GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v1", "CGO_ENABLED": "0", "vcs.revision": source, "vcs.modified": "false"}
    if any(settings.get(key) != value for key, value in required.items()):
        raise ValueError("binary build provenance differs from requested clean source")
    return {"go_version": TOOLCHAIN, "main_path": main_path, "settings": settings}, dependencies


def collect_notices(modules: list, env: dict) -> dict[str, bytes]:
    result = {}
    for module in modules:
        info = json.loads(run("go", "mod", "download", "-json", module["path"] + "@" + module["version"], env=env))
        if info.get("Sum") != module["sum"]:
            raise ValueError("module notice source does not match linked checksum")
        directory = Path(info["Dir"])
        found_license = False
        for folder, _, names in os.walk(directory, followlinks=False):
            for name in names:
                if not name.upper().startswith(("LICENSE", "NOTICE", "COPYING", "COPYRIGHT", "AUTHORS", "PATENTS")):
                    continue
                path = Path(folder) / name
                relative = path.relative_to(directory).as_posix()
                found_license |= "/" not in relative and name.upper().startswith(("LICENSE", "COPYING"))
                destination = f"licenses/{module['path']}@{module['version']}/{relative}"
                safe_name(destination)
                result[destination] = read_regular(path, 8 * 1024 * 1024)
                if len(result) > 2048 or sum(map(len, result.values())) > MAX_NOTICES:
                    raise ValueError("dependency notices exceed package bound")
        if not found_license:
            raise ValueError(f"linked module has no root license: {module['path']}")
    goroot = Path(run("go", "env", "GOROOT", env=env).decode().strip())
    for path in [goroot / "LICENSE", goroot / "PATENTS", *sorted((goroot / "src/vendor").rglob("*"))]:
        if path.name in ("LICENSE", "PATENTS", "NOTICE"):
            relative = "licenses/go/" + path.relative_to(goroot).as_posix()
            safe_name(relative)
            result[relative] = read_regular(path, 8 * 1024 * 1024)
    if sum(map(len, result.values())) > MAX_NOTICES:
        raise ValueError("notices exceed package bound")
    return result


def control(name: str, version: str, maintainer: str, size: int) -> bytes:
    architecture = "all" if name == "asb" else "amd64"
    fields = [f"Package: {name}", "Source: asb", f"Version: {version}", f"Architecture: {architecture}",
              f"Maintainer: {maintainer}", "Section: utils", "Priority: optional", f"Installed-Size: {(size + 1023) // 1024}",
              "Homepage: https://github.com/ToppyMicroServices/agents-secure-binding"]
    if name == "asb":
        fields.append(f"Depends: asb-tools (= {version})")
    descriptions = {
        "asb": "ASB tools entry-point metapackage",
        "asb-tools": "ASB runtime client and finite least-privilege tools",
        "asb-human": "ASB local Human approval preview",
        "asb-s3": "ASB restricted S3 reader candidate",
    }
    fields.extend([f"Description: {descriptions[name]}", " Local distribution candidate; component support boundaries remain unchanged.",
                   " No service is enabled and no application state is initialized."])
    return ("\n".join(fields) + "\n").encode()


def inspect_deb(path: Path, files: dict[str, bytes], expected_control: bytes) -> None:
    actual = {}
    expected_directories = {"."} | {str(parent) for name in files for parent in PurePosixPath(name).parents}
    directories = set()
    with tarfile.open(fileobj=io.BytesIO(run("dpkg-deb", "--fsys-tarfile", str(path))), mode="r:") as archive:
        for member in archive:
            if member.uid != 0 or member.gid != 0:
                raise ValueError("package ownership is not root:root")
            name = member.name.removeprefix("./").rstrip("/")
            if member.isdir():
                name = name or "."
                if member.mode != 0o755:
                    raise ValueError("unexpected directory mode")
                if name != ".":
                    safe_name(name)
                if name not in expected_directories or name in directories:
                    raise ValueError("unexpected or duplicate package directory")
                directories.add(name)
                continue
            safe_name(name)
            if not member.isfile() or name not in files or name in actual:
                raise ValueError("unexpected or duplicate package member")
            expected_mode = 0o755 if name.startswith("usr/bin/") else 0o644
            if member.mode != expected_mode or archive.extractfile(member).read() != files[name]:
                raise ValueError("final package payload or mode differs from inventory")
            actual[name] = True
    if set(actual) != set(files):
        raise ValueError("final package lacks an inventoried file")
    if directories != expected_directories:
        raise ValueError("final package lacks an inventoried parent directory")
    expected_md5 = "".join(f"{hashlib.md5(data).hexdigest()}  {name}\n" for name, data in sorted(files.items())).encode()
    controls = {}
    control_directories = set()
    with tarfile.open(fileobj=io.BytesIO(run("dpkg-deb", "--ctrl-tarfile", str(path))), mode="r:") as archive:
        for member in archive:
            if member.uid != 0 or member.gid != 0:
                raise ValueError("package control ownership is not root:root")
            if member.isdir():
                name = member.name.removeprefix("./").rstrip("/") or "."
                if name != "." or member.mode != 0o755 or name in control_directories:
                    raise ValueError("unexpected or duplicate control directory")
                control_directories.add(name)
                continue
            name = member.name.removeprefix("./")
            if not member.isfile() or name in controls or name not in ("control", "md5sums") or member.mode != 0o644:
                raise ValueError("package contains unexpected maintainer control files")
            controls[name] = archive.extractfile(member).read()
    if control_directories != {"."} or controls != {"control": expected_control, "md5sums": expected_md5}:
        raise ValueError("final package control files differ")


def write_package(staging: Path, output: Path, name: str, version: str, maintainer: str,
                  files: dict[str, bytes], epoch: str) -> dict:
    stage = staging / name
    stage.mkdir(mode=0o755)
    for relative, data in files.items():
        safe_name(relative)
        path = stage / relative
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o755 if relative.startswith("usr/bin/") else 0o644)
    debian = stage / "DEBIAN"
    debian.mkdir(mode=0o755)
    content = control(name, version, maintainer, sum(map(len, files.values())))
    (debian / "control").write_bytes(content)
    (debian / "md5sums").write_text("".join(f"{hashlib.md5(data).hexdigest()}  {path}\n" for path, data in sorted(files.items())))
    for path in debian.iterdir():
        path.chmod(0o644)
    # Normalize parent modes even when the builder's own umask is restrictive.
    for folder, _, _ in os.walk(stage):
        Path(folder).chmod(0o755)
    architecture = "all" if name == "asb" else "amd64"
    filename = f"{name}_{version}_{architecture}.deb"
    target = output / filename
    if target.exists() or target.is_symlink():
        raise ValueError("refuse to replace an existing candidate")
    temporary = staging / filename
    env = dict(os.environ, SOURCE_DATE_EPOCH=epoch)
    run("dpkg-deb", "--root-owner-group", "-Zgzip", "-z9", "--uniform-compression", "--build", str(stage), str(temporary), env=env)
    inspect_deb(temporary, files, content)
    payload = read_regular(temporary)
    with target.open("xb") as stream:
        stream.write(payload)
    # Inspect the final candidate, including the copy written for delivery.
    inspect_deb(target, files, content)
    return {"package": name, "file": filename, "sha256": sha256(payload), "bytes": len(payload), "architecture": architecture}


def build(args: argparse.Namespace) -> dict:
    if sys.platform != "linux" or platform.machine() != "x86_64":
        raise ValueError("build on Linux amd64; no local installation is performed")
    if not re.fullmatch(r"[0-9][A-Za-z0-9.+~]*-[A-Za-z0-9.+~]+", args.version):
        raise ValueError("provide an explicit Debian upstream-version-revision")
    if not re.fullmatch(r"[^<>\r\n]+ <[^<>\s@]+@[^<>\s@]+>", args.maintainer):
        raise ValueError("provide Maintainer as Name <email>")
    clean_source(args.source_commit)
    run("dpkg", "--validate-version", args.version)
    env = dict(os.environ, GOENV="off", GOWORK="off", GOFLAGS="", CGO_ENABLED="0", GOOS="linux", GOARCH="amd64", GOAMD64="v1", GOTOOLCHAIN=TOOLCHAIN + "+auto")
    if run("go", "env", "GOVERSION", env=env).decode().strip() != TOOLCHAIN:
        raise ValueError("required Go toolchain is unavailable")
    epoch = run("git", "show", "-s", "--format=%ct", args.source_commit).decode().strip()
    selected = ["asb", "asb-tools"] + (["asb-human"] if args.with_human else []) + (["asb-s3"] if args.with_s3 else [])
    output = args.output.resolve()
    if output.exists():
        raise ValueError("output must be a new directory")
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {"schema": "asb.debian-candidates/v1", "source_commit": args.source_commit, "version": args.version,
              "platform": "Linux amd64; Ubuntu 24.04 qualification target", "publication_status": "unpublished",
              "runtime_qualification": "not_run_by_builder", "packages": []}
    with tempfile.TemporaryDirectory(prefix="asb-deb-") as temporary:
        staging = Path(temporary)
        binary_directory = staging / "binaries"
        binary_directory.mkdir()
        package_data = {}
        for name in selected:
            doc = f"usr/share/doc/{name}/"
            copyright_text = b"Copyright (c) Ultraviolet\nCopyright (c) 2026 ToppyMicroServices O\xc3\x9c\nSource: https://github.com/ToppyMicroServices/agents-secure-binding\n\n"
            files = {doc + "copyright": copyright_text + read_regular(ROOT / "LICENSE")}
            changelog = f"asb ({args.version}) UNRELEASED; urgency=medium\n\n  * Build local candidates from {args.source_commit}.\n\n -- {args.maintainer}  {formatdate(int(epoch), localtime=False)}\n"
            files[doc + "changelog.Debian.gz"] = gzip.compress(changelog.encode(), mtime=0)
            document_paths = ("docs/asb-debian-packages.md", "docs/API_COMPATIBILITY.md", *DOCS.get(name, ()))
            destinations = {relative: doc + Path(relative).name for relative in document_paths}
            if name == "asb-s3":
                destinations.update({relative: doc + "examples/" + Path(relative).name for relative in S3_EXAMPLES})
            for relative in document_paths:
                files[destinations[relative]] = package_document(relative, destinations, args.source_commit)
            modules, binaries = {}, {}
            for executable, package in PROGRAMS.get(name, {}).items():
                binary = binary_directory / executable
                run("go", "build", "-mod=readonly", "-trimpath", "-buildvcs=true", "-o", str(binary), package, env=env)
                payload = read_regular(binary)
                validate_static_elf(payload)
                metadata, linked = build_info(binary, args.source_commit, env)
                if metadata["main_path"] != MODULE + package[1:]:
                    raise ValueError("binary entry point differs from requested command")
                for module in linked:
                    key = module["path"] + "@" + module["version"]
                    if key in modules and modules[key] != module:
                        raise ValueError("inconsistent module checksums")
                    modules[key] = module
                files["usr/bin/" + executable] = payload
                binaries[executable] = dict(metadata, sha256=sha256(payload), bytes=len(payload))
            if binaries:
                run("go", "mod", "verify", env=env)
                for relative, payload in collect_notices(list(modules.values()), env).items():
                    files[doc + relative] = payload
            if name == "asb-s3":
                for relative in S3_EXAMPLES:
                    files[destinations[relative]] = read_regular(ROOT / relative)
            inventory = {"schema": "asb.debian-payload/v1", "package": name, "version": args.version, "source_commit": args.source_commit,
                         "binaries": binaries, "modules": sorted(modules.values(), key=lambda item: item["path"]),
                         "runtime_qualification": "not_run_for_this_build", "aws_live_qualification": "not_inherited",
                         "files": {path: sha256(data) for path, data in sorted(files.items())}}
            files[doc + "inventory.json"] = encoded(inventory)
            package_data[name] = files
        clean_source(args.source_commit)
        output.mkdir(mode=0o755)
        for name, files in package_data.items():
            report["packages"].append(write_package(staging, output, name, args.version, args.maintainer, files, epoch))
    (output / "debian-candidates.json").write_bytes(encoded(report))
    (output / "SHA256SUMS").write_text("".join(f"{item['sha256']}  {item['file']}\n" for item in report["packages"]))
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--maintainer", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--with-human", action="store_true")
    parser.add_argument("--with-s3", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(build(args), sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError, IndexError, struct.error, tarfile.TarError, subprocess.SubprocessError) as error:
        print(f"Debian candidate rejected: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
