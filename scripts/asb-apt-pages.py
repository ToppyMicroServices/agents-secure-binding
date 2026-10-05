#!/usr/bin/env python3
"""Stage and inspect signed ASB apt bytes for the selected GitHub Pages site."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import html
import importlib.util
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
from urllib.parse import quote
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener

spec = importlib.util.spec_from_file_location("asb_apt", Path(__file__).with_name("asb-apt-repository.py"))
apt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(apt)
BASE_URL = "https://toppymicroservices.github.io/agents-secure-binding"
MAX_SITE = 512 * 1024 * 1024
MAX_FILES = 128


def policy(path: Path) -> dict:
    # This schema contains public fingerprints and hashes only, never credentials.
    value = apt.strict_json(apt.read(path))
    if (set(value) != {"schema", "base_url", "signers", "keyring_sha256"}
            or value["schema"] != "asb.apt-pages-policy/v1" or value["base_url"] != BASE_URL
            or not isinstance(value["signers"], list) or not 1 <= len(value["signers"]) <= 2
            or len(set(value["signers"])) != len(value["signers"])
            or not re.fullmatch(r"[0-9a-f]{64}", value["keyring_sha256"])):
        raise ValueError("invalid or unconfigured publication policy")
    for identity in value["signers"]:
        apt.fingerprint(identity)
    return value


def safe_path(name: str) -> None:
    path = PurePosixPath(name)
    if (not re.fullmatch(r"[A-Za-z0-9._+~/-]+", name) or path.is_absolute()
            or name != path.as_posix() or any(part in ("..", ".git", ".aws") for part in path.parts)):
        raise ValueError("unsafe publication path")


def public_keyring(data: bytes, public_policy: dict) -> None:
    if apt.sha(data) != public_policy["keyring_sha256"]:
        raise ValueError("public keyring differs from the approved policy")
    with tempfile.TemporaryDirectory(prefix="asb-pages-keyring-") as temporary:
        home = Path(temporary)
        key = home / "keyring.gpg"
        key.write_bytes(data)
        output = apt.execute("gpg", "--homedir", str(home), "--no-options", "--batch", "--with-colons",
                             "--import-options", "show-only", "--import", str(key)).decode()
    records = [line.split(":") for line in output.splitlines()]
    identities = [item[9] for item in records if item[0] == "fpr"]
    if (any(item[0] in ("sec", "ssb") for item in records)
            or len(identities) != len(public_policy["signers"]) or set(identities) != set(public_policy["signers"])):
        raise ValueError("keyring must contain only the approved standalone public signing keys")


def web_files(manifest: dict, public_policy: dict) -> dict[str, bytes]:
    source = apt.source(public_policy["base_url"] + "/apt")
    identities = "\n".join(public_policy["signers"])
    page = f'''<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>ASB apt preview packages</title>
<h1>ASB apt preview packages</h1>
<p>Signed Linux amd64 preview packages for ASB tools and optional Human/S3 applications.
Signing authenticates the package source; it does not make every ASB component production-qualified.</p>
<p>Version: <code>{html.escape(manifest['version'])}</code>.
Source: <a href="https://github.com/ToppyMicroServices/agents-secure-binding/commit/{manifest['source_commit']}">{manifest['source_commit']}</a>.
Metadata expires: {datetime.fromtimestamp(manifest['expires'], timezone.utc).isoformat()}.</p>
<p>Verify the signing fingerprint against the
<a href="https://github.com/ToppyMicroServices/agents-secure-binding/blob/main/packaging/debian/archive-signers.json">repository trust policy</a>
before installing the <a href="asb-archive.gpg">public keyring</a> at
<code>/etc/apt/keyrings/asb-archive.gpg</code> with mode 0644.</p>
<pre>{html.escape(identities)}</pre>
<p>Install <a href="asb.sources">this source file</a> at
<code>/etc/apt/sources.list.d/asb.sources</code>, then run:</p>
<pre>sudo apt-get update
sudo apt-get install asb</pre>
<p><code>asb-human</code> and <code>asb-s3</code> are explicit optional packages.
Installation does not provision credentials or enable services.
See the <a href="https://github.com/ToppyMicroServices/agents-secure-binding/blob/main/docs/asb-debian-packages.md">component support and operations documentation</a>.</p>
</html>
'''
    return {".nojekyll": b"", "asb.sources": source.encode(), "index.html": page.encode()}


def file_map(root: Path) -> dict[str, bytes]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("site must be a regular directory")
    result, total, directories = {}, 0, 0
    for directory, folders, files in os.walk(root, followlinks=False):
        directories += len(folders)
        if directories > MAX_FILES:
            raise ValueError("publication exceeds directory bound")
        for name in folders + files:
            member = Path(directory) / name
            if not (stat.S_ISREG(member.lstat().st_mode) or stat.S_ISDIR(member.lstat().st_mode)):
                raise ValueError("site contains a symlink or special file")
        for name in files:
            member = Path(directory) / name
            relative = member.relative_to(root).as_posix()
            safe_path(relative)
            data = apt.read(member, apt.MAX_PACKAGE)
            total += len(data)
            if total > MAX_SITE or len(result) >= MAX_FILES:
                raise ValueError("publication exceeds site bounds")
            result[relative] = data
    return result


def write_new(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)
    path.chmod(0o644)


@contextmanager
def snapshot_site(root: Path):
    # All subsequent trust checks and delivered bytes use this private snapshot.
    with tempfile.TemporaryDirectory(prefix="asb-pages-snapshot-") as temporary:
        captured = Path(temporary) / "site"
        captured.mkdir()
        for name, data in file_map(root).items():
            write_new(captured / name, data)
        yield captured


def verify_site(root: Path, public_policy: dict, expected_source: str) -> dict:
    with snapshot_site(root) as captured:
        return _verify_snapshot(captured, public_policy, expected_source)


def _verify_snapshot(root: Path, public_policy: dict, expected_source: str) -> dict:
    files = file_map(root)
    document = apt.strict_json(files.get("publication.json", b"{}"))
    if set(document) != {"schema", "source_commit", "version", "expires", "signer", "manifest_sha256", "files"}:
        raise ValueError("invalid publication inventory")
    if document["schema"] != "asb.apt-pages/v1" or document["source_commit"] != expected_source:
        raise ValueError("publication source differs from the approved source")
    if not isinstance(document["files"], dict) or set(document["files"]) != set(files) - {"publication.json"}:
        raise ValueError("publication has missing or extra files")
    for name, digest in document["files"].items():
        if apt.sha(files[name]) != digest:
            raise ValueError("publication bytes differ from inventory")
    public_keyring(files["asb-archive.gpg"], public_policy)
    result = apt.verify(argparse.Namespace(repository=root / "apt", keyring=root / "asb-archive.gpg", signer=public_policy["signers"]))
    for field in ("source_commit", "version", "expires", "signer", "manifest_sha256"):
        if document[field] != result[field]:
            raise ValueError("publication metadata differs from signed apt metadata")
    manifest = apt.inspect_repository(root / "apt")
    generated = web_files(manifest, public_policy)
    expected = set(generated) | {"asb-archive.gpg", "publication.json"} | {"apt/" + name for name in file_map(root / "apt")}
    if set(files) != expected or any(files[name] != data for name, data in generated.items()):
        raise ValueError("site includes unreviewed content")
    return {"schema": "asb.apt-pages-verification/v1", "passed": True, "source_commit": result["source_commit"],
            "version": result["version"], "signer": result["signer"], "files": len(files), "expires": result["expires"], "published": False}


def stage(repository: Path, keyring: Path, public_policy: dict, expected_source: str, output: Path) -> dict:
    if output.exists() or output.is_symlink():
        raise ValueError("output must be a new directory")
    # Copy only the strict repository inventory, then authenticate that copy.
    manifest = apt.inspect_repository(repository)
    if manifest["source_commit"] != expected_source:
        raise ValueError("repository source differs from approved source")
    snapshot = file_map(repository)
    key = apt.read(keyring, 1024 * 1024)
    public_keyring(key, public_policy)
    output.mkdir(parents=True, mode=0o755)
    for name, data in snapshot.items():
        write_new(output / "apt" / name, data)
    write_new(output / "asb-archive.gpg", key)
    checked = apt.verify(argparse.Namespace(repository=output / "apt", keyring=output / "asb-archive.gpg", signer=public_policy["signers"]))
    if checked["source_commit"] != expected_source:
        raise ValueError("copied source differs from approved source")
    manifest = apt.inspect_repository(output / "apt")
    for name, data in web_files(manifest, public_policy).items():
        write_new(output / name, data)
    inventory = {"schema": "asb.apt-pages/v1", **{key: checked[key] for key in ("source_commit", "version", "expires", "signer", "manifest_sha256")},
                 "files": {name: apt.sha(data) for name, data in file_map(output).items()}}
    write_new(output / "publication.json", apt.encoded(inventory))
    return verify_site(output, public_policy, expected_source)


def pack(site: Path, public_policy: dict, source: str, output: Path) -> dict:
    if output.exists() or output.is_symlink():
        raise ValueError("archive output already exists")
    # The private captured tree is reverified; never publish a later mutable read.
    with snapshot_site(site) as captured:
        _verify_snapshot(captured, public_policy, source)
        captured_files = file_map(captured)
        write_new(output, canonical_archive(captured_files))
    return {"packed": True, "sha256": apt.sha(apt.read(output, MAX_SITE)), "bytes": output.stat().st_size}


def canonical_archive(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in sorted(files.items()):
            item = tarfile.TarInfo(name)
            item.size, item.mode, item.mtime = len(data), 0o644, 0
            archive.addfile(item, io.BytesIO(data))
    result = buffer.getvalue()
    if len(result) > MAX_SITE:
        raise ValueError("archive exceeds site bound")
    return result


def unpack(archive: Path, expected_digest: str, output: Path) -> None:
    if output.exists() or output.is_symlink() or not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
        raise ValueError("invalid archive destination or hash")
    data = apt.read(archive, MAX_SITE)
    if apt.sha(data) != expected_digest:
        raise ValueError("archive hash differs from approved bytes")
    entries, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as bundle:
        for item in bundle:
            safe_path(item.name)
            if (not item.isfile() or item.name in entries or item.pax_headers or item.uid != 0 or item.gid != 0
                    or item.mode != 0o644 or not 0 <= item.size <= apt.MAX_PACKAGE):
                raise ValueError("archive has duplicate, linked or noncanonical members")
            total += item.size
            if total > MAX_SITE or len(entries) >= MAX_FILES:
                raise ValueError("archive exceeds bounds")
            entries[item.name] = bundle.extractfile(item).read(item.size + 1)
            if len(entries[item.name]) != item.size:
                raise ValueError("truncated archive member")
    if not entries or canonical_archive(entries) != data:
        raise ValueError("empty or noncanonical publication archive")
    output.mkdir(parents=True, mode=0o755)
    for name, payload in entries.items():
        write_new(output / name, payload)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("publication verification rejects redirects")


def verify_live(site: Path, public_policy: dict, source: str) -> dict:
    with snapshot_site(site) as captured:
        result = _verify_snapshot(captured, public_policy, source)
        files = file_map(captured)
    opener = build_opener(HTTPSHandler(), NoRedirect())
    for name, expected in sorted(files.items()):
        uri = public_policy["base_url"] + "/" + quote(name, safe="/._+~-")
        request = Request(uri, headers={"Accept-Encoding": "identity", "User-Agent": "ASB-publication-verifier"})
        with opener.open(request, timeout=30) as response:
            if response.status != 200 or response.geturl() != uri or response.headers.get("Content-Encoding", "identity") != "identity":
                raise ValueError("unexpected HTTPS publication response")
            delivered = response.read(len(expected) + 1)
        if delivered != expected:
            raise ValueError("published bytes differ from approved site: " + name)
    return result | {"published": True, "transport": "https", "base_url": public_policy["base_url"],
                     "verified_at": datetime.now(timezone.utc).isoformat()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("stage", "pack", "unpack", "verify", "verify-live"))
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--repository", type=Path)
    parser.add_argument("--keyring", type=Path)
    parser.add_argument("--site", type=Path)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--sha256")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        public_policy = policy(args.policy)
        if not re.fullmatch(r"[0-9a-f]{40}", args.source_commit):
            raise ValueError("use the full approved source commit")
        if args.command == "stage":
            result = stage(args.repository, args.keyring, public_policy, args.source_commit, args.output)
        elif args.command == "pack":
            result = pack(args.site, public_policy, args.source_commit, args.output)
        elif args.command == "unpack":
            unpack(args.archive, args.sha256, args.output)
            result = verify_site(args.output, public_policy, args.source_commit)
        else:
            result = (verify_live if args.command == "verify-live" else verify_site)(args.site, public_policy, args.source_commit)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError, AttributeError, UnicodeError, tarfile.TarError, subprocess.SubprocessError) as error:
        detail = str(error) if type(error) is ValueError else type(error).__name__
        print("apt publication rejected: " + detail, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
