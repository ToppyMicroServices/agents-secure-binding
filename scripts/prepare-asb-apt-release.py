#!/usr/bin/env python3
"""Prepare unsigned apt metadata from an identified successful Linux artifact."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import zipfile

spec = importlib.util.spec_from_file_location("asb_apt", Path(__file__).with_name("asb-apt-repository.py"))
apt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(apt)
REPOSITORY = "ToppyMicroServices/agents-secure-binding"
WORKFLOW = ".github/workflows/debian-distribution.yaml"
MAX_ARCHIVE = 512 * 1024 * 1024
MAX_MEMBERS = 256
CANDIDATE = "debian-upgrade/debian-candidates.json"
LIFECYCLE = "debian-upgrade-lifecycle.json"


def require(value, reason):
    if not value:
        raise ValueError(reason)


def commit(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value), "use a full source commit")
    return value


def positive_id(value):
    require(type(value) is int and 0 < value < 2 ** 63, "invalid GitHub identifier")
    return value


def authorize(run, listing, run_id, source, publisher, checkout):
    """Bind trusted GitHub API responses to the requested run and local main tree."""
    commit(source)
    commit(publisher)
    positive_id(run_id)
    require(run.get("id") == run_id and type(run.get("id")) is int, "qualification run ID differs")
    require(run.get("repository", {}).get("full_name") == REPOSITORY
            and run.get("head_repository", {}).get("full_name") == REPOSITORY, "qualification must come from this repository")
    require(run.get("path") == WORKFLOW and run.get("event") in ("pull_request", "workflow_dispatch")
            and run.get("status") == "completed" and run.get("conclusion") == "success"
            and run.get("head_sha") == source, "qualification workflow, status or source differs")
    repository_id = positive_id(run["repository"].get("id"))
    require(run["head_repository"].get("id") == repository_id, "fork artifacts cannot authorize publication")
    attempt = positive_id(run.get("run_attempt"))
    entries = listing.get("artifacts")
    require(isinstance(entries, list) and type(listing.get("total_count")) is int
            and listing["total_count"] == len(entries) and len(entries) <= 100, "artifact listing is incomplete")
    expected_name = "asb-debian-" + str(run_id)
    matches = [entry for entry in entries if isinstance(entry, dict) and entry.get("name") == expected_name]
    require(len(matches) == 1, "expected exactly one named qualification artifact")
    artifact = matches[0]
    artifact_id = positive_id(artifact.get("id"))
    require(artifact.get("expired") is False and type(artifact.get("size_in_bytes")) is int
            and 0 < artifact["size_in_bytes"] <= MAX_ARCHIVE, "qualification artifact is expired or exceeds its bound")
    digest = artifact.get("digest")
    require(isinstance(digest, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", digest), "GitHub artifact SHA-256 is required")
    execution = artifact.get("workflow_run", {})
    require(execution.get("id") == run_id and execution.get("head_sha") == source
            and execution.get("repository_id") == repository_id and execution.get("head_repository_id") == repository_id,
            "artifact workflow identity differs")

    def git(*arguments):
        return subprocess.check_output(["git", "-C", str(checkout), *arguments], stderr=subprocess.PIPE, timeout=30).decode().strip()

    require(git("rev-parse", "HEAD") == publisher and not git("status", "--porcelain", "--untracked-files=normal"),
            "preparation requires the clean workflow checkout")
    require(git("cat-file", "-t", source) == "commit", "source is not a commit")
    git("merge-base", "--is-ancestor", source, publisher)
    source_tree = commit(git("rev-parse", source + "^{tree}"))
    publisher_tree = commit(git("rev-parse", publisher + "^{tree}"))
    return {"repository": REPOSITORY, "workflow": WORKFLOW, "run_id": run_id, "run_attempt": attempt,
            "source_commit": source, "source_tree": source_tree, "publisher_commit": publisher, "publisher_tree": publisher_tree,
            "artifact": {"id": artifact_id, "name": expected_name, "sha256": digest.removeprefix("sha256:"),
                         "bytes": artifact["size_in_bytes"]}}


def qualified_payloads(data, authorization):
    """Read only the candidate package set; never extract paths supplied by a zip."""
    identity = authorization["artifact"]
    require(len(data) == identity["bytes"] and apt.sha(data) == identity["sha256"], "download differs from the GitHub artifact digest")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries, total = {}, 0
        require(len(archive.infolist()) <= MAX_MEMBERS, "artifact has too many members")
        for entry in archive.infolist():
            name = entry.filename.removesuffix("/")
            path = PurePosixPath(name)
            mode = entry.external_attr >> 16
            require(name and re.fullmatch(r"[A-Za-z0-9._+~/-]+", name) and not path.is_absolute()
                    and path.as_posix() == name and ".." not in path.parts and name not in entries,
                    "unsafe or duplicate artifact member")
            require(not entry.flag_bits & 1 and stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR)
                    and entry.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), "unsupported artifact member")
            require((not entry.is_dir() or entry.file_size == 0)
                    and stat.S_IFMT(mode) != (stat.S_IFREG if entry.is_dir() else stat.S_IFDIR), "invalid artifact directory")
            total += entry.file_size
            require(0 <= entry.file_size <= apt.MAX_PACKAGE and total <= MAX_ARCHIVE, "artifact decompression exceeds its bound")
            entries[name] = entry

        def read_member(name, maximum=apt.MAX_METADATA):
            entry = entries.get(name)
            require(entry is not None and not entry.is_dir() and entry.file_size <= maximum, "required artifact member is absent or too large")
            with archive.open(entry) as stream:
                payload = stream.read(maximum + 1)
            require(len(payload) == entry.file_size and len(payload) <= maximum, "artifact member length differs")
            return payload

        candidate_bytes, lifecycle_bytes = read_member(CANDIDATE), read_member(LIFECYCLE)
        candidate, lifecycle = apt.strict_json(candidate_bytes), apt.strict_json(lifecycle_bytes)
        require(candidate.get("schema") == "asb.debian-candidates/v1"
                and candidate.get("source_commit") == authorization["source_commit"]
                and candidate.get("publication_status") == "unpublished", "candidate source or schema differs")
        require(lifecycle.get("schema") == "asb.debian-lifecycle/v1" and lifecycle.get("passed") is True
                and lifecycle.get("source_commit") == candidate["source_commit"] and lifecycle.get("version") == candidate.get("version")
                and lifecycle.get("packages") == candidate.get("packages")
                and isinstance(lifecycle.get("checks"), dict) and set(lifecycle["checks"]) == apt.LIFECYCLE_CHECKS
                and all(value is True for value in lifecycle["checks"].values()), "candidate lacks complete successful lifecycle evidence")
        packages, payloads = candidate.get("packages"), {}
        require(isinstance(packages, list) and len(packages) == len(apt.PACKAGES), "candidate package set differs")
        sums = {}
        for line in read_member("debian-upgrade/SHA256SUMS").decode("ascii").splitlines():
            match = re.fullmatch(r"([0-9a-f]{64})  ([a-z0-9+~._-]+\.deb)", line)
            require(match and match[2] not in sums, "invalid package checksum inventory")
            sums[match[2]] = match[1]
        names = set()
        for package in packages:
            require(isinstance(package, dict) and set(package) == {"package", "architecture", "bytes", "sha256", "file"}, "invalid package record")
            name = package["package"]
            require(name in apt.PACKAGES and name not in names and package["architecture"] == apt.PACKAGES[name], "invalid or duplicate package identity")
            names.add(name)
            filename = package["file"]
            require(isinstance(filename, str) and re.fullmatch(r"[a-z0-9+~._-]+\.deb", filename)
                    and filename == f"{name}_{candidate['version']}_{package['architecture']}.deb", "package filename differs from candidate")
            payload = read_member("debian-upgrade/" + filename, apt.MAX_PACKAGE)
            require(type(package["bytes"]) is int and len(payload) == package["bytes"]
                    and apt.sha(payload) == package["sha256"] == sums.get(filename), "package bytes differ from qualified checksums")
            payloads[filename] = payload
        require(set(sums) == set(payloads), "checksum inventory has extra or missing packages")
        require({name for name in entries if name.startswith("debian-upgrade/") and not entries[name].is_dir()}
                == {CANDIDATE, "debian-upgrade/SHA256SUMS"} | {"debian-upgrade/" + name for name in payloads}, "candidate has extra files")
        return candidate_bytes, lifecycle_bytes, payloads


def write_new(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)
    path.chmod(0o644)


def prepare(archive, authorization, output):
    require(sys.platform == "linux", "prepare unsigned release metadata on Linux")
    require(not output.exists() and not output.is_symlink(), "output must be a new directory")
    data = apt.read(archive, MAX_ARCHIVE)
    candidate_bytes, lifecycle_bytes, payloads = qualified_payloads(data, authorization)
    created = int(datetime.now(timezone.utc).timestamp())
    expires = created + apt.MAX_VALIDITY
    with tempfile.TemporaryDirectory(prefix="asb-release-input-") as temporary:
        captured = Path(temporary)
        write_new(captured / "debian-candidates.json", candidate_bytes)
        write_new(captured / "lifecycle.json", lifecycle_bytes)
        for name, payload in payloads.items():
            write_new(captured / name, payload)
        prepared = apt.prepare(argparse.Namespace(artifacts=captured, lifecycle=captured / "lifecycle.json",
                               created=created, expires=expires, output=output / "repository"))
    manifest = apt.inspect_repository(output / "repository")
    require(manifest["source_commit"] == authorization["source_commit"] and manifest["lifecycle_sha256"] == apt.sha(lifecycle_bytes), "prepared source binding differs")
    write_new(output / "evidence/debian-candidates.json", candidate_bytes)
    write_new(output / "evidence/debian-lifecycle.json", lifecycle_bytes)
    inventory = {path.relative_to(output).as_posix(): apt.sha(apt.read(path, apt.MAX_PACKAGE))
                 for path in sorted(output.rglob("*")) if path.is_file()}
    result = {"schema": "asb.apt-release-preparation/v1", "passed": True, "signed": False, "published": False,
              **authorization, "created": created, "expires": expires, "version": manifest["version"],
              "manifest_sha256": prepared["manifest_sha256"], "candidate_sha256": apt.sha(candidate_bytes),
              "lifecycle_sha256": apt.sha(lifecycle_bytes), "files": dict(inventory),
              "limits": ["Unsigned metadata: independent review and offline signing are still required.",
                         "Existing Linux package qualification is reused; no product or package installation runs in preparation.",
                         "Seven-day metadata validity requires renewal; no production key or deployment is configured here."]}
    write_new(output / "prepare-report.json", apt.encoded(result))
    inventory["prepare-report.json"] = apt.sha(apt.encoded(result))
    write_new(output / "SHA256SUMS", "".join(f"{digest}  {name}\n" for name, digest in sorted(inventory.items())).encode())
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("authorize", "prepare"))
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--publisher-commit", required=True)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        authorization = authorize(apt.strict_json(apt.read(args.run)), apt.strict_json(apt.read(args.artifacts)),
                                  args.run_id, args.source_commit, args.publisher_commit, args.checkout)
        if args.command == "authorize":
            write_new(args.output, apt.encoded(authorization))
            result = authorization
        else:
            require(args.archive is not None, "prepare requires the downloaded artifact archive")
            result = prepare(args.archive, authorization, args.output)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, KeyError, TypeError, AttributeError, UnicodeError, OSError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        detail = str(error) if isinstance(error, ValueError) else type(error).__name__
        print("Unsigned apt preparation failed: " + detail, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
