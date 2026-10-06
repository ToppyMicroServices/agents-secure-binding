#!/usr/bin/env python3
"""Check source-run binding and unsigned release preparation without deployment."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

spec = importlib.util.spec_from_file_location("release_prepare", Path(__file__).with_name("prepare-asb-apt-release.py"))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)
SOURCE, PUBLISHER = "a" * 40, "b" * 40
RUN_ID, REPO_ID = 1234, 5678


def fixture(payloads=None):
    version = "0.1.0~preview.1-2"
    packages, files = [], {}
    for name, architecture in release.apt.PACKAGES.items():
        filename = f"{name}_{version}_{architecture}.deb"
        payload = payloads[name] if payloads else ("qualified test bytes: " + name).encode()
        packages.append({"package": name, "architecture": architecture, "file": filename,
                         "bytes": len(payload), "sha256": release.apt.sha(payload)})
        files["debian-upgrade/" + filename] = payload
    candidate = {"schema": "asb.debian-candidates/v1", "source_commit": SOURCE, "version": version,
                 "publication_status": "unpublished", "packages": packages}
    lifecycle = {"schema": "asb.debian-lifecycle/v1", "source_commit": SOURCE, "version": version,
                 "passed": True, "packages": packages, "checks": dict.fromkeys(release.apt.LIFECYCLE_CHECKS, True)}
    files[release.CANDIDATE] = release.apt.encoded(candidate)
    files[release.LIFECYCLE] = release.apt.encoded(lifecycle)
    files["debian-upgrade/SHA256SUMS"] = "".join(item["sha256"] + "  " + item["file"] + "\n" for item in packages).encode()
    return files


def zipped(files, extra=()):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in list(files.items()) + list(extra):
            archive.writestr(name, payload)
    return output.getvalue()


def metadata(data):
    repository = {"id": REPO_ID, "full_name": release.REPOSITORY}
    run = {"id": RUN_ID, "repository": repository, "head_repository": dict(repository), "path": release.WORKFLOW,
           "event": "pull_request", "status": "completed", "conclusion": "success", "head_sha": SOURCE, "run_attempt": 1}
    artifact = {"id": 999, "name": "asb-debian-" + str(RUN_ID), "expired": False,
                "size_in_bytes": len(data), "digest": "sha256:" + release.apt.sha(data),
                "workflow_run": {"id": RUN_ID, "head_sha": SOURCE, "repository_id": REPO_ID, "head_repository_id": REPO_ID}}
    return run, {"total_count": 1, "artifacts": [artifact]}


def git_output(command, **_):
    arguments = command[3:]
    if arguments == ["rev-parse", "HEAD"]:
        return PUBLISHER.encode()
    if arguments == ["cat-file", "-t", SOURCE]:
        return b"commit"
    if arguments[:1] == ["rev-parse"]:
        return (("c" if arguments[1].startswith(SOURCE) else "d") * 40).encode()
    return b""


def authorized(data):
    run, listing = metadata(data)
    with patch.object(release.subprocess, "check_output", side_effect=git_output):
        return release.authorize(run, listing, RUN_ID, SOURCE, PUBLISHER, Path("/checkout"))


class ReleasePreparationTests(unittest.TestCase):
    def test_exact_source_run_and_archive_are_bound(self):
        data = zipped(fixture())
        binding = authorized(data)
        self.assertEqual(binding["source_commit"], SOURCE)
        self.assertEqual(binding["publisher_commit"], PUBLISHER)
        self.assertEqual(binding["artifact"]["sha256"], release.apt.sha(data))
        candidate, lifecycle, payloads = release.qualified_payloads(data, binding)
        self.assertEqual(json.loads(candidate)["source_commit"], SOURCE)
        self.assertEqual(json.loads(lifecycle)["packages"], json.loads(candidate)["packages"])
        self.assertEqual(len(payloads), 4)

    def test_wrong_repo_workflow_run_source_status_and_fork_are_rejected(self):
        original, listing = metadata(zipped(fixture()))
        changes = [lambda r: r.update(id=RUN_ID + 1), lambda r: r.update(id=True),
                   lambda r: r["repository"].update(full_name="other/repo"),
                   lambda r: r["head_repository"].update(full_name="fork/repo"),
                   lambda r: r["head_repository"].update(id=REPO_ID + 1),
                   lambda r: r.update(path=".github/workflows/other.yaml"), lambda r: r.update(event="push"),
                   lambda r: r.update(status="in_progress"), lambda r: r.update(conclusion="failure"),
                   lambda r: r.update(head_sha="e" * 40), lambda r: r.update(run_attempt=0)]
        for change in changes:
            run = copy.deepcopy(original)
            change(run)
            with self.subTest(run=run), patch.object(release.subprocess, "check_output", side_effect=AssertionError("reject before Git")), self.assertRaises(ValueError):
                release.authorize(run, listing, RUN_ID, SOURCE, PUBLISHER, Path("/checkout"))

    def test_ambiguous_expired_unhashed_and_wrong_run_artifacts_are_rejected(self):
        run, original = metadata(zipped(fixture()))
        changes = [lambda a: a.update(total_count=2), lambda a: a.update(artifacts=[]),
                   lambda a: a.update(total_count=2, artifacts=a["artifacts"] * 2),
                   lambda a: a["artifacts"][0].update(expired=True), lambda a: a["artifacts"][0].pop("digest"),
                   lambda a: a["artifacts"][0].update(size_in_bytes=release.MAX_ARCHIVE + 1),
                   lambda a: a["artifacts"][0].update(name="wrong"),
                   lambda a: a["artifacts"][0]["workflow_run"].update(id=RUN_ID + 1),
                   lambda a: a["artifacts"][0]["workflow_run"].update(head_repository_id=REPO_ID + 1),
                   lambda a: a["artifacts"][0]["workflow_run"].update(head_sha="e" * 40)]
        for change in changes:
            listing = copy.deepcopy(original)
            change(listing)
            with self.subTest(listing=listing), patch.object(release.subprocess, "check_output", side_effect=AssertionError("reject before Git")), self.assertRaises(ValueError):
                release.authorize(run, listing, RUN_ID, SOURCE, PUBLISHER, Path("/checkout"))

    def test_checkout_must_match_clean_publisher_and_source_ancestry(self):
        run, listing = metadata(zipped(fixture()))
        for failure in ("different-head", "dirty", "nonancestor"):
            def changed(command, **kwargs):
                args = command[3:]
                if failure == "different-head" and args == ["rev-parse", "HEAD"]:
                    return b"e" * 40
                if failure == "dirty" and args[0] == "status":
                    return b" M source.py"
                if failure == "nonancestor" and args[0] == "merge-base":
                    raise subprocess.CalledProcessError(1, command)
                return git_output(command, **kwargs)
            with self.subTest(failure=failure), patch.object(release.subprocess, "check_output", side_effect=changed), self.assertRaises((ValueError, subprocess.CalledProcessError)):
                release.authorize(run, listing, RUN_ID, SOURCE, PUBLISHER, Path("/checkout"))

    def test_downloaded_archive_hash_is_checked_before_zip_processing(self):
        data = zipped(fixture())
        binding = authorized(data)
        for invalid in (data[:-1], data + b"changed"):
            with self.assertRaisesRegex(ValueError, "GitHub artifact digest"):
                release.qualified_payloads(invalid, binding)

    def test_traversal_links_and_duplicate_members_are_never_extracted(self):
        symlink = zipfile.ZipInfo("link")
        symlink.create_system = 3
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        extras = [("../outside", b"x"), ("/absolute", b"x"), (symlink, b"private"), (release.CANDIDATE, b"duplicate")]
        for extra in extras:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                data = zipped(fixture(), [extra])
            with self.subTest(extra=str(extra[0])), self.assertRaises(ValueError):
                release.qualified_payloads(data, authorized(data))

    def test_missing_or_failed_lifecycle_cannot_authorize_package_bytes(self):
        for change in (lambda value: value.update(passed=False), lambda value: value.update(checks={}),
                       lambda value: value["checks"].update(apt_install=False),
                       lambda value: value.update(source_commit="e" * 40), lambda value: value.update(version="9.0-1")):
            files = fixture()
            lifecycle = json.loads(files[release.LIFECYCLE])
            change(lifecycle)
            files[release.LIFECYCLE] = release.apt.encoded(lifecycle)
            data = zipped(files)
            with self.assertRaisesRegex(ValueError, "lifecycle"):
                release.qualified_payloads(data, authorized(data))

    def test_tampered_package_checksum_inventory_and_extra_candidate_are_rejected(self):
        for change in ("package", "checksum", "extra", "wrong-source", "duplicate-json"):
            files = fixture()
            if change == "package":
                name = next(key for key in files if key.endswith(".deb"))
                files[name] += b"tampered"
            elif change == "checksum":
                files["debian-upgrade/SHA256SUMS"] += b"a" * 64 + b"  extra.deb\n"
            elif change == "extra":
                files["debian-upgrade/private.txt"] = b"unreviewed"
            elif change == "wrong-source":
                candidate = json.loads(files[release.CANDIDATE]); candidate["source_commit"] = "e" * 40
                files[release.CANDIDATE] = release.apt.encoded(candidate)
            else:
                files[release.CANDIDATE] = b'{"schema":"first","schema":"second"}'
            data = zipped(files)
            with self.subTest(change=change), self.assertRaises(ValueError):
                release.qualified_payloads(data, authorized(data))

    @unittest.skipUnless(sys.platform == "linux", "real Debian metadata preparation runs on Linux")
    def test_final_unsigned_repository_matches_qualified_packages_and_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payloads = {}
            for name, architecture in release.apt.PACKAGES.items():
                tree = root / name
                (tree / "DEBIAN").mkdir(parents=True)
                (tree / "DEBIAN/control").write_text(f"Package: {name}\nVersion: 0.1.0~preview.1-2\nArchitecture: {architecture}\nMaintainer: Test <test@example.invalid>\nDescription: Synthetic metadata fixture\n")
                package = root / (name + ".deb")
                subprocess.run(["dpkg-deb", "--build", "--root-owner-group", str(tree), str(package)], check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
                payloads[name] = package.read_bytes()
            data = zipped(fixture(payloads))
            archive = root / "artifact.zip"; archive.write_bytes(data)
            output = root / "unsigned"
            report = release.prepare(archive, authorized(data), output)
            stored = json.loads((output / "prepare-report.json").read_bytes())
            self.assertEqual(stored, report)
            self.assertFalse(stored["signed"])
            self.assertFalse(stored["published"])
            self.assertEqual(stored["expires"] - stored["created"], 7 * 86400)
            manifest = release.apt.inspect_repository(output / "repository")
            self.assertEqual(manifest["source_commit"], SOURCE)
            self.assertEqual(manifest["lifecycle_sha256"], stored["lifecycle_sha256"])
            self.assertEqual(release.apt.sha((output / "repository/dists/asb-preview/manifest.json").read_bytes()), stored["manifest_sha256"])
            self.assertFalse((output / "repository/dists/asb-preview/InRelease").exists())
            self.assertFalse((output / "repository/dists/asb-preview/Release.gpg").exists())
            for name, digest in stored["files"].items():
                self.assertEqual(release.apt.sha((output / name).read_bytes()), digest)
            checksums = {name: digest for digest, name in (line.split("  ", 1) for line in (output / "SHA256SUMS").read_text().splitlines())}
            self.assertEqual(set(checksums), set(stored["files"]) | {"prepare-report.json"})
            for name, digest in checksums.items():
                self.assertEqual(release.apt.sha((output / name).read_bytes()), digest)


if __name__ == "__main__":
    unittest.main()
