#!/usr/bin/env python3
"""Adversarial archive tests; run on the Linux distribution job."""

import importlib.util
import gzip
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("package_s3", Path(__file__).with_name("package-s3.py"))
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class DistributionTest(unittest.TestCase):
    def setUp(self):
        self.files = {name: b"fixture\n" for name in package.FILES}
        self.files.update({"bin/asb-s3": b"fixture executable", "build-info.txt": b"fixture", "modules.json": b"[]", "licenses/go/LICENSE": b"fixture license"})
        self.record = {
            "schema": "asb.s3-qualified-candidate/v1",
            "candidate": "asb-s3-v0.1.0-rc.1", "source_commit": "a" * 40, "run_id": 1,
            "binary_sha256": package.digest(self.files["bin/asb-s3"]),
            "qualified_packaging_sha256": {name: package.digest(self.files[name]) for name in (
                "packaging/s3/asb-s3.service", "packaging/s3/config.example.json", "packaging/s3/journald-asb-s3.conf")},
        }
        self.files[package.RECORD] = package.encoded(self.record)
        self.manifest = {"schema": "asb.s3-distribution/v1", "candidate": self.record["candidate"], "binary_source_commit": self.record["source_commit"], "qualification_run": 1}
        self.data = package.archive_bytes(self.files, self.manifest)

    def verify(self, data):
        return package.verify_archive(data, self.record)

    def rewrite(self, transform):
        output = io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(self.data), mode="r:gz") as source:
            entries = [(member, source.extractfile(member).read()) for member in source]
        with tarfile.open(fileobj=output, mode="w:gz") as target:
            for member, data in transform(entries):
                target.addfile(member, io.BytesIO(data))
        return output.getvalue()

    def test_complete_archive_is_deterministic(self):
        self.assertEqual(self.data, package.archive_bytes(self.files, self.manifest))
        self.assertEqual(len(self.verify(self.data)["files"]), len(self.files))

    def test_changed_payload_fails(self):
        altered = self.rewrite(lambda entries: [(m, b"x" * len(d) if m.name.endswith("/bin/asb-s3") else d) for m, d in entries])
        with self.assertRaisesRegex(ValueError, "hash or mode"):
            self.verify(altered)

    def test_missing_added_and_duplicate_members_fail(self):
        def added(entries):
            member = tarfile.TarInfo(self.record["candidate"] + "/unexpected")
            return entries + [(member, b"")]
        for transform in (lambda entries: entries[1:], added, lambda entries: entries + entries[:1]):
            with self.subTest(transform=transform), self.assertRaises(ValueError):
                self.verify(self.rewrite(transform))

    def test_links_and_unsafe_paths_fail(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE, tarfile.FIFOTYPE):
            def changed(entries):
                entries[0][0].type = kind
                entries[0][0].linkname = "/etc/passwd"
                entries[0][0].size = 0
                return entries
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "unsafe"):
                self.verify(self.rewrite(changed))
        for name in ("/tmp/injected", "root/../injected", "root//injected", "root/./injected", "root/back\\slash"):
            def renamed(entries):
                entries[0][0].name = name
                return entries
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.verify(self.rewrite(renamed))

    def test_executable_and_privilege_modes_are_checked(self):
        for mode in (0o644, 0o4755, 0o777):
            def changed(entries):
                for member, _ in entries:
                    if member.name.endswith("/bin/asb-s3"):
                        member.mode = mode
                return entries
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, "hash or mode"):
                self.verify(self.rewrite(changed))

    def test_expansion_and_entry_limits(self):
        with mock.patch.object(package, "MAX_BYTES", len(self.data) + 1), self.assertRaisesRegex(ValueError, "expanded"):
            self.verify(self.data)
        with mock.patch.object(package, "MAX_FILES", 1), self.assertRaises(ValueError):
            self.verify(self.data)

    def test_rehashed_different_binary_is_not_qualified(self):
        self.files["bin/asb-s3"] = b"different build"
        with self.assertRaisesRegex(ValueError, "qualification"):
            self.verify(package.archive_bytes(self.files, self.manifest))

    def test_compressed_extended_header_is_bounded_before_tar_parsing(self):
        header = tarfile.TarInfo("pax")
        header.type = tarfile.XHDTYPE
        header.size = 65536
        compressed = gzip.compress(header.tobuf() + b"x" * header.size)
        with mock.patch.object(package, "MAX_BYTES", 8192), self.assertRaisesRegex(ValueError, "expanded"):
            self.verify(compressed)

    def test_changed_service_does_not_inherit_qualification(self):
        self.files["packaging/s3/asb-s3.service"] = b"changed service"
        with self.assertRaisesRegex(ValueError, "service packaging"):
            self.verify(package.archive_bytes(self.files, self.manifest))

    def test_archive_cannot_remove_or_replace_trusted_qualification(self):
        for change in ({"qualified_packaging_sha256": {}}, {"schema": "unknown"}, {"source_commit": "b" * 40}):
            with self.subTest(change=change):
                self.files[package.RECORD] = package.encoded(dict(self.record, **change))
                with self.assertRaisesRegex(ValueError, "trusted checkout"):
                    self.verify(package.archive_bytes(self.files, self.manifest))

    def test_input_symlinks_and_fifos_are_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "regular").write_bytes(b"ok")
            (root / "link").symlink_to(root / "regular")
            os.mkfifo(root / "fifo")
            with self.assertRaises(OSError):
                package.read_regular(root / "link")
            with self.assertRaises(ValueError):
                package.read_regular(root / "fifo")

    def test_packager_rejects_unqualified_input_before_go(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "binary").write_bytes(b"different executable")
            with mock.patch.object(package, "command") as command, self.assertRaisesRegex(ValueError, "live-qualified"):
                package.create(root / "binary", root / "output.tar.gz")
            command.assert_not_called()
            self.assertFalse((root / "output.tar.gz").exists())

    def test_signature_requires_expected_signer_and_exact_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "gnupg"
            home.mkdir(mode=0o700)
            env = dict(os.environ, GNUPGHOME=str(home))
            def gpg(*args):
                return subprocess.check_output(["gpg", "--batch", *args], env=env, stderr=subprocess.DEVNULL, timeout=30)
            try:
                gpg("--passphrase", "", "--quick-generate-key", "ASB distribution test <test@example.invalid>", "ed25519", "sign", "1d")
                fingerprint = next(line.split(":")[9] for line in gpg("--with-colons", "--list-keys").decode().splitlines() if line.startswith("fpr:"))
                archive = root / "candidate.tar.gz"
                archive.write_bytes(self.data)
                gpg("--armor", "--detach-sign", str(archive))
                signature = root / "candidate.tar.gz.asc"
                with mock.patch.dict(os.environ, env):
                    package.verify_signature(self.data, signature, fingerprint)
                    with self.assertRaisesRegex(ValueError, "not trusted"):
                        package.verify_signature(self.data, signature, "0" * 40)
                    with self.assertRaises(ValueError):
                        package.verify_signature(self.data + b"tamper", signature, fingerprint)
            finally:
                subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"], check=False, timeout=30)

    def test_signed_cli_requires_clean_packaging_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / package.RECORD).parent.mkdir(parents=True)
            (root / package.RECORD).write_bytes(package.encoded(self.record))
            archive = root / "candidate.tar.gz"
            for dirty, expected in ((False, 0), (True, 2), (None, 2)):
                manifest = dict(self.manifest)
                if dirty is not None:
                    manifest["packaging_tree_modified"] = dirty
                archive.write_bytes(package.archive_bytes(self.files, manifest))
                arguments = ["package-s3.py", "verify", str(archive), "--signature", "fixture.asc", "--trusted-signer", "A" * 40]
                with self.subTest(dirty=dirty), mock.patch.object(package, "ROOT", root), \
                        mock.patch.object(package.sys, "argv", arguments), \
                        mock.patch.object(package, "verify_signature") as signature, \
                        contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(package.main(), expected)
                    signature.assert_called_once()


if __name__ == "__main__":
    unittest.main()
