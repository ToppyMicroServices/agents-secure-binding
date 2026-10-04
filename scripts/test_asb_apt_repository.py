#!/usr/bin/env python3
"""Reject malformed metadata before it can become an ASB apt signing input."""

import argparse
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("asb_apt", Path(__file__).with_name("asb-apt-repository.py"))
apt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(apt)


def fixture():
    manifest = {"schema": "asb.apt-repository/v1", "created": 100, "expires": 200,
                "source_commit": "a" * 40, "version": "0.1.0~preview.1-1", "lifecycle_sha256": "b" * 64, "packages": []}
    for name, architecture in (("asb", "all"), ("asb-tools", "amd64")):
        payload = b"package fixture, never executed"
        manifest["packages"].append({"package": name, "architecture": architecture,
            "path": f"pool/main/a/asb/{name}_{manifest['version']}_{architecture}.deb", "bytes": len(payload), "sha256": apt.sha(payload),
            "control": f"Package: {name}\nVersion: {manifest['version']}\nArchitecture: {architecture}\nDescription: fixture\n"})
    return manifest


class AptRepositoryTest(unittest.TestCase):
    def test_approved_signer_requires_exact_fingerprint(self):
        self.assertEqual(apt.fingerprint("A" * 40), "A" * 40)
        for value in ("A" * 16, "a" * 40, "A" * 40 + "!", "user@example.invalid", "-option"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                apt.fingerprint(value)

    def test_time_bounds_reject_expiry_future_and_excessive_validity(self):
        apt.validate_dates(100, 200, 100)
        apt.validate_dates(110, 200, 100)
        for created, expires, now in ((100, 200, 200), (111, 200, 100), (200, 100, 100), (100, 100 + apt.MAX_VALIDITY + 1, 100), (True, 200, 100)):
            with self.subTest(created=created, expires=expires, now=now), self.assertRaises(ValueError):
                apt.validate_dates(created, expires, now)

    def test_source_is_narrow_and_preserves_apt_checks(self):
        result = apt.source("https://packages.example.invalid/asb")
        self.assertIn("Signed-By: /etc/apt/keyrings/asb-archive.gpg\n", result)
        self.assertIn("Check-Valid-Until: yes\n", result)
        self.assertNotIn("Trusted:", result)
        for uri in ("http://example.invalid", "https://u:p@example.invalid", "https://example.invalid\nTrusted: yes", "https://example.invalid?token=a", "file:/tmp/repository"):
            with self.subTest(uri=uri), self.assertRaises(ValueError):
                apt.source(uri)

    def test_json_duplicates_and_control_injection_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            apt.strict_json(b'{"created":100,"created":200}')
        for value in ("Package: asb\nPackage: other\n", "Package: asb\n\nPackage: other\n", "Package: asb\r\n"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                manifest = fixture()
                manifest["packages"][0]["control"] = value
                apt.validate_manifest(manifest)
        manifest = fixture()
        manifest["packages"][0]["control"] += "Filename: ../../etc/passwd\n"
        with self.assertRaisesRegex(ValueError, "control"):
            apt.validate_manifest(manifest)

    def test_manifest_rejects_unknown_fields_paths_duplicates_and_identity(self):
        for change in (lambda data: data.update(extra=True),
                       lambda data: data["packages"].append(data["packages"][0]),
                       lambda data: data["packages"][0].update(path="../../etc/passwd"),
                       lambda data: data["packages"][0].update(bytes=True),
                       lambda data: data["packages"][0].update(architecture="amd64"),
                       lambda data: data.update(packages=[data["packages"][0]])):
            manifest = fixture()
            change(manifest)
            with self.assertRaises(ValueError):
                apt.validate_manifest(manifest)

    def test_final_repository_bytes_paths_and_extra_files_are_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = fixture()
            content = apt.metadata(manifest)
            for item in manifest["packages"]:
                content[item["path"]] = b"package fixture, never executed"
            for name, data in content.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            self.assertEqual(apt.inspect_repository(root), manifest)
            self.assertEqual(apt.metadata(manifest), apt.metadata(manifest))
            release = root / apt.DIST / "Release"
            release.write_bytes(release.read_bytes() + b"Trusted: yes\n")
            with self.assertRaisesRegex(ValueError, "differs"):
                apt.inspect_repository(root)
            release.write_bytes(content[str(apt.DIST / "Release")])
            extra = root / "extra"
            extra.write_bytes(b"unexpected")
            with self.assertRaisesRegex(ValueError, "extra"):
                apt.inspect_repository(root)
            extra.unlink()
            extra.symlink_to(release)
            with self.assertRaisesRegex(ValueError, "symlink"):
                apt.inspect_repository(root)
            extra.unlink()
            package = root / manifest["packages"][0]["path"]
            package.write_bytes(b"altered")
            with self.assertRaisesRegex(ValueError, "package differs"):
                apt.inspect_repository(root)

    def test_verify_binds_inspected_manifest_to_authenticated_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            root.mkdir()
            manifest = fixture()
            now = int(apt.datetime.now(apt.timezone.utc).timestamp())
            manifest.update(created=now - 1, expires=now + 3600)
            content = apt.metadata(manifest)
            for item in manifest["packages"]:
                content[item["path"]] = b"package fixture, never executed"
            for name, data in content.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            for name in ("InRelease", "Release.gpg"):
                (root / apt.DIST / name).write_bytes(b"signature fixture")
            keyring = Path(temporary) / "keyring.gpg"
            keyring.write_bytes(b"public key fixture")
            identity = "A" * 40
            authenticated_release = content[str(apt.DIST / "Release")]
            original_inspect = apt.inspect_repository

            def authenticated_copy(*command):
                if "--output" in command:
                    Path(command[command.index("--output") + 1]).write_bytes(authenticated_release)
                return (f"[GNUPG:] VALIDSIG {identity} 2026-01-01 0 0 4 0 22 8 01 {identity}\n").encode()

            def swap_after_authentication(path):
                # A publisher replaces a self-consistent Release and manifest
                # after the old Release was authenticated. No matching new
                # signature exists. This cut previously accepted the new state.
                changed = dict(manifest, source_commit="c" * 40)
                for name, data in apt.metadata(changed).items():
                    (root / name).write_bytes(data)
                return original_inspect(path)

            with patch.object(apt, "execute", side_effect=authenticated_copy), patch.object(apt, "inspect_repository", side_effect=swap_after_authentication):
                with self.assertRaisesRegex(ValueError, "authenticated Release differs"):
                    apt.verify(argparse.Namespace(repository=root, keyring=keyring, signer=[identity]))

    def test_sign_uses_release_derived_from_the_inspected_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            (root / apt.DIST).mkdir(parents=True)
            home = Path(temporary) / "private-gnupg"
            home.mkdir(mode=0o700)
            manifest = fixture()
            now = int(apt.datetime.now(apt.timezone.utc).timestamp())
            manifest.update(created=now - 1, expires=now + 3600)
            expected = apt.metadata(manifest)[str(apt.DIST / "Release")]
            # The inspected manifest was valid; its on-disk Release has changed
            # at the next read. The signer must not authenticate these new bytes.
            (root / apt.DIST / "Release").write_bytes(b"uninspected replacement")
            signed = []

            def capture_signing_input(*command):
                if "--output" in command:
                    signed.append(Path(command[-1]).read_bytes())
                    Path(command[command.index("--output") + 1]).write_bytes(b"signature fixture")
                    return b""
                return b"public key fixture"

            with patch.object(apt, "inspect_repository", return_value=manifest), patch.object(apt, "execute", side_effect=capture_signing_input), patch.object(apt, "verify", return_value={"passed": True}):
                apt.sign(argparse.Namespace(repository=root, gnupg_home=home, signer="A" * 40))
            self.assertEqual(signed, [expected, expected])

    def test_prepare_requires_exact_successful_lifecycle_before_writing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "debian-candidates.json").write_bytes(apt.encoded({"schema": "asb.debian-candidates/v1", "packages": []}))
            evidence = root / "evidence.json"
            evidence.write_bytes(apt.encoded({"schema": "asb.debian-lifecycle/v1", "passed": False}))
            with patch.object(apt.sys, "platform", "linux"), patch.object(apt, "validate_dates"):
                with self.assertRaisesRegex(ValueError, "lifecycle"):
                    apt.prepare(argparse.Namespace(artifacts=root, lifecycle=evidence, created=100, expires=200, output=root / "output"))
            self.assertFalse((root / "output").exists())


if __name__ == "__main__":
    unittest.main()
