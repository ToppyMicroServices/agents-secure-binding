#!/usr/bin/env python3
"""Exercise publication trust, archive boundaries and public-content allowlists."""
from datetime import datetime, timezone
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("asb_pages", Path(__file__).with_name("asb-apt-pages.py"))
pages = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pages)
apt = pages.apt


def fixture():
    now = int(datetime.now(timezone.utc).timestamp())
    manifest = {"schema": "asb.apt-repository/v1", "created": now - 1, "expires": now + 3600,
                "source_commit": "a" * 40, "version": "0.1.0~preview.1-1", "lifecycle_sha256": "b" * 64, "packages": []}
    files = {}
    for name, arch in (("asb", "all"), ("asb-tools", "amd64")):
        content = b"synthetic archive fixture, never installed"
        path = f"pool/main/a/asb/{name}_{manifest['version']}_{arch}.deb"
        manifest["packages"].append({"package": name, "architecture": arch, "path": path, "bytes": len(content), "sha256": apt.sha(content),
                                    "control": f"Package: {name}\nVersion: {manifest['version']}\nArchitecture: {arch}\nDescription: fixture\n"})
        files[path] = content
    files.update(apt.metadata(manifest))
    files.update({str(apt.DIST / "InRelease"): b"test signature", str(apt.DIST / "Release.gpg"): b"test signature"})
    trusted = {"schema": "asb.apt-pages-policy/v1", "base_url": pages.BASE_URL, "signers": ["A" * 40], "keyring_sha256": apt.sha(b"public fixture")}
    return manifest, files, trusted


class AptPagesTest(unittest.TestCase):
    def test_policy_rejects_redirected_destinations_unknown_keys_and_duplicates(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "policy.json"
            _, _, trusted = fixture()
            path.write_bytes(apt.encoded(trusted))
            self.assertEqual(pages.policy(path), trusted)
            for changed in (dict(trusted, base_url="https://other.invalid"), dict(trusted, signers=[]),
                            dict(trusted, signers=["A" * 40, "A" * 40]), dict(trusted, extra=True)):
                path.write_bytes(apt.encoded(changed))
                with self.assertRaises(ValueError):
                    pages.policy(path)
            path.write_bytes(b'{"schema":"a","schema":"b"}')
            with self.assertRaises(ValueError):
                pages.policy(path)

    def test_archive_rejects_traversal_links_duplicates_and_trailing_bytes_before_writing(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "input.tar"
            for mode in ("traversal", "symlink", "hardlink", "duplicate", "trailing"):
                output = root / mode
                buffer = io.BytesIO()
                with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as bundle:
                    item = tarfile.TarInfo("../escaped" if mode == "traversal" else "index.html")
                    item.size, item.mode = 1, 0o644
                    if mode in ("symlink", "hardlink"):
                        item.type = tarfile.SYMTYPE if mode == "symlink" else tarfile.LNKTYPE
                        item.linkname = "../outside"
                        item.size = 0
                    bundle.addfile(item, io.BytesIO(b"x"))
                    if mode == "duplicate":
                        bundle.addfile(item, io.BytesIO(b"x"))
                data = buffer.getvalue() + (b"hidden trailer" if mode == "trailing" else b"")
                archive.write_bytes(data)
                with self.subTest(mode=mode), self.assertRaises(ValueError):
                    pages.unpack(archive, apt.sha(data), output)
                self.assertFalse(output.exists())
            self.assertFalse((root.parent / "escaped").exists())

    def test_archive_requires_expected_hash_and_round_trips_exact_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "input.tar"
            files = {"index.html": b"reviewed", "apt/dists/asb-preview/Release": b"fixture"}
            data = pages.canonical_archive(files)
            archive.write_bytes(data)
            with self.assertRaises(ValueError):
                pages.unpack(archive, "0" * 64, root / "wrong")
            self.assertFalse((root / "wrong").exists())
            pages.unpack(archive, apt.sha(data), root / "right")
            self.assertEqual(pages.file_map(root / "right"), files)

    def test_keyring_rejects_private_or_additional_keys(self):
        _, _, trusted = fixture()
        fingerprint = "fpr:::::::::" + "A" * 40 + ":\n"
        for output in ("sec::::::::::\n" + fingerprint, fingerprint + "fpr:::::::::" + "B" * 40 + ":\n"):
            with patch.object(apt, "execute", return_value=output.encode()), self.assertRaises(ValueError):
                pages.public_keyring(b"public fixture", trusted)
        with patch.object(apt, "execute", return_value=("pub::::::::::\n" + fingerprint).encode()):
            pages.public_keyring(b"public fixture", trusted)
        with self.assertRaises(ValueError):
            pages.public_keyring(b"changed bytes", trusted)

    def test_publication_rejects_extra_file_html_change_and_source_change(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest, files, trusted = fixture()
            repo = root / "repo"
            for name, data in files.items():
                pages.write_new(repo / name, data)
            key = root / "keyring.gpg"
            key.write_bytes(b"public fixture")
            def verified(args):
                actual = apt.inspect_repository(args.repository)
                return {"source_commit": actual["source_commit"], "version": actual["version"], "expires": actual["expires"],
                        "signer": "A" * 40, "manifest_sha256": apt.sha(apt.encoded(actual))}
            with patch.object(pages, "public_keyring"), patch.object(apt, "verify", side_effect=verified):
                site = root / "site"
                self.assertTrue(pages.stage(repo, key, trusted, manifest["source_commit"], site)["passed"])
                for mode in ("extra", "html", "source"):
                    saved = pages.file_map(site)
                    inventory = apt.strict_json(saved["publication.json"])
                    if mode == "extra":
                        (site / "private-key.txt").write_bytes(b"must not publish")
                        inventory["files"]["private-key.txt"] = apt.sha(b"must not publish")
                    elif mode == "html":
                        (site / "index.html").write_bytes(b"<script>unreviewed</script>")
                        inventory["files"]["index.html"] = apt.sha((site / "index.html").read_bytes())
                    else:
                        inventory["source_commit"] = "f" * 40
                    (site / "publication.json").write_bytes(apt.encoded(inventory))
                    with self.subTest(mode=mode), self.assertRaises(ValueError):
                        pages.verify_site(site, trusted, manifest["source_commit"])
                    for name in pages.file_map(site):
                        if name not in saved:
                            (site / name).unlink()
                    for name, data in saved.items():
                        (site / name).write_bytes(data)

    def test_live_comparison_uses_the_verified_snapshot(self):
        with tempfile.TemporaryDirectory() as temp:
            site = Path(temp) / "site"
            site.mkdir()
            (site / "index.html").write_bytes(b"approved bytes")
            _, _, trusted = fixture()
            def verify(captured, _trusted, _source):
                self.assertNotEqual(captured, site)
                self.assertEqual((captured / "index.html").read_bytes(), b"approved bytes")
                (site / "index.html").write_bytes(b"changed after verification")
                return {"passed": True}
            response = Mock()
            response.status = 200
            response.geturl.return_value = pages.BASE_URL + "/index.html"
            response.headers = {}
            response.read.return_value = b"approved bytes"
            response.__enter__ = Mock(return_value=response)
            response.__exit__ = Mock(return_value=False)
            opener = Mock()
            opener.open.return_value = response
            with patch.object(pages, "_verify_snapshot", side_effect=verify), patch.object(pages, "build_opener", return_value=opener):
                self.assertTrue(pages.verify_live(site, trusted, "a" * 40)["published"])
            response.read.assert_called_once_with(len(b"approved bytes") + 1)

    def test_redirects_are_rejected(self):
        with self.assertRaises(ValueError):
            pages.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://other.invalid/")


if __name__ == "__main__":
    unittest.main()
