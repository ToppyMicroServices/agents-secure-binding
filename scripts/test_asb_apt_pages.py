#!/usr/bin/env python3
"""Exercise publication trust, archive boundaries and public-content allowlists."""
import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import importlib.util
import io
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError

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
    public_policy = {"schema": "asb.apt-pages-policy/v1", "base_url": pages.BASE_URL, "signers": ["A" * 40], "keyring_sha256": apt.sha(b"public fixture")}
    return manifest, files, public_policy


class AptPagesTest(unittest.TestCase):
    def test_policy_rejects_redirected_destinations_unknown_keys_and_duplicates(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "policy.json"
            _, _, public_policy = fixture()
            path.write_bytes(apt.encoded(public_policy))
            self.assertEqual(pages.policy(path), public_policy)
            for changed in (dict(public_policy, base_url="https://other.invalid"),
                            dict(public_policy, base_url="https://toppymicroservices.github.io/agents-secure-binding"),
                            dict(public_policy, base_url="http://www.toppymicros.com/agents-secure-binding"),
                            dict(public_policy, signers=[]),
                            dict(public_policy, signers=["A" * 40, "A" * 40]), dict(public_policy, extra=True)):
                path.write_bytes(apt.encoded(changed))
                with self.assertRaises(ValueError):
                    pages.policy(path)
            path.write_bytes(b'{"schema":"a","schema":"b"}')
            with self.assertRaises(ValueError):
                pages.policy(path)

    def test_subkey_policy_binds_only_exact_signers_to_their_primaries(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "policy.json"
            _, _, standalone = fixture()
            primary, subkey = "A" * 40, "B" * 40
            chosen = dict(standalone, schema="asb.apt-pages-policy/v2", signers=[subkey],
                          subkey_primaries={subkey: primary})
            path.write_bytes(apt.encoded(chosen))
            self.assertEqual(pages.policy(path), chosen)
            rotating = dict(chosen, signers=[subkey, "C" * 40],
                            subkey_primaries={subkey: primary, "C" * 40: primary})
            path.write_bytes(apt.encoded(rotating))
            self.assertEqual(pages.policy(path), rotating)
            for changed in (dict(chosen, subkey_primaries={}),
                            dict(chosen, subkey_primaries={primary: subkey}),
                            dict(chosen, subkey_primaries={subkey: subkey}),
                            dict(chosen, subkey_primaries={subkey: "a" * 40}),
                            dict(chosen, signers=[primary, subkey], subkey_primaries={primary: subkey, subkey: primary}),
                            dict(chosen, extra=True)):
                path.write_bytes(apt.encoded(changed))
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    pages.policy(path)
            source = pages.web_files(fixture()[0], chosen)["asb.sources"].decode()
            self.assertIn(f"Signed-By: /etc/apt/keyrings/asb-archive.gpg {subkey}!\n", source)
            self.assertNotIn(primary + "!", source)

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
        _, _, public_policy = fixture()
        fingerprint = "fpr:::::::::" + "A" * 40 + ":\n"
        for output in ("sec::::::::::\n" + fingerprint, fingerprint + "fpr:::::::::" + "B" * 40 + ":\n"):
            with patch.object(apt, "execute", return_value=output.encode()), self.assertRaises(ValueError):
                pages.public_keyring(b"public fixture", public_policy)
        with patch.object(apt, "execute", return_value=("pub::::::::::\n" + fingerprint).encode()):
            pages.public_keyring(b"public fixture", public_policy)
        with self.assertRaises(ValueError):
            pages.public_keyring(b"changed bytes", public_policy)

    def test_subkey_keyring_rejects_wrong_binding_extra_keys_and_bad_status(self):
        _, _, standalone = fixture()
        primary, subkey = "A" * 40, "B" * 40
        chosen = dict(standalone, schema="asb.apt-pages-policy/v2", signers=[subkey],
                      subkey_primaries={subkey: primary})

        def record(kind, identity=None, validity="-", expires=""):
            fields = [""] * 12
            fields[0], fields[1], fields[6] = kind, validity, expires
            if identity is not None:
                fields[9] = identity
            return ":".join(fields) + "\n"

        pub = record("pub") + record("fpr", primary)
        sub = record("sub") + record("fpr", subkey)
        valid = pub + sub
        with patch.object(apt, "execute", return_value=valid.encode()):
            pages.public_keyring(b"public fixture", chosen)
        rotating = dict(chosen, signers=[subkey, "C" * 40],
                        subkey_primaries={subkey: primary, "C" * 40: primary})
        with patch.object(apt, "execute", return_value=(valid + record("sub") + record("fpr", "C" * 40)).encode()):
            pages.public_keyring(b"public fixture", rotating)
        bad = (record("sec") + valid, valid + record("sub") + record("fpr", "C" * 40),
               valid + record("pub") + record("fpr", "C" * 40), pub,
               record("pub") + record("fpr", "C" * 40) + sub,
               pub + record("sub", validity="r") + record("fpr", subkey),
               pub + record("sub", validity="e") + record("fpr", subkey),
               pub + record("sub", expires="1") + record("fpr", subkey),
               record("pub") + record("fpr", subkey) + record("sub") + record("fpr", primary))
        for output in bad:
            with self.subTest(output=output), patch.object(apt, "execute", return_value=output.encode()), self.assertRaises(ValueError):
                pages.public_keyring(b"public fixture", chosen)

    @unittest.skipUnless(sys.platform == "linux" and all(shutil.which(name) for name in ("gpg", "gpgv", "gpgconf", "apt-get")),
                         "requires Linux, GnuPG and apt")
    def test_ephemeral_subkey_is_the_only_accepted_repository_and_apt_signer(self):
        with tempfile.TemporaryDirectory() as temp, ExitStack() as cleanup:
            root = Path(temp)
            home = root / "gnupg"
            home.mkdir(mode=0o700)
            cleanup.callback(lambda: subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"],
                                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30))

            def gpg(*command):
                return subprocess.run(["gpg", "--homedir", str(home), "--batch", *command],
                                      check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120).stdout

            gpg("--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key",
                "ASB ephemeral apt subkey <apt-subkey@example.invalid>", "ed25519", "sign", "1d")
            listing = gpg("--with-colons", "--list-keys").decode()
            primary = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
            gpg("--pinentry-mode", "loopback", "--passphrase", "", "--quick-add-key", primary, "ed25519", "sign", "1d")
            listing = gpg("--with-colons", "--list-keys", primary).decode()
            fingerprints = [line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")]
            self.assertEqual(len(fingerprints), 2)
            self.assertEqual(fingerprints[0], primary)
            subkey = fingerprints[1]
            keyring = root / "asb-archive.gpg"
            keyring.write_bytes(gpg("--export-options", "export-minimal", "--export", primary))
            manifest, files, standalone = fixture()
            chosen = dict(standalone, schema="asb.apt-pages-policy/v2", signers=[subkey],
                          subkey_primaries={subkey: primary}, keyring_sha256=apt.sha(keyring.read_bytes()))
            pages.public_keyring(keyring.read_bytes(), chosen)

            def repository(name, signer):
                path = root / name
                for file, data in files.items():
                    if file not in (str(apt.DIST / "InRelease"), str(apt.DIST / "Release.gpg")):
                        pages.write_new(path / file, data)
                apt.sign(argparse.Namespace(repository=path, gnupg_home=home, signer=signer))
                return path

            selected = repository("selected", subkey)
            site = root / "site"
            self.assertTrue(pages.stage(selected, keyring, chosen, manifest["source_commit"], site)["passed"])
            generated = (site / "asb.sources").read_text()
            self.assertIn(subkey + "!", generated)
            self.assertNotIn(primary + "!", generated)

            def apt_update(repo, name):
                client = root / name
                client.mkdir()
                state, cache = client / "state", client / "cache"
                (state / "lists" / "partial").mkdir(parents=True)
                (cache / "archives" / "partial").mkdir(parents=True)
                (client / "trusted.gpg.d").mkdir()
                (client / "status").write_bytes(b"")
                (client / "trusted.gpg").write_bytes(b"")
                source = generated.replace(pages.BASE_URL + "/apt", repo.as_uri())
                source = source.replace("/etc/apt/keyrings/asb-archive.gpg", str(keyring))
                sources = client / "asb.sources"
                sources.write_text(source)
                options = {"Dir::Etc::sourcelist": sources, "Dir::Etc::sourceparts": "-",
                           "Dir::Etc::trusted": client / "trusted.gpg", "Dir::Etc::trustedparts": client / "trusted.gpg.d",
                           "Dir::State": state, "Dir::State::status": client / "status", "Dir::Cache": cache,
                           "APT::Sandbox::User": pwd.getpwuid(os.getuid()).pw_name,
                           "APT::Update::Error-Mode": "any", "Debug::NoLocking": "1", "Acquire::Languages": "none"}
                command = ["apt-get"]
                for option, value in options.items():
                    command.extend(("-o", f"{option}={value}"))
                command.append("update")
                return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                      env={**os.environ, "LC_ALL": "C"}, timeout=120)

            accepted = apt_update(selected, "apt-selected")
            self.assertEqual(accepted.returncode, 0, accepted.stdout.decode(errors="replace"))

            primary_signed = repository("primary-signed", primary)
            with self.assertRaisesRegex(ValueError, "exact signer"):
                pages.stage(primary_signed, keyring, chosen, manifest["source_commit"], root / "primary-site")
            denied = apt_update(primary_signed, "apt-primary")
            self.assertNotEqual(denied.returncode, 0, denied.stdout.decode(errors="replace"))
            self.assertTrue(any(word in denied.stdout for word in (b"NO_PUBKEY", b"GPG error", b"not signed")),
                            denied.stdout.decode(errors="replace"))

            signature = selected / apt.DIST / "Release.gpg"
            data = signature.read_bytes()
            signature.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
            with self.assertRaises(subprocess.SubprocessError):
                apt.verify(argparse.Namespace(repository=selected, keyring=keyring, signer=[subkey]))

            wrong_primary = dict(chosen, subkey_primaries={subkey: "C" * 40})
            with self.assertRaises(ValueError):
                pages.public_keyring(keyring.read_bytes(), wrong_primary)
            gpg("--pinentry-mode", "loopback", "--passphrase", "", "--quick-add-key", primary, "ed25519", "sign", "1d")
            extra_export = gpg("--export-options", "export-minimal", "--export", primary)
            with self.assertRaises(ValueError):
                pages.public_keyring(extra_export, dict(chosen, keyring_sha256=apt.sha(extra_export)))

    def test_publication_rejects_missing_changed_and_extra_files_even_with_updated_inventory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest, files, public_policy = fixture()
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
                self.assertTrue(pages.stage(repo, key, public_policy, manifest["source_commit"], site)["passed"])
                for mode in ("extra", "nested-marker", "missing-marker", "nonempty-marker", "html", "source"):
                    saved = pages.file_map(site)
                    inventory = apt.strict_json(saved["publication.json"])
                    if mode == "extra":
                        (site / "private-key.txt").write_bytes(b"must not publish")
                        inventory["files"]["private-key.txt"] = apt.sha(b"must not publish")
                    elif mode == "nested-marker":
                        (site / "nested").mkdir()
                        (site / "nested" / ".nojekyll").write_bytes(b"")
                        inventory["files"]["nested/.nojekyll"] = apt.sha(b"")
                    elif mode == "missing-marker":
                        (site / ".nojekyll").unlink()
                        inventory["files"].pop(".nojekyll")
                    elif mode == "nonempty-marker":
                        (site / ".nojekyll").write_bytes(b"changed marker")
                        inventory["files"][".nojekyll"] = apt.sha(b"changed marker")
                    elif mode == "html":
                        (site / "index.html").write_bytes(b"<script>unreviewed</script>")
                        inventory["files"]["index.html"] = apt.sha((site / "index.html").read_bytes())
                    else:
                        inventory["source_commit"] = "f" * 40
                    (site / "publication.json").write_bytes(apt.encoded(inventory))
                    with self.subTest(mode=mode), self.assertRaises(ValueError):
                        pages.verify_site(site, public_policy, manifest["source_commit"])
                    for name in pages.file_map(site):
                        if name not in saved:
                            (site / name).unlink()
                    if mode == "nested-marker":
                        (site / "nested").rmdir()
                    for name, data in saved.items():
                        (site / name).write_bytes(data)

    def test_live_comparison_uses_the_verified_snapshot(self):
        with tempfile.TemporaryDirectory() as temp:
            site = Path(temp) / "site"
            site.mkdir()
            (site / ".nojekyll").write_bytes(b"")
            (site / "index.html").write_bytes(b"approved bytes")
            _, _, public_policy = fixture()
            def verify(captured, _policy, _source):
                self.assertNotEqual(captured, site)
                self.assertEqual((captured / "index.html").read_bytes(), b"approved bytes")
                (site / "index.html").write_bytes(b"changed after verification")
                return {"passed": True, "files": 2}
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
                result = pages.verify_live(site, public_policy, "a" * 40)
            self.assertTrue(result["published"])
            self.assertEqual((result["files"], result["archive_files"], result["public_files"]), (2, 2, 1))
            self.assertEqual(result["archive_only_markers"], [".nojekyll"])
            opener.open.assert_called_once()
            self.assertEqual(opener.open.call_args.args[0].full_url, pages.BASE_URL + "/index.html")
            response.read.assert_called_once_with(len(b"approved bytes") + 1)

    def test_live_readback_rejects_http_errors_changed_bytes_and_redirects(self):
        with tempfile.TemporaryDirectory() as temp:
            site = Path(temp) / "site"
            site.mkdir()
            (site / ".nojekyll").write_bytes(b"")
            (site / "index.html").write_bytes(b"approved bytes")
            _, _, public_policy = fixture()
            url = pages.BASE_URL + "/index.html"
            for status in (403, 404):
                opener = Mock()
                opener.open.side_effect = HTTPError(url, status, "private message", {}, io.BytesIO(b"private body"))
                with self.subTest(status=status), patch.object(pages, "_verify_snapshot", return_value={"passed": True}), patch.object(pages, "build_opener", return_value=opener):
                    with self.assertRaisesRegex(ValueError, f"index.html HTTP {status}") as caught:
                        pages.verify_live(site, public_policy, "a" * 40)
                    self.assertNotIn("private", str(caught.exception))
                    opener.open.assert_called_once()
            response = Mock()
            response.status = 200
            response.geturl.return_value = url
            response.headers = {}
            response.read.return_value = b"changed bytes"
            response.__enter__ = Mock(return_value=response)
            response.__exit__ = Mock(return_value=False)
            opener = Mock()
            opener.open.return_value = response
            with patch.object(pages, "_verify_snapshot", return_value={"passed": True}), patch.object(pages, "build_opener", return_value=opener):
                with self.assertRaisesRegex(ValueError, "published bytes differ.*index.html"):
                    pages.verify_live(site, public_policy, "a" * 40)
            opener.open.side_effect = ValueError("publication verification rejects redirects")
            with patch.object(pages, "_verify_snapshot", return_value={"passed": True}), patch.object(pages, "build_opener", return_value=opener):
                with self.assertRaisesRegex(ValueError, "rejects redirects"):
                    pages.verify_live(site, public_policy, "a" * 40)

    def test_redirects_are_rejected(self):
        with self.assertRaises(ValueError):
            pages.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://other.invalid/")


if __name__ == "__main__":
    unittest.main()
