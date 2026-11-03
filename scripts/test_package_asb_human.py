#!/usr/bin/env python3
"""Focused packaging rejection tests; fixtures never execute a Go binary."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("asb_human_package", Path(__file__).with_name("package-asb-human.py"))
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)

SOURCE = "a" * 40
MODULE = {"path": "example.com/dependency", "version": "v1.2.3", "sum": "h1:" + "A" * 43 + "="}
NOTICE = "licenses/example.com/dependency@v1.2.3/LICENSE"


def build_info(source=SOURCE, goos="linux", goarch="amd64"):
    settings = {"-trimpath": "true", "GOOS": goos, "GOARCH": goarch, "CGO_ENABLED": "0",
                "vcs": "git", "vcs.revision": source, "vcs.modified": "false"}
    if goarch == "amd64":
        settings["GOAMD64"] = "v1"
    return ("fixture: " + package.deb.TOOLCHAIN + "\n\tpath\t" + package.ENTRYPOINT
            + "\n\tmod\t" + package.deb.MODULE + "\t(devel)\n"
            + "\tdep\t{path}\t{version}\t{sum}\n".format(**MODULE)
            + "".join("\tbuild\t" + key + "=" + value + "\n" for key, value in settings.items())).encode()


class HumanPreviewPackageTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "docs").mkdir()
        (self.root / "LICENSE").write_bytes(b"Root license fixture\n")
        (self.root / "docs/asb-human-binary-quickstart.md").write_text(
            "# Preview\n[Guide](" + package.REPOSITORY + "/blob/main/docs/local-human-approval.md)\n")

    def make_bundle(self, goos="linux", goarch="amd64", mutate_input=False):
        name = package.PLATFORMS[goos, goarch]
        binary = self.root / (goos + "-input") / name
        binary.parent.mkdir()
        binary.write_bytes(b"fixture executable, never run\n")
        output = self.root / (goos + "-preview")

        def go(*args, **kwargs):
            if args == ("go", "env", "GOVERSION"):
                return (package.deb.TOOLCHAIN + "\n").encode()
            self.assertEqual(args[:3], ("go", "version", "-m"))
            captured = Path(args[3])
            self.assertNotEqual(captured, binary)
            self.assertEqual(captured.read_bytes(), b"fixture executable, never run\n")
            if mutate_input:
                binary.write_bytes(b"changed original input\n")
            return build_info(goos=goos, goarch=goarch)

        notices = {NOTICE: b"Dependency license fixture\n", "licenses/go/LICENSE": b"Go license fixture\n"}
        with patch.object(package.deb, "ROOT", self.root), patch.object(package.deb, "clean_source"), \
                patch.object(package.deb, "run", side_effect=go), \
                patch.object(package.deb, "collect_notices", return_value=notices), \
                patch.object(package.platform, "system", return_value="Linux"):
            package.package(binary, output, SOURCE, goos, goarch)
        return output

    def test_complete_bundles_preserve_native_checksum_format_and_pin_guide(self):
        for goos, goarch in package.PLATFORMS:
            with self.subTest(platform=(goos, goarch)):
                directory = self.make_bundle(goos, goarch)
                result = package.verify(directory, SOURCE, goos, goarch)
                binary = package.PLATFORMS[goos, goarch]
                self.assertEqual((directory / "SHA256SUMS").read_text(),
                                 result["binary"]["sha256"] + "  " + binary + "\n")
                self.assertIn("/blob/" + SOURCE + "/docs/local-human-approval.md", (directory / "USAGE.md").read_text())
                self.assertEqual((directory / "LICENSE").read_bytes(), b"Root license fixture\n")
                self.assertIn(NOTICE, result["files"])
                self.assertFalse(result["code_signed"])
                self.assertFalse(result["notarized"])

    def test_provenance_and_delivery_use_same_captured_binary(self):
        directory = self.make_bundle(mutate_input=True)
        self.assertEqual((directory / "asb-human").read_bytes(), b"fixture executable, never run\n")
        package.verify(directory, SOURCE, "linux", "amd64")

    def test_wrong_source_platform_cgo_toolchain_and_entrypoint_are_rejected(self):
        original = build_info()
        for before, after in (
            (SOURCE.encode(), b"b" * 40), (b"vcs.modified=false", b"vcs.modified=true"),
            (b"GOOS=linux", b"GOOS=windows"), (b"GOARCH=amd64", b"GOARCH=arm64"),
            (b"CGO_ENABLED=0", b"CGO_ENABLED=1"), (b"GOAMD64=v1", b"GOAMD64=v3"),
            (b"-trimpath=true", b"-trimpath=false"), (b"go1.26.10", b"go1.26.9"),
            (b"/cmd/asb-human", b"/cmd/asb-s3"),
        ):
            with self.subTest(change=after), self.assertRaises(ValueError):
                package.parse_build_info(original.replace(before, after), SOURCE, "linux", "amd64")

    def test_replacements_unpinned_modules_and_duplicate_records_are_rejected(self):
        original = build_info()
        cases = (
            original + b"\t=>\t../local-dependency\t(devel)\n",
            original.replace(MODULE["sum"].encode(), b""),
            original + b"\tbuild\tGOOS=linux\n",
            original + ("\tdep\t{path}\t{version}\t{sum}\n".format(**MODULE)).encode(),
            original + ("\tpath\t" + package.ENTRYPOINT + "\n").encode(),
        )
        for candidate in cases:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                package.parse_build_info(candidate, SOURCE, "linux", "amd64")

    def test_dirty_source_stops_before_packaging_or_notice_download(self):
        with patch.object(package.platform, "system", return_value="Linux"), \
                patch.object(package.deb, "clean_source", side_effect=ValueError("dirty source")), \
                patch.object(package.deb, "collect_notices") as notices:
            with self.assertRaisesRegex(ValueError, "dirty source"):
                package.package(self.root / "asb-human", self.root / "preview", SOURCE, "linux", "amd64")
        notices.assert_not_called()
        self.assertFalse((self.root / "preview").exists())

    def test_changed_binary_guide_and_notices_fail_full_inventory_verification(self):
        directory = self.make_bundle()
        for name in ("asb-human", "USAGE.md", "LICENSE", NOTICE, "licenses/go/LICENSE", "SHA256SUMS"):
            target = directory / name
            original = target.read_bytes()
            target.write_bytes(original + b"changed\n")
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "hash mismatch"):
                package.verify(directory, SOURCE, "linux", "amd64")
            target.write_bytes(original)

    def test_wrong_expected_identity_missing_and_extra_members_are_rejected(self):
        directory = self.make_bundle()
        for source, goos, goarch in (("b" * 40, "linux", "amd64"), (SOURCE, "windows", "amd64")):
            with self.subTest(identity=(source, goos, goarch)), self.assertRaises(ValueError):
                package.verify(directory, source, goos, goarch)
        extra = directory / "unexpected.txt"
        extra.write_text("extra")
        with self.assertRaisesRegex(ValueError, "extra file"):
            package.verify(directory, SOURCE, "linux", "amd64")
        extra.unlink()
        extra.mkdir()
        with self.assertRaisesRegex(ValueError, "extra directories"):
            package.verify(directory, SOURCE, "linux", "amd64")
        extra.rmdir()
        (directory / NOTICE).unlink()
        with self.assertRaisesRegex(ValueError, "missing files"):
            package.verify(directory, SOURCE, "linux", "amd64")

    def test_omitted_license_and_ambiguous_inventory_are_rejected(self):
        directory = self.make_bundle()
        inventory_path = directory / "inventory.json"
        original = inventory_path.read_bytes()
        inventory = json.loads(original)
        del inventory["files"][NOTICE]
        inventory_path.write_bytes(package.deb.encoded(inventory))
        with self.assertRaisesRegex(ValueError, "missing linked module license"):
            package.verify(directory, SOURCE, "linux", "amd64")
        inventory_path.write_bytes(original.replace(b'{\n', b'{\n  "status": "preview",\n', 1))
        with self.assertRaisesRegex(ValueError, "duplicate inventory field"):
            package.verify(directory, SOURCE, "linux", "amd64")

    def test_portable_reader_rejects_links_even_without_unix_open_flags(self):
        directory = self.make_bundle()
        with patch.object(package.os, "O_NOFOLLOW", 0), patch.object(package.os, "O_NONBLOCK", 0):
            package.verify(directory, SOURCE, "linux", "amd64")
            original = directory / "LICENSE"
            original.unlink()
            original.symlink_to(self.root / "LICENSE")
            with self.assertRaisesRegex(ValueError, "regular file"):
                package.verify(directory, SOURCE, "linux", "amd64")


if __name__ == "__main__":
    unittest.main()
