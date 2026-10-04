#!/usr/bin/env python3
"""Bounded Debian packaging checks, intended for the Linux distribution job."""

import importlib.util
import io
from pathlib import Path
import platform
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("asb_deb", Path(__file__).with_name("build-asb-deb.py"))
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class DebianPackageTest(unittest.TestCase):
    def test_control_archive_rejects_extra_directories_and_nonroot_owners(self):
        files = {"usr/bin/asb": b"fixture"}
        control = b"fixture control\n"
        md5 = (package.hashlib.md5(files["usr/bin/asb"]).hexdigest() + "  usr/bin/asb\n").encode()

        def archive(entries):
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode="w:") as content:
                for name, data, uid in entries:
                    member = tarfile.TarInfo(name)
                    member.uid = uid
                    if data is None:
                        member.type, member.mode = tarfile.DIRTYPE, 0o755
                        content.addfile(member)
                    else:
                        member.mode, member.size = (0o755 if name.startswith("./usr/bin/") else 0o644), len(data)
                        content.addfile(member, io.BytesIO(data))
            return output.getvalue()

        data = archive([(name, None, 0) for name in ("./", "./usr", "./usr/bin")] + [("./usr/bin/asb", b"fixture", 0)])
        for reason, entries in (
            ("directory", [("./unexpected", None, 0), ("./control", control, 0)]),
            ("ownership", [("./control", control, 1000)]),
        ):
            with self.subTest(reason=reason), patch.object(package, "run", side_effect=[data, archive([("./", None, 0), ("./md5sums", md5, 0), *entries])]):
                with self.assertRaisesRegex(ValueError, reason):
                    package.inspect_deb(Path("fixture.deb"), files, control)

    def test_packaged_docs_resolve_local_examples_and_pin_source_links(self):
        source = "a" * 40
        original = ("# Runbook\n[config](../packaging/s3/config.example.json)\n"
                    "[acceptance](../packaging/s3/acceptance.example.json#operator)\n"
                    "[other](other.md#scope)\n[source](../pkg/example/)\n"
                    "[web](https://example.invalid/reference)\n[section](#runbook)\n")
        destinations = {"docs/runbook.md": "usr/share/doc/asb-s3/runbook.md",
                        "packaging/s3/config.example.json": "usr/share/doc/asb-s3/examples/config.example.json",
                        "packaging/s3/acceptance.example.json": "usr/share/doc/asb-s3/examples/acceptance.example.json"}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "docs").mkdir()
            (root / "pkg/example").mkdir(parents=True)
            (root / "docs/runbook.md").write_text(original)
            with patch.object(package, "ROOT", root):
                copied = package.package_document("docs/runbook.md", destinations, source).decode()
            self.assertIn("[config](examples/config.example.json)", copied)
            self.assertIn("[acceptance](examples/acceptance.example.json#operator)", copied)
            self.assertIn("/blob/" + source + "/docs/other.md#scope)", copied)
            self.assertIn("/tree/" + source + "/pkg/example)", copied)
            self.assertIn("[web](https://example.invalid/reference)", copied)
            self.assertIn("[section](#runbook)", copied)
            self.assertIn("Repository-relative build and test commands require a checkout", copied)
            self.assertEqual((root / "docs/runbook.md").read_text(), original)
        self.assertIn("packaging/s3/acceptance.example.json", package.S3_EXAMPLES)

    def test_build_info_requires_baseline_amd64_cpu(self):
        source = "a" * 40
        output = ("fixture: " + package.TOOLCHAIN + "\n"
                  "\tpath\t" + package.MODULE + "/cmd/asb-human\n"
                  "\tbuild\tGOOS=linux\n\tbuild\tGOARCH=amd64\n"
                  "\tbuild\tCGO_ENABLED=0\n\tbuild\tvcs.revision=" + source + "\n"
                  "\tbuild\tvcs.modified=false\n\tbuild\tGOAMD64=")
        for cpu in ("v1", "v2", "v3", "v4"):
            with self.subTest(cpu=cpu), patch.object(package, "run", return_value=(output + cpu + "\n").encode()):
                if cpu == "v1":
                    metadata, _ = package.build_info(Path("fixture"), source, {})
                    self.assertEqual(metadata["settings"]["GOAMD64"], cpu)
                else:
                    with self.assertRaisesRegex(ValueError, "provenance"):
                        package.build_info(Path("fixture"), source, {})

    def test_elf_profile_rejects_dynamic_or_wrong_machine(self):
        raw = bytearray(120)
        raw[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<HHIQQQIHHHHHH", raw, 16, 2, 62, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
        package.validate_static_elf(bytes(raw))
        for segment in (2, 3):
            struct.pack_into("<I", raw, 64, segment)
            with self.assertRaisesRegex(ValueError, "dynamic"):
                package.validate_static_elf(bytes(raw))
        struct.pack_into("<H", raw, 18, 183)
        with self.assertRaisesRegex(ValueError, "layout"):
            package.validate_static_elf(bytes(raw))
        with self.assertRaises(ValueError):
            package.validate_static_elf(b"not an executable")

    def test_control_keeps_optional_packages_out_of_default_dependencies(self):
        control = package.control("asb", "0.1.0~preview.1-1", "ASB QA <qa@example.invalid>", 1).decode()
        self.assertIn("Architecture: all\n", control)
        self.assertIn("Depends: asb-tools (= 0.1.0~preview.1-1)\n", control)
        self.assertNotIn("asb-human", control)
        self.assertNotIn("asb-s3", control)
        for name in ("asb-tools", "asb-human", "asb-s3"):
            self.assertNotIn("Depends:", package.control(name, "1-1", "ASB QA <qa@example.invalid>", 1).decode())

    def test_unsafe_package_paths_are_rejected(self):
        for name in ("/etc/passwd", "usr/../etc/passwd", "usr//bin/asb", "./usr/bin/asb", "usr/bin/a\nb"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                package.safe_name(name)

    @unittest.skipUnless(sys.platform == "linux" and platform.machine() == "x86_64", "Debian archive check runs on Linux amd64")
    def test_final_deb_inventory_modes_and_no_maintainer_scripts(self):
        files = {"usr/bin/asb-leastprivilege": b"package fixture, never executed", "usr/share/doc/asb-tools/copyright": b"fixture notice\n"}
        maintainer = "ASB QA <qa@example.invalid>"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage, output = root / "stage", root / "output"
            stage.mkdir()
            output.mkdir()
            result = package.write_package(stage, output, "asb-tools", "0.1.0~preview.1-1", maintainer, files, "1700000000")
            archive = output / result["file"]
            self.assertEqual(result["sha256"], package.sha256(archive.read_bytes()))
            altered = dict(files, **{"usr/bin/asb-leastprivilege": b"different"})
            with self.assertRaisesRegex(ValueError, "payload"):
                package.inspect_deb(archive, altered, package.control("asb-tools", "0.1.0~preview.1-1", maintainer, sum(map(len, files.values()))))
            # An empty unlisted directory is still an installed filesystem
            # change, even though every regular file matches the inventory.
            extra_directory = stage / "asb-tools/usr/local"
            extra_directory.mkdir()
            extra_archive = root / "extra-directory.deb"
            subprocess.check_call(["dpkg-deb", "--root-owner-group", "--build", str(stage / "asb-tools"), str(extra_archive)], stdout=subprocess.DEVNULL)
            with self.assertRaisesRegex(ValueError, "directory"):
                package.inspect_deb(extra_archive, files, package.control("asb-tools", "0.1.0~preview.1-1", maintainer, sum(map(len, files.values()))))
            extra_directory.rmdir()
            # Rebuild a tampered control archive to check the FINAL .deb,
            # rather than merely asserting the builder omitted postinst.
            postinst = stage / "asb-tools/DEBIAN/postinst"
            postinst.write_text("#!/bin/sh\nexit 0\n")
            postinst.chmod(0o755)
            tampered = root / "tampered.deb"
            subprocess.check_call(["dpkg-deb", "--root-owner-group", "--build", str(stage / "asb-tools"), str(tampered)], stdout=subprocess.DEVNULL)
            with self.assertRaisesRegex(ValueError, "maintainer"):
                package.inspect_deb(tampered, files, package.control("asb-tools", "0.1.0~preview.1-1", maintainer, sum(map(len, files.values()))))


if __name__ == "__main__":
    unittest.main()
