#!/usr/bin/env python3
"""Reject ambiguous source and migration claims in the Linux apt gate."""

import argparse
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("apt_check", Path(__file__).with_name("check-asb-apt.py"))
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


class AptUpgradeTest(unittest.TestCase):
    def source_args(self):
        return argparse.Namespace(initial_source="a" * 40, upgrade_source="b" * 40, source_checkout=Path("."))

    def git(self, *command):
        args = command[3:]
        if args == ("rev-parse", "HEAD"):
            return ("b" * 40 + "\n").encode()
        if args[0] == "rev-parse":
            return (("c" if args[1].startswith("a") else "d") * 40 + "\n").encode()
        return b""

    def test_distinct_ancestor_sources_and_clean_checkout_are_required(self):
        args = self.source_args()
        with patch.object(check, "run", side_effect=self.git):
            result = check.validate_sources(args, {"source_commit": args.initial_source}, {"source_commit": args.upgrade_source})
        self.assertTrue(result["ancestor_verified"])
        self.assertNotEqual(result["initial_tree"], result["upgrade_tree"])
        self.assertFalse(result["human_entrypoint_sources_changed"])
        for initial, upgrade in (("a" * 40, "a" * 40), ("short", "b" * 40)):
            args.initial_source, args.upgrade_source = initial, upgrade
            with self.subTest(initial=initial, upgrade=upgrade), self.assertRaises(ValueError):
                check.validate_sources(args, {"source_commit": initial}, {"source_commit": upgrade})
        args = self.source_args()
        with self.assertRaisesRegex(ValueError, "reviewed commit"):
            check.validate_sources(args, {"source_commit": "f" * 40}, {"source_commit": args.upgrade_source})

    def test_same_tree_dirty_checkout_and_nonancestor_are_rejected(self):
        args = self.source_args()
        for failure in ("same-tree", "dirty", "nonancestor"):
            def altered_git(*command):
                words = command[3:]
                if failure == "same-tree" and words == ("rev-parse", "b" * 40 + "^{tree}"):
                    return ("c" * 40).encode()
                if failure == "dirty" and words[0] == "status":
                    return b" M changed.go\n"
                if failure == "nonancestor" and words[0] == "merge-base":
                    raise subprocess.CalledProcessError(1, command)
                return self.git(*command)
            with self.subTest(failure=failure), patch.object(check, "run", side_effect=altered_git), self.assertRaises((ValueError, subprocess.CalledProcessError)):
                check.validate_sources(args, {"source_commit": args.initial_source}, {"source_commit": args.upgrade_source})

    def test_taskcoord_evidence_requires_real_one_to_two_transition(self):
        state = {"schema": 1, "tasks_sha256": "a" * 64, "actions_sha256": "b" * 64, "reachability_quarantine_tables": 0, "integrity": "ok"}
        common = {"schema": "asb.taskcoord-upgrade-probe/v1", "passed": True, "participant_preserved": True,
                  "assignment_preserved": True, "immutable_retry_preserved": True}
        initial = dict(common, mode="seed", before={}, after=state)
        upgrade = dict(common, mode="verify", before=state, after=dict(state, schema=2, reachability_quarantine_tables=2))

        def output(old, new):
            return b"ASB_TASKCOORD_INITIAL=" + json.dumps(old).encode() + b"\nASB_TASKCOORD_UPGRADE=" + json.dumps(new).encode() + b"\n"

        self.assertEqual(check.taskcoord_transition(output(initial, upgrade))["upgrade"]["after"]["schema"], 2)
        for change in (lambda value: value["after"].update(schema=1),
                       lambda value: value["after"].update(tasks_sha256="c" * 64),
                       lambda value: value["after"].update(reachability_quarantine_tables=0),
                       lambda value: value.update(immutable_retry_preserved=False),
                       lambda value: value["before"].update(schema=2)):
            new = copy.deepcopy(upgrade)
            change(new)
            with self.assertRaises(ValueError):
                check.taskcoord_transition(output(initial, new))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            check.taskcoord_transition(output(initial, upgrade) + output(initial, upgrade))

    def test_human_schema_evidence_rejects_missing_changed_or_duplicate_markers(self):
        output = b"ASB_HUMAN_SCHEMA_INITIAL=00000001\nASB_HUMAN_SCHEMA_UPGRADE=00000001\n"
        self.assertEqual(check.human_schema_transition(output), {"initial": 1, "upgrade": 1})
        for altered in (b"", output.replace(b"UPGRADE=00000001", b"UPGRADE=00000002"),
                        output + b"ASB_HUMAN_SCHEMA_INITIAL=00000001\n",
                        output + b"ASB_HUMAN_SCHEMA_UPGRADE=malformed\n"):
            with self.assertRaisesRegex(ValueError, "ambiguous"):
                check.human_schema_transition(altered)

    def test_human_package_checks_final_bytes_and_embedded_source(self):
        source, version = "a" * 40, "0.1.0~preview.1-1"
        binary = b"fixture bytes never executed"
        info = {"go_version": "go1.26.6", "main_path": check.deb.MODULE + "/cmd/asb-human", "settings": {"vcs.revision": source}}
        inventory = {"schema": "asb.debian-payload/v1", "package": "asb-human", "source_commit": source, "version": version,
                     "files": {"usr/bin/asb-human": check.apt.sha(binary)}, "modules": [],
                     "binaries": {"asb-human": dict(info, sha256=check.apt.sha(binary), bytes=len(binary))}}
        files = {"usr/bin/asb-human": binary, "usr/share/doc/asb-human/inventory.json": check.apt.encoded(inventory)}

        def archive(payloads, binary_modes=False):
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode="w:gz") as archive:
                for name, data in payloads.items():
                    item = tarfile.TarInfo("./" + name)
                    item.size, item.mode = len(data), 0o755 if binary_modes and name.startswith("usr/bin/") else 0o644
                    archive.addfile(item, io.BytesIO(data))
            return output.getvalue()

        control = check.deb.control("asb-human", version, "ASB QA <qa@example.invalid>", sum(map(len, files.values())))
        raw = b"!<arch>\n"
        for name, value in (("debian-binary", b"2.0\n"), ("control.tar.gz", archive({"control": control, "md5sums": b""})), ("data.tar.gz", archive(files, True))):
            header = f"{name:<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(value):<10}`\n".encode()
            raw += header + value + (b"\n" if len(value) % 2 else b"")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            filename = "asb-human_" + version + "_amd64.deb"
            (directory / filename).write_bytes(raw)
            (directory / "debian-candidates.json").write_bytes(check.apt.encoded({"source_commit": source, "version": version,
                "packages": [{"package": "asb-human", "file": filename, "bytes": len(raw), "sha256": check.apt.sha(raw)}]}))
            with patch.object(check.deb, "validate_static_elf"), patch.object(check.deb, "inspect_deb"), patch.object(check.deb, "build_info", return_value=(info, [])):
                result = check.inspect_human_package(directory, source)
                self.assertEqual(result["binary_sha256"], check.apt.sha(binary))
                with self.assertRaisesRegex(ValueError, "source mismatch"):
                    check.inspect_human_package(directory, "b" * 40)
                changed = dict(info, main_path="different/program")
                with patch.object(check.deb, "build_info", return_value=(changed, [])), self.assertRaisesRegex(ValueError, "embedded build"):
                    check.inspect_human_package(directory, source)
            (directory / filename).write_bytes(raw + b"changed")
            with self.assertRaisesRegex(ValueError, "bytes differ"):
                check.inspect_human_package(directory, source)


if __name__ == "__main__":
    unittest.main()
