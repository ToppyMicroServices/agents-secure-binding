#!/usr/bin/env python3

import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location("linux_reference", Path(__file__).with_name("check-asb-linux-reference.py"))
REFERENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REFERENCE)


class ReferenceEvidenceTest(unittest.TestCase):
    def environment(self):
        return {
            "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64", "ImageOS": "ubuntu24",
            "ImageVersion": "20261004.1.0", "GITHUB_REPOSITORY": REFERENCE.REPOSITORY,
            "GITHUB_JOB": "conformance", "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_WORKFLOW_REF": REFERENCE.REPOSITORY + "/.github/workflows/aws-s3-linux.yaml@refs/heads/main",
        }

    def test_named_environment_rejects_different_host_workflow_or_missing_evidence(self):
        env = self.environment()
        release = {"ID": "ubuntu", "VERSION_ID": "24.04"}
        self.assertEqual(REFERENCE.named_environment(env, "Linux", "x86_64", release), env)
        for key, value in {"RUNNER_ENVIRONMENT": "self-hosted", "ImageOS": "ubuntu22",
                           "GITHUB_REPOSITORY": "other/repository", "GITHUB_JOB": "other",
                           "GITHUB_WORKFLOW_REF": "other/workflow", "GITHUB_SHA": "a" * 39,
                           "ImageVersion": "", "GITHUB_RUN_ID": "123\nprivate"}.items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                REFERENCE.named_environment({**env, key: value}, "Linux", "x86_64", release)
        with self.assertRaises(ValueError):
            REFERENCE.named_environment(env, "Darwin", "x86_64", release)
        with self.assertRaises(ValueError):
            REFERENCE.named_environment(env, "Linux", "x86_64", {"ID": "ubuntu", "VERSION_ID": "22.04"})

    def relay_events(self):
        return [
            *[{"Action": "pass", "Package": package, "Test": test}
              for package, tests in REFERENCE.RELAY_TESTS.items() for test in tests],
            *[{"Action": "pass", "Package": package} for package in REFERENCE.RELAY_TESTS],
        ]

    def test_relay_requires_named_tests_and_package_completion_without_skips(self):
        events = self.relay_events()
        encode = lambda value: b"\n".join(json.dumps(event).encode() for event in value)
        result = REFERENCE.relay_evidence(encode(events))
        self.assertEqual(len(result["tests"]), 11)
        self.assertFalse(result["live_delivery_provider_tested"])
        cases = [events[1:], events[:-1], [{**event, "Package": "other"} for event in events],
                 [*events, {"Action": "fail"}], [*events, {**events[0], "Action": "skip"}]]
        for case in cases:
            with self.subTest(case=case[-1]), self.assertRaises(ValueError):
                REFERENCE.relay_evidence(encode(case))

    def offline_fixture(self, directory):
        binary = b"synthetic-binary-for-parser-test"
        sha = hashlib.sha256(binary).hexdigest()
        (directory / "asb-s3").write_bytes(binary)
        (directory / "source-commit.txt").write_text("a" * 40 + "\n")
        (directory / "binary.sha256").write_text(sha + "  evidence/asb-s3\n")
        events = [
            *[{"Action": "pass", "Package": package, "Test": test}
              for package, tests in REFERENCE.CORE_TESTS.items() for test in tests],
            *[{"Action": "pass", "Package": package} for package in REFERENCE.CORE_TESTS],
        ]
        (directory / "tests.jsonl").write_text("\n".join(json.dumps(event) for event in events))
        for name, tests in REFERENCE.OFFLINE_TESTS.items():
            text = "".join(f"--- PASS: {test} (0.01s)\n" for test in tests)
            if name == "qa-systemd.txt":
                text += ("systemd_runtime_identity main_pid=123 uid=987 no_new_privileges=true "
                         "effective_capabilities_zero=true executable_sha256=" + sha + "\n")
            (directory / name).write_text(text)
        required_checks = {"workflow_prior_steps", "source_commit", "binary_sha256", "core:no_failure"}
        required_checks.update(name + ":no_failure" for name in REFERENCE.OFFLINE_TESTS)
        required_checks.update(test for tests in REFERENCE.OFFLINE_TESTS.values() for test in tests)
        required_checks.update(test for tests in REFERENCE.CORE_TESTS.values() for test in tests)
        report = {
            "schema": "asb.s3-operational-qa/v1", "status": "passed", "source_commit": "a" * 40,
            "checks": dict.fromkeys(required_checks, True), "real_aws": False, "container_boot_is_physical_reboot": False,
            "physical_power_loss_qualified": False, "organization_deployment_qualified": False,
            "long_term_leak_absence_proven": False,
        }
        return report

    def write_report(self, directory, report):
        report["files_sha256"] = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in directory.iterdir() if path.name != "qa-result.json"
        }
        (directory / "qa-result.json").write_text(json.dumps(report))

    def test_offline_binds_source_binary_raw_gates_and_live_process_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            report = self.offline_fixture(directory)
            self.write_report(directory, report)
            result = REFERENCE.validate_offline(directory, "a" * 40, directory / "asb-s3")
            self.assertEqual(result["service_uid"], 987)
            self.assertFalse(result["organization_deployment_qualified"])
            with self.assertRaises(ValueError):
                REFERENCE.validate_offline(directory, "b" * 40, directory / "asb-s3")
            for field, value in {"status": "failed", "real_aws": True, "checks": {"one": True}}.items():
                altered = copy.deepcopy(report)
                altered[field] = value
                self.write_report(directory, altered)
                with self.subTest(field=field), self.assertRaises(ValueError):
                    REFERENCE.validate_offline(directory, "a" * 40, directory / "asb-s3")
            self.write_report(directory, report)
            original = (directory / "qa-systemd.txt").read_text()
            for old, new in [("uid=987", "uid=0"), ("main_pid=123", "main_pid=0"),
                             ("no_new_privileges=true", "no_new_privileges=false"),
                             ("--- PASS:", "--- SKIP:"),
                             ("executable_sha256=", "unmeasured_hash=")]:
                (directory / "qa-systemd.txt").write_text(original.replace(old, new))
                self.write_report(directory, report)  # Rehashing cannot replace an absent gate.
                with self.subTest(old=old), self.assertRaises(ValueError):
                    REFERENCE.validate_offline(directory, "a" * 40, directory / "asb-s3")
            (directory / "qa-systemd.txt").write_text(original)
            self.write_report(directory, report)
            (directory / "qa-systemd.txt").write_text(original + "changed")
            with self.assertRaises(ValueError):
                REFERENCE.validate_offline(directory, "a" * 40, directory / "asb-s3")

    def test_manifest_rejects_parent_paths_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            report = self.offline_fixture(directory)
            self.write_report(directory, report)
            report["files_sha256"]["../outside"] = "a" * 64
            (directory / "qa-result.json").write_text(json.dumps(report))
            with self.assertRaises(ValueError):
                REFERENCE.validate_offline(directory, "a" * 40, directory / "asb-s3")
            self.write_report(directory, report)
            (directory / "source-commit.txt").unlink()
            (directory / "source-commit.txt").symlink_to(directory / "binary.sha256")
            with self.assertRaises(ValueError):
                REFERENCE.validate_offline(directory, "a" * 40, directory / "asb-s3")


if __name__ == "__main__":
    unittest.main()
