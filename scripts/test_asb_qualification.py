#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("asb-qualification.py")


class QualificationHarnessTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "source"
        self.root.mkdir()
        self.profile_path = self.root / "qualification" / "profile.json"
        self.profile_path.parent.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.name", "ASB Test"], cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.email", "asb-test@example.invalid"], cwd=self.root, check=True)

    def write_profile(self, command: list[str]) -> None:
        profile = {
            "profileVersion": 1,
            "id": "test-profile",
            "claim": "test qualification claim",
            "targetOs": [sys.platform, "darwin", "linux", "windows"],
            "checks": [{
                "id": "test-check",
                "required": True,
                "command": command,
                "timeoutSeconds": 10,
            }],
        }
        self.profile_path.write_text(json.dumps(profile), encoding="utf-8")

    def commit(self) -> None:
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "test: add profile"], cwd=self.root, check=True)

    def run_harness(self, *arguments: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *arguments],
            cwd=self.root, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )

    def refresh_checksums(self, bundle: Path) -> None:
        targets = sorted(
            path for path in bundle.iterdir()
            if path.is_file() and path.name not in {"SHA256SUMS", "SHA256SUMS.asc"}
        )
        (bundle / "SHA256SUMS").write_text(
            "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in targets),
            encoding="utf-8",
        )

    def assert_bundle_rejected_before_signing(self, bundle: Path, reason: str) -> None:
        before = {path.name: path.read_bytes() for path in bundle.iterdir()}
        verified = self.run_harness("verify", "--bundle", str(bundle))
        self.assertEqual(verified.returncode, 2, verified.stdout)
        self.assertIn(reason, verified.stderr)
        signed = self.run_harness("sign", "--bundle", str(bundle), "--signing-key", "invalid-fingerprint")
        self.assertEqual(signed.returncode, 2, signed.stdout)
        self.assertIn(reason, signed.stderr)
        self.assertNotIn("trusted signer", signed.stderr)
        self.assertEqual({path.name: path.read_bytes() for path in bundle.iterdir()}, before)

    def test_report_must_bind_every_declared_check_before_verifying_or_signing(self) -> None:
        self.write_profile([sys.executable, "-c", "print('ok')"])
        profile = json.loads(self.profile_path.read_text(encoding="utf-8"))
        profile["checks"].append({**profile["checks"][0], "id": "second-check"})
        self.profile_path.write_text(json.dumps(profile), encoding="utf-8")
        self.commit()
        original = self.base / "complete-bundle"
        result = self.run_harness(
            "run", "--profile", str(self.profile_path), "--source-root", str(self.root),
            "--output", str(original),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        cases = [
            ("empty", lambda r: r.update(checks=[]), "checks do not match"),
            ("omitted", lambda r: r["checks"].pop(), "checks do not match"),
            ("duplicate", lambda r: r["checks"][1].update(r["checks"][0]), "duplicate check"),
            ("unknown", lambda r: r["checks"][0].update(id="other-check"), "unknown or duplicate"),
            ("optionalized", lambda r: r["checks"][0].update(required=False), "definition does not match"),
            ("command", lambda r: r["checks"][0].update(command=["true"]), "definition does not match"),
            ("timeout", lambda r: r["checks"][0].update(timeoutSeconds=11), "definition does not match"),
            ("boolean-timeout", lambda r: r["checks"][0].update(timeoutSeconds=True), "definition does not match"),
            ("exit", lambda r: r["checks"][0].update(returnCode=1), "exit status zero"),
            ("boolean-exit", lambda r: r["checks"][0].update(returnCode=False), "invalid qualification return code"),
            ("status", lambda r: r["checks"][0].update(status="skipped"), "invalid qualification check status"),
            ("failed", lambda r: r["checks"][0].update(status="failed", returnCode=1), "incomplete required check"),
            ("missing-log", lambda r: r["checks"][0].update(stdout=None), "own output logs"),
            ("swapped-log", lambda r: r["checks"][0].update(stdout="second-check.stdout.log"), "own output logs"),
            ("metadata-log", lambda r: r["checks"][0].update(stderr="profile.json"), "own output logs"),
            ("secret-status", lambda r: r["checks"][0].update(secretMaterialDetected=None), "secret detection status"),
            ("profile-id", lambda r: r["profile"].update(id="other-profile"), "profile description"),
            ("claim", lambda r: r["profile"].update(claim="live provider qualified"), "profile description"),
            ("target-os", lambda r: r["environment"].update(os="unsupported-os"), "target OS is outside"),
            ("source-commit", lambda r: r["source"].pop("commit"), "source commit, tree and status"),
            ("source-tree", lambda r: r["source"].update(tree="unknown"), "source commit, tree and status"),
        ]
        for name, mutate, reason in cases:
            with self.subTest(name=name):
                bundle = self.base / f"mutated-{name}"
                shutil.copytree(original, bundle)
                report_path = bundle / "qa-report.json"
                report = json.loads(report_path.read_text(encoding="utf-8"))
                mutate(report)
                report_path.write_text(json.dumps(report), encoding="utf-8")
                self.refresh_checksums(bundle)
                self.assert_bundle_rejected_before_signing(bundle, reason)

    def test_rehashed_bundle_must_contain_a_valid_unambiguous_profile_and_report(self) -> None:
        self.write_profile([sys.executable, "-c", "print('ok')"])
        self.commit()
        original = self.base / "valid-profile-bundle"
        result = self.run_harness(
            "run", "--profile", str(self.profile_path), "--source-root", str(self.root),
            "--output", str(original),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("empty-profile", "duplicate-profile", "invalid-profile-object", "duplicate-report"):
            with self.subTest(name=name):
                bundle = self.base / name
                shutil.copytree(original, bundle)
                report_path = bundle / "qa-report.json"
                report = json.loads(report_path.read_text(encoding="utf-8"))
                profile_path = bundle / "profile.json"
                if name == "empty-profile":
                    profile = json.loads(profile_path.read_text(encoding="utf-8"))
                    profile["checks"] = []
                    profile_path.write_text(json.dumps(profile), encoding="utf-8")
                    reason = "checks must be a non-empty list"
                elif name == "duplicate-profile":
                    profile_path.write_text('{"checks": [],' + profile_path.read_text(encoding="utf-8")[1:], encoding="utf-8")
                    reason = "duplicate JSON field"
                elif name == "invalid-profile-object":
                    profile_path.write_text("[]", encoding="utf-8")
                    reason = "JSON document must be an object"
                else:
                    reason = "duplicate JSON field"
                report["profile"]["sha256"] = "sha256:" + hashlib.sha256(profile_path.read_bytes()).hexdigest()
                report_text = json.dumps(report)
                if name == "duplicate-report":
                    report_text = '{"checks": [],' + report_text[1:]
                report_path.write_text(report_text, encoding="utf-8")
                self.refresh_checksums(bundle)
                self.assert_bundle_rejected_before_signing(bundle, reason)

    def test_optional_failure_and_wrong_target_remain_verifiable_non_claims(self) -> None:
        self.write_profile([sys.executable, "-c", "print('ok')"])
        profile = json.loads(self.profile_path.read_text(encoding="utf-8"))
        profile["checks"].append({
            "id": "optional-check", "required": False,
            "command": [sys.executable, "-c", "raise SystemExit(1)"], "timeoutSeconds": 10,
        })
        for name, target_os, expected_status in (
            ("optional-failure", [sys.platform, "darwin", "linux", "windows"], "passed"),
            ("upper-target", ["DARWIN", "LINUX", "WINDOWS"], "passed"),
            ("wrong-target", ["unsupported-os"], "failed"),
        ):
            with self.subTest(name=name):
                profile["targetOs"] = target_os
                self.profile_path.write_text(json.dumps(profile), encoding="utf-8")
                self.commit()
                bundle = self.base / name
                result = self.run_harness(
                    "run", "--profile", str(self.profile_path), "--source-root", str(self.root),
                    "--output", str(bundle),
                )
                self.assertEqual(result.returncode, 0 if expected_status == "passed" else 1, result.stderr)
                verified = self.run_harness("verify", "--bundle", str(bundle))
                self.assertEqual(verified.returncode, 0, verified.stderr)
                self.assertIn(f'"status":"{expected_status}"', verified.stdout)
                self.assertIn('"qualificationClaim":false', verified.stdout)

    def test_signing_keeps_prevalidated_log_digests(self) -> None:
        self.write_profile([sys.executable, "-c", "print('ok')"])
        self.commit()
        bundle = self.base / "signing-race-bundle"
        result = self.run_harness(
            "run", "--profile", str(self.profile_path), "--source-root", str(self.root),
            "--output", str(bundle),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        spec = importlib.util.spec_from_file_location("asb_qualification_signing_race", SCRIPT)
        harness = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(harness)
        report_path = bundle / "qa-report.json"
        sums_path = bundle / "SHA256SUMS"
        old_report, old_sums = report_path.read_bytes(), sums_path.read_bytes()
        write_atomic = harness.write_private_atomic
        mutated = False

        def replace_log_before_claim_write(path: Path, data: bytes) -> None:
            nonlocal mutated
            if path == report_path and not mutated:
                mutated = True
                (bundle / "test-check.stdout.log").write_bytes(b"changed after validation\n")
            write_atomic(path, data)

        def fake_sign(command: list[str], **kwargs) -> subprocess.CompletedProcess[bytes]:
            Path(command[command.index("--output") + 1]).write_bytes(b"synthetic signature")
            return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

        args = harness.parser().parse_args([
            "sign", "--bundle", str(bundle), "--signing-key", "A" * 40,
        ])
        # Isolate the file race from cryptography; the separate GPG test verifies real signatures.
        with mock.patch.object(harness, "write_private_atomic", replace_log_before_claim_write), \
                mock.patch.object(harness, "gpg_executable", return_value="synthetic-gpg"), \
                mock.patch.object(harness.subprocess, "run", side_effect=fake_sign), \
                mock.patch.object(harness, "verify_signature", return_value="A" * 40) as verified:
            with self.assertRaisesRegex(ValueError, "digest mismatch: test-check.stdout.log"):
                harness.sign_bundle(args)
            verified.assert_not_called()
        self.assertTrue(mutated)
        self.assertEqual(report_path.read_bytes(), old_report)
        self.assertEqual(sums_path.read_bytes(), old_sums)
        self.assertFalse((bundle / "SHA256SUMS.asc").exists())

    def test_dirty_source_is_rejected_before_profile_execution(self) -> None:
        marker = self.base / "executed.marker"
        tracked = self.root / "tracked.txt"
        tracked.write_text("clean\n", encoding="utf-8")
        self.write_profile([
            sys.executable, "-c",
            f"from pathlib import Path; Path({str(marker)!r}).write_text('executed')",
        ])
        self.commit()
        tracked.write_text("dirty\n", encoding="utf-8")

        bundle = self.base / "dirty-bundle"
        result = self.run_harness(
            "run", "--profile", str(self.profile_path), "--source-root", str(self.root),
            "--output", str(bundle),
        )

        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(marker.exists())
        self.assertFalse(bundle.exists())

    def test_unsigned_result_is_non_claim_and_forged_claim_is_rejected(self) -> None:
        self.write_profile([sys.executable, "-c", "print('ok')"])
        self.commit()
        bundle = self.base / "clean-bundle"
        result = self.run_harness(
            "run", "--profile", str(self.profile_path), "--source-root", str(self.root),
            "--output", str(bundle),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report_path = bundle / "qa-report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["status"], "passed")
        self.assertFalse(report["qualificationClaim"])

        verified = self.run_harness("verify", "--bundle", str(bundle))
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertIn('"qualificationClaim":false', verified.stdout)

        report["qualificationClaim"] = True
        report_path.write_text(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        targets = sorted(
            path for path in bundle.iterdir()
            if path.is_file() and path.name not in {"SHA256SUMS", "SHA256SUMS.asc"}
        )
        (bundle / "SHA256SUMS").write_text(
            "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in targets),
            encoding="utf-8",
        )
        forged = self.run_harness("verify", "--bundle", str(bundle))
        self.assertEqual(forged.returncode, 2)
        self.assertIn("requires a signature and trusted signer", forged.stderr)

    def test_profile_without_required_checks_is_rejected(self) -> None:
        profile = {
            "profileVersion": 1,
            "id": "empty-profile",
            "claim": "must not qualify without checks",
            "targetOs": ["darwin", "linux", "windows"],
            "checks": [],
        }
        self.profile_path.write_text(json.dumps(profile), encoding="utf-8")
        self.commit()
        result = self.run_harness(
            "run", "--profile", str(self.profile_path), "--source-root", str(self.root),
            "--output", str(self.base / "empty-bundle"),
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("checks must be a non-empty list", result.stderr)

    def test_checks_run_from_the_recorded_commit_snapshot(self) -> None:
        started = self.base / "started.marker"
        observed = self.base / "observed.txt"
        payload = self.root / "payload.txt"
        payload.write_text("A\n", encoding="utf-8")
        self.write_profile([
            sys.executable, "-c",
            "from pathlib import Path; import time; "
            f"Path({str(started)!r}).write_text('started'); time.sleep(1); "
            f"Path({str(observed)!r}).write_text(Path('payload.txt').read_text())",
        ])
        self.commit()
        commit_a = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.root, check=True,
            text=True, stdout=subprocess.PIPE,
        ).stdout.strip()

        payload.write_text("B\n", encoding="utf-8")
        self.commit()
        commit_b = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.root, check=True,
            text=True, stdout=subprocess.PIPE,
        ).stdout.strip()
        subprocess.run(["git", "checkout", "-q", "--detach", commit_a], cwd=self.root, check=True)

        bundle = self.base / "snapshot-bundle"
        process = subprocess.Popen(
            [
                sys.executable, str(SCRIPT), "run", "--profile", str(self.profile_path),
                "--source-root", str(self.root), "--output", str(bundle),
            ],
            cwd=self.root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + 10
        while not started.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertTrue(started.exists(), "qualification check did not start")
        subprocess.run(["git", "checkout", "-q", "--detach", commit_b], cwd=self.root, check=True)
        stdout, stderr = process.communicate(timeout=15)

        self.assertEqual(process.returncode, 0, stderr)
        report = json.loads((bundle / "qa-report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["source"]["commit"], commit_a)
        self.assertEqual(observed.read_text(encoding="utf-8"), "A\n")
        self.assertIn('"status":"passed"', stdout)

    @unittest.skipIf(os.name == "nt", "the race wrapper uses a POSIX shell")
    def test_signature_verification_uses_loaded_bundle_bytes(self) -> None:
        real_gpg = shutil.which("gpg")
        self.assertIsNotNone(real_gpg, "gpg is required for qualification signature tests")
        self.write_profile([sys.executable, "-c", "print('ok')"])
        self.commit()
        trusted = self.base / "trusted-bundle"
        result = self.run_harness(
            "run", "--profile", str(self.profile_path), "--source-root", str(self.root),
            "--output", str(trusted),
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        gnupg_home = self.base / "gnupg"
        gnupg_home.mkdir(mode=0o700)
        gpg_env = os.environ.copy()
        gpg_env["GNUPGHOME"] = str(gnupg_home)
        generated = subprocess.run(
            [real_gpg, "--batch", "--passphrase", "", "--quick-generate-key",
             "ASB Qualification Test <asb-test@example.invalid>", "ed25519", "sign", "0"],
            cwd=self.root, env=gpg_env, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False,
        )
        if generated.returncode != 0 and os.environ.get("ASB_REQUIRE_GPG_TEST") != "1":
            self.skipTest("gpg-agent is unavailable in this local environment")
        self.assertEqual(generated.returncode, 0, generated.stderr)
        listing = subprocess.run(
            [real_gpg, "--batch", "--with-colons", "--list-secret-keys"],
            cwd=self.root, env=gpg_env, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(listing.returncode, 0, listing.stderr)
        fingerprint = next(
            line.split(":")[9] for line in listing.stdout.splitlines()
            if line.startswith("fpr:")
        )
        signed = self.run_harness(
            "sign", "--bundle", str(trusted), "--signing-key", fingerprint,
            env=gpg_env,
        )
        self.assertEqual(signed.returncode, 0, signed.stderr)
        verified = self.run_harness(
            "verify", "--bundle", str(trusted), "--trusted-signer", fingerprint,
            env=gpg_env,
        )
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertIn('"signerVerified":true', verified.stdout)
        self.assertNotIn(fingerprint, verified.stdout)

        attack = self.base / "attack-bundle"
        shutil.copytree(trusted, attack)
        report_path = attack / "qa-report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["limitations"].append("attacker-controlled mutation")
        report_path.write_text(
            json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        targets = sorted(
            path for path in attack.iterdir()
            if path.is_file() and path.name not in {"SHA256SUMS", "SHA256SUMS.asc"}
        )
        (attack / "SHA256SUMS").write_text(
            "".join(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
                for path in targets
            ),
            encoding="utf-8",
        )

        wrapper_dir = self.base / "wrapper"
        wrapper_dir.mkdir()
        wrapper = wrapper_dir / "gpg"
        wrapper.write_text(
            "#!/bin/sh\n"
            "cp -R \"$TRUSTED_BUNDLE/.\" \"$ATTACK_BUNDLE/\"\n"
            "exec \"$REAL_GPG\" \"$@\"\n",
            encoding="utf-8",
        )
        wrapper.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        attack_env = gpg_env.copy()
        attack_env.update({
            "PATH": str(wrapper_dir) + os.pathsep + attack_env.get("PATH", ""),
            "TRUSTED_BUNDLE": str(trusted),
            "ATTACK_BUNDLE": str(attack),
            "REAL_GPG": real_gpg,
        })
        attacked = self.run_harness(
            "verify", "--bundle", str(attack), "--trusted-signer", fingerprint,
            env=attack_env,
        )
        self.assertEqual(attacked.returncode, 2, attacked.stderr)
        self.assertIn("qualification signature verification failed", attacked.stderr)


if __name__ == "__main__":
    unittest.main()
