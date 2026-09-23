#!/usr/bin/env python3

from __future__ import annotations

import hashlib
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
