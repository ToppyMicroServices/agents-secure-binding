#!/usr/bin/env python3
"""Exercise renewal authorization, attended boundaries, and expiry notifications."""
import copy
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("renewal", Path(__file__).with_name("renew-asb-apt.py"))
renewal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renewal)
spec = importlib.util.spec_from_file_location("pages_fixture", Path(__file__).with_name("test_asb_apt_pages.py"))
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
apt, pages = renewal.apt, renewal.pages


def baseline(root, key=b"public fixture"):
    manifest, files, public = fixtures.fixture()
    # Historical dates are allowed only in the independently pinned baseline.
    manifest.update(created=100, expires=100 + 7 * 86400)
    files.update(apt.metadata(manifest))
    files = {"apt/" + k: v for k, v in files.items()}
    files["asb-archive.gpg"] = key
    archive = root / "baseline.tar"
    archive.write_bytes(pages.canonical_archive(files))
    approved = {"schema": "asb.apt-renewal-policy/v1", "baseline_release": "apt-preview-fixture",
                "baseline_sha256": apt.sha(archive.read_bytes()), "baseline_bytes": archive.stat().st_size,
                "source_commit": manifest["source_commit"], "version": manifest["version"],
                "payload_sha256": renewal.payload_digest(manifest), "validity_days": 45,
                "notify_assignee": "fixture-owner", "notification_issue": 97}
    return archive, approved, public


class RenewalTest(unittest.TestCase):
    def test_policy_is_explicit_and_rejects_unknown_or_unbounded_values(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, original, _ = baseline(root)
            path = root / "policy.json"
            path.write_bytes(apt.encoded(original))
            self.assertEqual(renewal.policy(path), original)
            for changed in (dict(original, extra=True), dict(original, validity_days=46),
                            dict(original, validity_days=True), dict(original, baseline_bytes=True),
                            dict(original, baseline_sha256="x"), dict(original, notification_issue=0),
                            dict(original, baseline_release="../other"), dict(original, notify_assignee="@other")):
                path.write_bytes(apt.encoded(changed))
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    renewal.policy(path)

    def test_pinned_expired_baseline_produces_only_fresh_unsigned_45_day_metadata(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(pages, "public_keyring"):
            root = Path(temp)
            archive, approved, public = baseline(root)
            prepared = root / "prepared"
            plan = renewal.prepare(approved, public, archive, prepared)
            manifest = renewal.validate_prepared(prepared, approved, public)
            self.assertEqual(manifest["expires"] - manifest["created"], 45 * 86400)
            self.assertEqual(plan["payload_sha256"], approved["payload_sha256"])
            self.assertFalse((prepared / "repository" / apt.DIST / "InRelease").exists())
            for field, value in (("version", "9.0-1"), ("source_commit", "f" * 40), ("lifecycle_sha256", "f" * 64)):
                changed = copy.deepcopy(manifest)
                changed[field] = value
                with self.subTest(field=field), self.assertRaises(ValueError):
                    renewal.check_payload(changed, approved)
            changed = copy.deepcopy(manifest)
            changed["packages"][0]["control"] += "Homepage: https://other.invalid\n"
            with self.assertRaisesRegex(ValueError, "payload differs"):
                renewal.check_payload(changed, approved)

    def test_baseline_hash_and_fresh_signing_window_are_enforced(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(pages, "public_keyring"):
            root = Path(temp)
            archive, approved, public = baseline(root)
            with self.assertRaises(ValueError):
                renewal.prepare(dict(approved, baseline_sha256="f" * 64), public, archive, root / "bad")
            prepared = root / "prepared"
            renewal.prepare(approved, public, archive, prepared)
            manifest = apt.inspect_repository(prepared / "repository")
            with patch.object(renewal, "now", return_value=manifest["created"] + 7 * 86400 + 1):
                with self.assertRaisesRegex(ValueError, "older than seven days"):
                    renewal.validate_prepared(prepared, approved, public)
            changed = dict(manifest, expires=manifest["created"] + 46 * 86400)
            with self.assertRaises(ValueError):
                renewal.check_payload(changed, approved, fresh=True)
            changed = dict(manifest, expires=manifest["created"] + 7 * 86400)
            with self.assertRaisesRegex(ValueError, "45-day"):
                renewal.check_payload(changed, approved, fresh=True)

    def test_preparation_rejects_changed_plan_extra_signatures_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(pages, "public_keyring"):
            root = Path(temp)
            archive, approved, public = baseline(root)
            prepared = root / "prepared"
            renewal.prepare(approved, public, archive, prepared)
            plan = prepared / "signing-plan.json"
            original = plan.read_bytes()
            changed = json.loads(original)
            changed["baseline_sha256"] = "e" * 64
            plan.write_bytes(apt.encoded(changed))
            with self.assertRaisesRegex(ValueError, "signing plan"):
                renewal.validate_prepared(prepared, approved, public)
            plan.write_bytes(original)
            signature = prepared / "repository" / apt.DIST / "InRelease"
            signature.write_bytes(b"unrequested signature")
            with self.assertRaisesRegex(ValueError, "unexpected preparation"):
                renewal.validate_prepared(prepared, approved, public)
            signature.unlink()
            (prepared / "extra").symlink_to(plan)
            with self.assertRaises(ValueError):
                renewal.validate_prepared(prepared, approved, public)

    def test_release_must_be_immutable_preview_with_exact_digest_and_size(self):
        release = {"tag_name": "apt-preview-fixture", "draft": False, "prerelease": True, "immutable": True,
                   "assets": [{"name": "asb-apt-site.tar", "size": 100, "digest": "sha256:" + "a" * 64}]}
        self.assertEqual(renewal.release_asset(release, release["tag_name"], "a" * 64, 100), release["assets"][0])
        for change in (lambda r: r.update(draft=True), lambda r: r.update(prerelease=False),
                       lambda r: r.update(immutable=False), lambda r: r["assets"].append(r["assets"][0]),
                       lambda r: r["assets"][0].update(digest="sha256:" + "b" * 64),
                       lambda r: r["assets"][0].update(size=101)):
            invalid = copy.deepcopy(release)
            change(invalid)
            with self.assertRaises(ValueError):
                renewal.release_asset(invalid, release["tag_name"], "a" * 64, 100)
        with patch.object(renewal, "api", side_effect=AssertionError("reject before API")):
            for tag in ("../main", "v2.0.0", "apt-preview-renewal-evil"):
                with self.assertRaises(ValueError):
                    renewal.submit(tag, {}, {})

    def test_hardware_session_never_uses_software_keys_and_always_prompts_removal(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "home"
            home.mkdir(mode=0o700)
            identity, grip = "A" * 40, "B" * 40
            listing = ("fpr:::::::::" + identity + ":\ngrp:::::::::" + grip + ":\n").encode()
            for mode in ("success", "software", "sign-error", "timeout", "cancel"):
                calls, messages = [], []
                def run(args, **kwargs):
                    calls.append(args)
                    self.assertLessEqual(kwargs["timeout"], 180)
                    if "--list-keys" in args:
                        return Mock(stdout=listing)
                    if args[0] == "gpg-connect-agent":
                        kind = "D" if mode == "software" else "T"
                        return Mock(stdout=f"S KEYINFO {grip} {kind} serial OPENPGP.1 - - -\nOK\n".encode())
                    if mode == "sign-error":
                        raise subprocess.CalledProcessError(2, args)
                    if mode == "timeout":
                        raise subprocess.TimeoutExpired(args, kwargs["timeout"])
                    return Mock(stdout=b"")
                prompt = Mock(side_effect=KeyboardInterrupt) if mode == "cancel" else Mock()
                with patch.object(renewal.subprocess, "run", side_effect=run):
                    if mode == "success":
                        renewal.hardware_sign(root, home, identity, prompt=prompt, announce=messages.append)
                    else:
                        with self.assertRaises((ValueError, subprocess.SubprocessError, KeyboardInterrupt)):
                            renewal.hardware_sign(root, home, identity, prompt=prompt, announce=messages.append)
                self.assertEqual(len(messages), 1)
                self.assertIn("REMOVE THE YUBIKEY NOW", messages[0])
                signature_calls = [a for a in calls if "--clearsign" in a or "--detach-sign" in a]
                self.assertEqual(len(signature_calls), 2 if mode == "success" else 0 if mode in ("software", "cancel") else 1)
                for call in signature_calls:
                    self.assertIn(identity + "!", call)
                    self.assertNotIn("--passphrase", call)
                    self.assertNotIn("--pinentry-mode", call)

    def test_expiry_thresholds_calendar_boundary_and_future_rejection(self):
        current = int(datetime(2026, 12, 1, tzinfo=timezone.utc).timestamp())
        manifest = {"created": current - 86400, "expires": current + 30 * 86400}
        self.assertEqual(renewal.expiry_state(manifest, current), "ready")
        manifest["created"] = current
        for days, expected in ((30, "healthy"), (14, "warning"), (7, "urgent"), (0, "expired"), (-1, "expired")):
            manifest["expires"] = current + days * 86400
            self.assertEqual(renewal.expiry_state(manifest, current), expected)
        manifest["created"] = current + 11
        with self.assertRaises(ValueError):
            renewal.expiry_state(manifest, current)

    def test_notifications_are_bound_deduplicated_and_resolved(self):
        approved = {"notification_issue": 97, "notify_assignee": "fixture-owner"}
        issue = {"title": renewal.TITLE, "state": "open", "body": "initial"}
        with patch.object(renewal, "api", side_effect=[issue, {}, {}]) as api:
            result = renewal.notify(approved, "urgent", "expiry", cycle="2026-11")
            self.assertEqual(result["notification"], "updated")
            self.assertEqual(api.call_args_list[1].args[0], "issues/97")
            body = api.call_args_list[1].args[1]["body"]
        issue["body"] = body
        with patch.object(renewal, "api", return_value=issue) as api:
            self.assertEqual(renewal.notify(approved, "urgent", "expiry", cycle="2026-11")["notification"], "unchanged")
            api.assert_called_once()
        with patch.object(renewal, "api", side_effect=[issue, {}, {}]) as api:
            renewal.notify(approved, "healthy", "renewed", cycle="2026-11")
            self.assertEqual(api.call_args_list[1].args[1]["state"], "closed")
        with patch.object(renewal, "api", return_value=dict(issue, title="another issue")):
            with self.assertRaises(ValueError):
                renewal.notify(approved, "urgent", "expiry")

    def test_monitor_authenticates_dates_and_rejects_forged_manifest_or_transport(self):
        manifest, files, public = fixtures.fixture()
        approved = {"source_commit": manifest["source_commit"], "version": manifest["version"],
                    "payload_sha256": renewal.payload_digest(manifest)}
        release = apt.metadata(manifest)[str(apt.DIST / "Release")]
        for mode in ("valid", "forged-expiry", "noncanonical", "signature", "http", "redirect", "encoding", "oversize"):
            def open_response(request, **kwargs):
                name = request.full_url.removeprefix(public["base_url"] + "/")
                data = b"public fixture" if name == "asb-archive.gpg" else files[name.removeprefix("apt/")]
                if name.endswith("manifest.json"):
                    if mode == "forged-expiry":
                        data = apt.encoded(dict(manifest, expires=manifest["expires"] + 86400))
                    elif mode == "noncanonical":
                        data = b" " + data
                if mode == "oversize":
                    data = b"x" * (apt.MAX_METADATA + 1)
                response = Mock()
                response.status = 404 if mode == "http" else 200
                response.geturl.return_value = "https://other.invalid" if mode == "redirect" else request.full_url
                response.headers = {"Content-Encoding": "gzip"} if mode == "encoding" else {}
                response.read.return_value = data
                response.__enter__ = Mock(return_value=response)
                response.__exit__ = Mock(return_value=False)
                return response
            opener = Mock()
            opener.open.side_effect = open_response
            with patch.object(renewal, "build_opener", return_value=opener), patch.object(pages, "public_keyring"), patch.object(apt, "verify_signatures", return_value=("A" * 40, release), side_effect=ValueError("bad signature") if mode == "signature" else None):
                if mode == "valid":
                    self.assertEqual(renewal.monitor(approved, public)["state"], "urgent")
                else:
                    with self.subTest(mode=mode), self.assertRaises(ValueError):
                        renewal.monitor(approved, public)

    def test_monitor_failure_notifies_unknown_freshness_instead_of_healthy(self):
        approved = {"notification_issue": 97, "notify_assignee": "fixture-owner"}
        with patch.object(renewal, "policy", return_value=approved), patch.object(pages, "policy", return_value={}), patch.object(renewal, "monitor", side_effect=ValueError("untrusted response")), patch.object(renewal, "notify") as notify, patch.object(sys, "argv", ["renew", "monitor"]):
            self.assertEqual(renewal.main(), 2)
            self.assertEqual(notify.call_args.args[1], "error")
            self.assertIn("unknown", notify.call_args.args[2])

    def test_submit_never_dispatches_when_signed_archive_validation_fails(self):
        tag = "apt-preview-renewal-20261105-1793872800"
        release = {"tag_name": tag, "draft": False, "prerelease": True, "immutable": True,
                   "assets": [{"name": "asb-apt-site.tar", "size": 3, "digest": "sha256:" + "a" * 64}]}
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "site.tar"
            archive.write_bytes(b"bad")
            with patch.object(renewal, "api", return_value=release) as api, patch.object(renewal, "download", return_value=archive), patch.object(pages, "unpack", side_effect=ValueError("signature or bytes rejected")):
                with self.assertRaises(ValueError):
                    renewal.submit(tag, {}, {})
                api.assert_called_once()

    @unittest.skipUnless(sys.platform == "linux" and all(shutil.which(x) for x in ("gpg", "gpgv", "gpgconf")), "Linux CI uses ephemeral software keys, never a production token")
    def test_final_45_day_archive_is_verified_with_real_ephemeral_signatures(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "home"
            home.mkdir(mode=0o700)
            try:
                subprocess.run(["gpg", "--homedir", str(home), "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
                                "--quick-generate-key", "ASB renewal CI <renewal@example.invalid>", "ed25519", "sign", "1d"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=60)
                listing = subprocess.check_output(["gpg", "--homedir", str(home), "--with-colons", "--list-keys"], stderr=subprocess.PIPE).decode()
                signer = next(x.split(":")[9] for x in listing.splitlines() if x.startswith("fpr:"))
                key = subprocess.check_output(["gpg", "--homedir", str(home), "--export", signer])
                archive, approved, public = baseline(root, key)
                public.update(signers=[signer], keyring_sha256=apt.sha(key))
                prepared = root / "prepared"
                renewal.prepare(approved, public, archive, prepared)
                def ephemeral_sign(repository, _home, identity):
                    import argparse
                    apt.sign(argparse.Namespace(repository=repository, gnupg_home=home, signer=identity))
                output = root / "final.tar"
                with patch.object(renewal, "hardware_sign", side_effect=ephemeral_sign):
                    result = renewal.sign(prepared, output, home, approved, public, signer)
                pages.unpack(output, result["sha256"], root / "final")
                self.assertTrue(renewal.validate_signed(root / "final", approved, public)["passed"])
                manifest = apt.inspect_repository(root / "final/apt")
                tag = "apt-preview-renewal-" + datetime.fromtimestamp(manifest["created"], timezone.utc).strftime("%Y%m%d") + "-" + str(manifest["created"])
                release = {"tag_name": tag, "draft": False, "prerelease": True, "immutable": True,
                           "assets": [{"name": "asb-apt-site.tar", "size": output.stat().st_size, "digest": "sha256:" + result["sha256"]}]}
                with patch.object(renewal, "api", return_value=release) as api, patch.object(renewal, "download", return_value=output):
                    self.assertTrue(renewal.submit(tag, approved, public)["dispatched"])
                    self.assertEqual(api.call_args_list[-1].args[1]["ref"], "main")
                with patch.object(renewal, "gh") as gh, patch.object(renewal, "api", side_effect=[{"object": {"sha": "a" * 40}}, None]) as api:
                    self.assertEqual(renewal.upload(output, approved, public)["release_tag"], tag)
                    self.assertIn("--draft", gh.call_args_list[0].args)
                    self.assertIn("--draft=false", gh.call_args_list[1].args)
                    self.assertEqual(api.call_args_list[-1].args[0], "actions/workflows/apt-renewal.yaml/dispatches")
                signature = root / "final/apt" / apt.DIST / "InRelease"
                signature.write_bytes(signature.read_bytes() + b"changed")
                with self.assertRaises((ValueError, subprocess.SubprocessError)):
                    renewal.validate_signed(root / "final", approved, public)
            finally:
                subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)


if __name__ == "__main__":
    unittest.main()
