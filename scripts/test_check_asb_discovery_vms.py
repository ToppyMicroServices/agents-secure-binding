"""Guards for the disposable VM harness; no guests or network mutation."""

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("discovery_vms", Path(__file__).with_name("check-asb-discovery-vms.py"))
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)


class VMHarnessGuards(unittest.TestCase):
    def test_manifest_signature_requires_good_and_full_pinned_identity(self):
        valid = "[GNUPG:] VALIDSIG " + vm.IMAGE_SIGNER + " 2026-09-05\n"
        good = "[GNUPG:] GOODSIG " + vm.IMAGE_SIGNER[-16:] + " Ubuntu Cloud Image Builder\n"
        vm.check_image_signature(valid + good + "[GNUPG:] NO_PUBKEY OTHER_KEY\n")
        for invalid in (valid, good, valid + good.replace("GOODSIG", "EXPKEYSIG"),
                        valid.replace(vm.IMAGE_SIGNER, "A" * 40) + good):
            with self.assertRaises(ValueError):
                vm.check_image_signature(invalid)

    def test_signed_manifest_requires_one_exact_image_hash(self):
        valid = "a" * 64 + " *" + vm.IMAGE_NAME + "\n"
        self.assertEqual(vm.signed_image_hash(valid), "a" * 64)
        for invalid in ("", valid + valid, valid.replace("a" * 64, "g" * 64), valid.replace(vm.IMAGE_NAME, "other.img")):
            with self.assertRaises(ValueError):
                vm.signed_image_hash(invalid)

    def test_bounded_evidence_rejects_oversize_and_nonobject(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "evidence.json"
            for raw in (b" " * 65537, b"[]"):
                path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    vm.read_json(path)

    def test_cleanup_continues_after_one_guest_fails_to_exit(self):
        lab = vm.Lab(Path("/nonexistent"), Path("/nonexistent/binary"))
        process = Mock()
        process.poll.return_value = None
        process.wait.side_effect = subprocess.TimeoutExpired("guest", 5)
        lab.processes = {"agent-a": process}
        lab.taps = ["owned-tap"]
        lab.bridge = "owned-bridge"
        lab.bridge_created = True
        with patch.object(vm.subprocess, "run", return_value=Mock(returncode=0)) as run:
            self.assertFalse(lab.cleanup())
            self.assertEqual([call.args[0] for call in run.call_args_list],
                             [["ip", "link", "delete", "owned-tap"], ["ip", "link", "delete", "owned-bridge"]])

    def test_diagnostics_classifies_failure_without_serial_payload(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "agent-a").mkdir()
            (root / "agent-a/serial.log").write_bytes(b"private-placeholder-never-report\nFailed to mount /evidence\n")
            lab = vm.Lab(root, root / "binary")
            lab.stage, lab.active_role = "wait-guest-ready", "agent-a"
            lab.processes = {"agent-a": Mock(poll=Mock(return_value=3))}
            result = lab.diagnostics()
            self.assertEqual(result["stage"], "wait-guest-ready")
            self.assertEqual(result["guests"]["agent-a"]["qemu_exit_status"], 3)
            self.assertTrue(result["guests"]["agent-a"]["serial_categories"]["mount_failure"])
            self.assertNotIn("private-placeholder", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
