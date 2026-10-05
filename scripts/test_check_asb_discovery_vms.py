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

    def test_service_failure_exits_readiness_without_waiting_for_timeout(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            share = root / "agent-b/evidence"
            share.mkdir(parents=True)
            vm.write_json(share / "stopped.json", {"role": "agent-b", "pid": 41, "stage": "task-server",
                                                  "passed": False, "category": "invalid-authority"})
            lab = vm.Lab(root, root / "binary")
            lab.processes = {"agent-b": Mock(poll=Mock(return_value=None))}
            with patch.object(vm.time, "sleep", side_effect=AssertionError("must not wait after service failure")):
                with self.assertRaisesRegex(RuntimeError, r"task-server \(invalid-authority\)"):
                    lab.ready("agent-b")
            diagnostics = lab.diagnostics()["guests"]["agent-b"]["process_markers"]
            self.assertEqual(diagnostics["stopped"]["stage"], "task-server")

    def test_systemd_exec_failure_is_reported_without_a_go_marker(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            share = root / "agent-b/evidence"
            share.mkdir(parents=True)
            vm.write_json(share / "service-exit.json", {"result": "exit-code", "exit_code": "exited", "exit_status": "203"})
            lab = vm.Lab(root, root / "binary")
            with self.assertRaisesRegex(RuntimeError, "exited before completion"):
                lab.reject_stopped("agent-b")
            self.assertEqual(vm.process_markers(share, "agent-b")["service-exit"]["exit_status"], "203")

    def test_process_diagnostics_reject_nonallowlisted_guest_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            share = Path(temporary)
            valid = {"role": "agent-b", "pid": 41, "stage": "discovery", "passed": False, "category": "permission"}
            for changed in (dict(valid, private="unreported-private-token"), dict(valid, stage="unreported-private-token"),
                            dict(valid, category="unreported-private-token"), dict(valid, pid=True), dict(valid, passed=True)):
                vm.write_json(share / "stopped.json", changed)
                result = vm.process_markers(share, "agent-b")
                self.assertEqual(result, {"stopped": {"invalid": True}})
                self.assertNotIn("unreported-private-token", json.dumps(result))

    def test_successful_stop_can_wait_for_its_response(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            share = root / "agent-b/evidence"
            share.mkdir(parents=True)
            vm.write_json(share / "stopped.json", {"role": "agent-b", "pid": 41, "stage": "control", "passed": True, "category": "none"})
            vm.write_json(share / "service-exit.json", {"result": "success", "exit_code": "exited", "exit_status": "0"})
            lab = vm.Lab(root, root / "binary")
            lab.reject_stopped("agent-b", allow_success=True)
            with self.assertRaises(RuntimeError):
                lab.reject_stopped("agent-b")


if __name__ == "__main__":
    unittest.main()
