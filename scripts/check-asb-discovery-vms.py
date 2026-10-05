#!/usr/bin/env python3
"""Run a bounded three-guest ASB lab on an explicitly selected disposable Linux runner."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import tempfile
import time
import urllib.request
import uuid

ROLES = ("agent-a", "relay", "agent-b")
IMAGE_NAME = "ubuntu-24.04-minimal-cloudimg-amd64.img"
IMAGE_BASE = "https://cloud-images.ubuntu.com/minimal/releases/noble/release-20260905/"
# Ubuntu Security FAQ: https://wiki.ubuntu.com/Security/FAQ
IMAGE_SIGNER = "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81"
MAX_RUNTIME = 20 * 60
STAGES = {"config", "discovery", "task-server", "ready", "control"}
ERROR_CATEGORIES = {"none", "address-not-available", "address-in-use", "permission", "not-found", "deadline",
                    "cancelled", "missing-trust-source", "trust-source-unavailable", "missing-replay-cache",
                    "missing-policy", "invalid-authority", "invalid-token-lifetime", "missing-context",
                    "invalid-current-time", "other"}
SERVICE_RESULTS = {"success", "resources", "timeout", "exit-code", "signal", "core-dump", "watchdog",
                   "start-limit-hit", "oom-kill", "exec-condition", "other"}
EXIT_CODES = {"exited", "killed", "dumped", "unknown"}
EXIT_SIGNALS = {"HUP", "INT", "QUIT", "ILL", "ABRT", "BUS", "FPE", "KILL", "SEGV", "PIPE", "ALRM", "TERM", "unknown"}
EXEC_ERRORS = {"none", "missing", "permission", "exec-format", "text-file-busy", "io", "no-memory", "other", "unavailable"}
BOOT_PHASES = {"mounts", "directories", "config-copy", "binary-copy", "binary-verify", "unit-start", "complete"}
BOOT_ERRORS = {"none", "permission", "missing", "timeout", "command-failed", "verification-failed"}
DIAGNOSTIC_PATHS = {"/", "/usr", "/usr/local", "/usr/local/bin", "/usr/local/bin/asb-interaction"}
EXIT_MARKER = """#!/bin/sh
set -eu
exec /usr/bin/python3 -I /usr/local/libexec/asb-vm-diagnostics.py exit
"""


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def download(url: str, destination: Path, maximum: int, deadline: float) -> None:
    size = 0
    if deadline <= time.monotonic():
        raise TimeoutError("download deadline exceeded")
    with urllib.request.urlopen(url, timeout=min(30, deadline - time.monotonic())) as response, destination.open("xb") as stream:
        if response.url != url:
            raise ValueError("unexpected image/key redirect")
        while chunk := response.read(1024 * 1024):
            if time.monotonic() >= deadline:
                raise TimeoutError("download deadline exceeded")
            size += len(chunk)
            if size > maximum:
                raise ValueError("download exceeds fixed size bound")
            stream.write(chunk)


def write_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True) + "\n")
    temporary.chmod(0o644)
    temporary.replace(path)


def read_json(path: Path) -> dict:
    with path.open("rb") as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError("guest evidence exceeds bound")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("guest evidence must be an object")
    return value


def valid_path_metadata(value: object) -> bool:
    if not isinstance(value, dict) or not set(value) <= DIAGNOSTIC_PATHS:
        return False
    for metadata in value.values():
        if not isinstance(metadata, dict):
            return False
        if metadata == {"exists": False}:
            continue
        if (set(metadata) != {"exists", "mode", "uid", "gid", "symlink"} or metadata.get("exists") is not True
                or type(metadata.get("symlink")) is not bool
                or any(type(metadata.get(key)) is not int or not 0 <= metadata[key] <= maximum
                       for key, maximum in (("mode", 0o7777), ("uid", 2 ** 32 - 1), ("gid", 2 ** 32 - 1)))):
            return False
    return True


def process_markers(share: Path, role: str) -> dict:
    """Copy only fixed diagnostic fields; never report guest error text."""
    result = {}
    for name in ("stage", "stopped", "service-exit", "bootstrap"):
        path = share / (name + ".json")
        if not path.exists():
            continue
        try:
            value = read_json(path)
            if name == "bootstrap":
                fields = {"phase", "passed", "category", "input_mount", "evidence_mount", "config_copied", "binary_copied",
                          "binary_sha256", "binary_static_elf", "paths"}
                binary_hash = value.get("binary_sha256")
                if (set(value) != fields or value.get("phase") not in BOOT_PHASES or value.get("category") not in BOOT_ERRORS
                        or any(type(value.get(key)) is not bool for key in ("passed", "input_mount", "evidence_mount", "config_copied", "binary_copied", "binary_static_elf"))
                        or not isinstance(binary_hash, str) or (binary_hash != "" and (len(binary_hash) != 64 or any(c not in "0123456789abcdef" for c in binary_hash)))
                        or not valid_path_metadata(value.get("paths"))
                        or (value["passed"] and (value["phase"] != "complete" or value["category"] != "none"))):
                    raise ValueError("invalid bootstrap marker")
                result[name] = {key: value[key] for key in fields}
                continue
            if name == "service-exit":
                status = value.get("exit_status")
                if (set(value) != {"result", "exit_code", "exit_status", "exec_error", "paths"}
                        or value.get("result") not in SERVICE_RESULTS or value.get("exit_code") not in EXIT_CODES
                        or not isinstance(status, str) or len(status) > 8
                        or not (status in EXIT_SIGNALS or (status.isascii() and status.isdecimal() and int(status) <= 255))
                        or value.get("exec_error") not in EXEC_ERRORS or not valid_path_metadata(value.get("paths"))):
                    raise ValueError("invalid service marker")
                result[name] = {key: value[key] for key in ("result", "exit_code", "exit_status", "exec_error", "paths")}
                continue
            expected = {"role", "pid", "stage"} | ({"passed", "category"} if name == "stopped" else set())
            if (set(value) != expected or value.get("role") != role or type(value.get("pid")) is not int
                    or not 0 < value["pid"] <= 2 ** 31 - 1 or value.get("stage") not in STAGES):
                raise ValueError("invalid process marker")
            if name == "stopped" and (type(value.get("passed")) is not bool or value.get("category") not in ERROR_CATEGORIES
                                       or value["passed"] != (value["category"] == "none")):
                raise ValueError("invalid stopped marker")
            result[name] = {key: value[key] for key in expected}
        except (OSError, ValueError, TypeError):
            result[name] = {"invalid": True}
    return result


def signed_image_hash(sums: str) -> str:
    matches = []
    for line in sums.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1].lstrip("*") == IMAGE_NAME:
            matches.append(fields[0])
    if len(matches) != 1 or len(matches[0]) != 64 or any(c not in "0123456789abcdef" for c in matches[0]):
        raise ValueError("cloud image hash missing or ambiguous")
    return matches[0]


def check_image_signature(status: str) -> None:
    # Ubuntu manifests may also carry a second signature whose key is not
    # installed. Require both an unexpired good signature and its full pinned
    # fingerprint; an unknown extra signer cannot supply either condition.
    lines = [line.split() for line in status.splitlines()]
    valid = any(len(parts) >= 3 and parts[:2] == ["[GNUPG:]", "VALIDSIG"] and parts[2] == IMAGE_SIGNER for parts in lines)
    good = any(len(parts) >= 3 and parts[:2] == ["[GNUPG:]", "GOODSIG"] and parts[2] == IMAGE_SIGNER[-16:] for parts in lines)
    if not valid or not good:
        raise ValueError("cloud image signature does not match pinned signing identity")


class Lab:
    def __init__(self, root: Path, binary: Path):
        self.root, self.binary = root, binary
        self.started = time.monotonic()
        self.deadline = self.started + MAX_RUNTIME
        self.stage = "initialize"
        self.active_role: str | None = None
        self.bridge = "asb" + uuid.uuid4().hex[:8]
        self.bridge_created = False
        self.taps: list[str] = []
        self.processes: dict[str, subprocess.Popen] = {}
        self.logs = []
        self.sequence = 0
        self.acceleration = "kvm" if os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg"
        self.guest_acceleration: dict[str, str] = {}

    def run(self, *args: str, timeout: int = 120) -> bytes:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("VM qualification deadline exceeded")
        return subprocess.check_output(args, stderr=subprocess.PIPE, timeout=min(timeout, remaining))

    def prepare_image(self) -> dict:
        self.stage = "image-signing-key"
        home = self.root / "gnupg"
        home.mkdir(mode=0o700)
        key = self.root / "image-key.asc"
        download("https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x" + IMAGE_SIGNER, key, 1024 * 1024, self.deadline)
        self.run("gpg", "--no-autostart", "--homedir", str(home), "--batch", "--import", str(key))
        sums, signature = self.root / "SHA256SUMS", self.root / "SHA256SUMS.gpg"
        self.stage = "image-signed-manifest"
        download(IMAGE_BASE + sums.name, sums, 65536, self.deadline)
        download(IMAGE_BASE + signature.name, signature, 65536, self.deadline)
        try:
            status = self.run("gpg", "--no-autostart", "--homedir", str(home), "--batch", "--no-auto-key-retrieve", "--status-fd", "1",
                              "--verify", str(signature), str(sums))
        except subprocess.CalledProcessError as error:
            if error.returncode != 2:  # 2 can mean the optional second key is absent.
                raise
            status = error.output
        check_image_signature(status.decode())
        expected_hash = signed_image_hash(sums.read_text())
        image = self.root / IMAGE_NAME
        self.stage = "image-download-and-checksum"
        download(IMAGE_BASE + IMAGE_NAME, image, 512 * 1024 * 1024, self.deadline)
        if digest(image) != expected_hash:
            raise ValueError("cloud image checksum mismatch")
        return {"url": IMAGE_BASE + IMAGE_NAME, "sha256": expected_hash, "signer": IMAGE_SIGNER}

    def prepare_guests(self) -> None:
        self.stage = "bootstrap-ephemeral-credentials"
        self.run(str(self.binary), "--prepare-vm-dir", str(self.root / "credentials"))
        self.stage = "create-private-bridge"
        self.run("ip", "link", "add", self.bridge, "type", "bridge")
        self.bridge_created = True
        self.run("ip", "link", "set", self.bridge, "up")
        for index, role in enumerate(ROLES):
            self.stage, self.active_role = "prepare-guest-disk-network-cloud-init", role
            guest = self.root / role
            guest.mkdir(mode=0o700)
            inputs, evidence = guest / "input", guest / "evidence"
            inputs.mkdir(mode=0o700)
            evidence.mkdir(mode=0o777)
            evidence.chmod(0o777)  # Parent is private; only this guest receives the share.
            shutil.copy2(self.binary, inputs / "asb-interaction")
            shutil.copy2(self.root / "credentials" / role / "config.json", inputs / "config.json")
            self.run("qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(self.root / IMAGE_NAME), str(guest / "disk.qcow2"), "4G")
            shutil.copyfile("/usr/share/OVMF/OVMF_VARS_4M.fd", guest / "vars.fd")
            tap = self.bridge + str(index)
            self.run("ip", "tuntap", "add", "dev", tap, "mode", "tap")
            self.taps.append(tap)
            self.run("ip", "link", "set", tap, "master", self.bridge)
            self.run("ip", "link", "set", tap, "up")
            mac = f"52:54:00:12:34:{index + 11:02x}"
            (guest / "meta-data").write_text(f"instance-id: {uuid.uuid4()}\nlocal-hostname: asb-{role}\n")
            (guest / "network-config").write_text("version: 2\nethernets:\n  lab:\n    match:\n      macaddress: " + mac +
                f"\n    set-name: lab0\n    addresses: [10.203.0.{index + 11}/24]\n    dhcp4: false\n    dhcp6: false\n    optional: true\n")
            unit = ("[Unit]\nDescription=ASB disposable qualification node\nRequiresMountsFor=/evidence\nWants=network-online.target\nAfter=network-online.target\n"
                    "[Service]\nUser=asb\nGroup=asb\nWorkingDirectory=/var/lib/asb-vm\nKillSignal=SIGINT\nTimeoutStopSec=10\n"
                    f"ExecStart=/usr/local/bin/asb-interaction --role {role} --config /etc/asb-vm/config.json --ready /evidence/ready.json --control-dir /evidence\n"
                    "ExecStopPost=+/usr/local/bin/asb-vm-exit-marker\n"
                    "Restart=no\n[Install]\nWantedBy=multi-user.target\n")
            cloud = {"users": [{"name": "asb", "system": True, "lock_passwd": True}], "ssh_pwauth": False,
                "package_update": False, "package_upgrade": False,
                "mounts": [["asb-input", "/mnt/asb-input", "9p", "trans=virtio,version=9p2000.L,ro", "0", "0"],
                           ["asb-evidence", "/evidence", "9p", "trans=virtio,version=9p2000.L", "0", "0"]],
                "write_files": [{"path": "/etc/systemd/system/asb-vm.service", "permissions": "0644", "content": unit},
                                {"path": "/usr/local/bin/asb-vm-exit-marker", "permissions": "0755", "owner": "root:root", "content": EXIT_MARKER},
                                {"path": "/usr/local/libexec/asb-vm-diagnostics.py", "permissions": "0644", "owner": "root:root",
                                 "content": Path(__file__).with_name("fixtures").joinpath("discovery-vm/guest-diagnostics.py").read_text()}],
                "runcmd": [["/bin/sh", "-ec", "exec /usr/bin/python3 -I /usr/local/libexec/asb-vm-diagnostics.py bootstrap --sha256 " + digest(self.binary)]]}
            (guest / "user-data").write_text("#cloud-config\n" + json.dumps(cloud))
            self.run("cloud-localds", "--network-config=" + str(guest / "network-config"), str(guest / "seed.img"), str(guest / "user-data"), str(guest / "meta-data"))

    def start(self, role: str) -> None:
        self.stage, self.active_role = "start-guest", role
        guest = self.root / role
        for name in ("ready.json", "request.json", "response.json", "stopped.json", "stage.json", "service-exit.json"):
            (guest / "evidence" / name).unlink(missing_ok=True)
        index = ROLES.index(role)
        acceleration = self.guest_acceleration.get(role, self.acceleration)
        log = (guest / "serial.log").open("ab")
        self.logs.append(log)
        args = ["qemu-system-x86_64", "-machine", "q35,accel=" + acceleration,
                "-cpu", "host" if acceleration == "kvm" else "max", "-m", "768", "-smp", "1", "-nographic", "-monitor", "none", "-no-reboot",
                "-device", "virtio-rng-pci",
                "-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
                "-drive", f"if=pflash,format=raw,file={guest / 'vars.fd'}",
                "-drive", f"if=virtio,format=qcow2,cache=none,file={guest / 'disk.qcow2'}",
                "-drive", f"if=virtio,format=raw,readonly=on,file={guest / 'seed.img'}",
                "-netdev", f"tap,id=lab,ifname={self.taps[index]},script=no,downscript=no",
                "-device", f"virtio-net-pci,netdev=lab,mac=52:54:00:12:34:{index + 11:02x}",
                "-virtfs", f"local,path={guest / 'input'},mount_tag=asb-input,security_model=none,readonly=on",
                "-virtfs", f"local,path={guest / 'evidence'},mount_tag=asb-evidence,security_model=none"]
        self.processes[role] = subprocess.Popen(args, stdout=log, stderr=log)
        self.guest_acceleration[role] = acceleration

    def ready(self, role: str) -> None:
        self.stage, self.active_role = "wait-guest-ready", role
        until = min(self.deadline, time.monotonic() + 300)
        while time.monotonic() < until:
            process = self.processes[role]
            if process.poll() is not None:
                if self.guest_acceleration[role] == "kvm":
                    self.guest_acceleration[role] = "tcg"
                    self.start(role)
                    self.stage = "wait-guest-ready-tcg-fallback"
                    continue
                raise RuntimeError("QEMU guest exited before readiness")
            self.reject_stopped(role)
            path = self.root / role / "evidence/ready.json"
            if path.exists():
                record = read_json(path)
                if record.get("role") != role or not isinstance(record.get("pid"), int) or record["pid"] <= 0:
                    raise ValueError("guest readiness identity mismatch")
                installation = process_markers(self.root / role / "evidence", role).get("bootstrap", {})
                if installation.get("passed") is True:
                    if (installation.get("binary_sha256") != digest(self.binary) or installation.get("binary_static_elf") is not True
                            or any(installation.get(field) is not True for field in ("input_mount", "evidence_mount", "config_copied", "binary_copied"))):
                        raise ValueError("guest installation does not match the qualified static binary")
                    return
            time.sleep(0.2)
        raise TimeoutError("guest readiness exceeded 300 seconds")

    def reject_stopped(self, role: str, allow_success: bool = False) -> None:
        markers = process_markers(self.root / role / "evidence", role)
        if any(value.get("invalid") for value in markers.values()):
            raise ValueError("invalid guest process diagnostic")
        if "bootstrap" in markers and markers["bootstrap"]["category"] != "none":
            raise RuntimeError("guest bootstrap failed at " + markers["bootstrap"]["phase"] + " (" + markers["bootstrap"]["category"] + ")")
        if "stopped" in markers and not (allow_success and markers["stopped"]["passed"]):
            stopped = markers["stopped"]
            raise RuntimeError("guest service stopped at " + stopped["stage"] + " (" + stopped["category"] + ")")
        if "service-exit" in markers and not (allow_success and markers["service-exit"]["result"] == "success"):
            raise RuntimeError("guest service exited before completion (" + markers["service-exit"]["result"] + ", " + markers["service-exit"]["exec_error"] + ")")

    def command(self, role: str, action: str) -> dict:
        self.stage, self.active_role = "guest-command-" + action, role
        self.sequence += 1
        share = self.root / role / "evidence"
        write_json(share / "request.json", {"id": self.sequence, "action": action})
        until = min(self.deadline, time.monotonic() + 30)
        while time.monotonic() < until:
            path = share / "response.json"
            if path.exists():
                value = read_json(path)
                if value.get("id") == self.sequence:
                    if value.get("action") != action or value.get("role") != role or value.get("passed") is not True:
                        raise ValueError("guest qualification command did not pass")
                    return value
            if self.processes[role].poll() is not None:
                raise RuntimeError("guest exited during command")
            self.reject_stopped(role, allow_success=action == "stop")
            time.sleep(0.1)
        raise TimeoutError("guest command exceeded 30 seconds")

    def crash_restart(self, role: str) -> None:
        self.stage, self.active_role = "force-stop-guest-for-restart", role
        self.processes[role].kill()
        self.processes[role].wait(timeout=10)
        self.start(role)
        self.ready(role)

    def drain(self, role: str) -> dict:
        observation = self.command(role, "stop")
        self.stage, self.active_role = "wait-service-drain", role
        until = min(self.deadline, time.monotonic() + 15)
        path = self.root / role / "evidence/stopped.json"
        while time.monotonic() < until:
            if path.exists():
                stopped = read_json(path)
                if stopped.get("passed") is not True or stopped.get("role") != role or stopped.get("pid") != observation["pid"]:
                    raise ValueError("guest service did not drain successfully")
                return stopped
            time.sleep(0.1)
        raise TimeoutError("guest service drain exceeded 15 seconds")

    def diagnostics(self) -> dict:
        guests = {}
        # Read at most the final 64 KiB and emit only fixed boolean categories.
        # Never publish serial bytes, error strings, credentials or guest files.
        categories = {
            "mount_failure": (b"failed to mount", b"mount: /evidence", b"mount: /mnt/asb-input"),
            "unit_dependency_failure": (b"dependency failed",),
            "asb_service_failure": (b"asb-vm.service: main process exited", b"agent interaction:"),
            "kernel_panic": (b"kernel panic",),
            "kvm_failure": (b"failed to initialize kvm", b"could not access kvm"),
            "out_of_memory": (b"out of memory", b"out-of-memory"),
            "disk_full": (b"no space left on device",),
        }
        for role, process in self.processes.items():
            guest = self.root / role
            tail = b""
            try:
                with (guest / "serial.log").open("rb") as log:
                    log.seek(max(0, log.seek(0, 2) - 65536))
                    tail = log.read(65536).lower()
            except OSError:
                pass
            guests[role] = {"qemu_exit_status": process.poll(),
                            "acceleration": self.guest_acceleration.get(role),
                            "ready_file_present": (guest / "evidence/ready.json").is_file(),
                            "serial_categories": {name: any(token in tail for token in tokens) for name, tokens in categories.items()},
                            "bootstrap_failure_phases": sorted(phase for phase in BOOT_PHASES if b"asb_vm_bootstrap_failure:" + phase.encode() in tail),
                            "process_markers": process_markers(guest / "evidence", role)}
        return {"stage": self.stage, "role": self.active_role,
                "elapsed_seconds": round(time.monotonic() - self.started, 3), "guests": guests}

    def cleanup(self) -> bool:
        passed = True
        for process in self.processes.values():
            try:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
            except (OSError, subprocess.SubprocessError):
                passed = False
        for log in self.logs:
            try:
                log.close()
            except OSError:
                passed = False
        for device in self.taps + ([self.bridge] if self.bridge_created else []):
            try:
                completed = subprocess.run(["ip", "link", "delete", device], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                passed = completed.returncode == 0 and passed
            except (OSError, subprocess.SubprocessError):
                passed = False
        return passed


def qualify(lab: Lab) -> dict:
    image = lab.prepare_image()
    lab.prepare_guests()
    for role in ROLES:
        lab.start(role)
    for role in ROLES:
        lab.ready(role)
    initial = {role: lab.command(role, "status") for role in ROLES}
    if len({v["boot_id"] for v in initial.values()}) != 3 or len({v["machine_id_sha256"] for v in initial.values()}) != 3:
        raise ValueError("guest kernel or machine identities are not distinct")
    interaction = lab.command("agent-a", "task")
    task = interaction.get("task", {})
    if not task.get("passed") or not task.get("discovery", {}).get("dht_found") or task.get("without_task_proof_status") != 401 or task.get("authorized_status") != 200:
        raise ValueError("cross-VM authenticated task evidence is incomplete")
    if task.get("result", {}).get("pid") != initial["agent-b"]["pid"]:
        raise ValueError("task result does not identify the observed Agent B guest process")
    lab.command("relay", "gossip")
    baseline = {role: lab.command(role, "status") for role in ROLES}
    if any(v["records"] != 1 for v in baseline.values()):
        raise ValueError("cross-VM live population failed to converge")
    lab.stage, lab.active_role = "partition-guest-network", "agent-b"
    lab.run("ip", "link", "set", lab.taps[2], "down")
    withdrawn = lab.command("agent-b", "withdraw")
    stale = lab.command("agent-a", "status")
    if withdrawn["records"] != 0 or withdrawn["tombstones"] != 1 or stale["records"] != 1:
        raise ValueError("partitioned withdrawal did not preserve the intended states")
    lab.crash_restart("agent-b")
    recovered_b = lab.command("agent-b", "status")
    if recovered_b["boot_id"] == withdrawn["boot_id"] or recovered_b["machine_id_sha256"] != withdrawn["machine_id_sha256"] or recovered_b["records"] != 0 or recovered_b["tombstones"] != 1:
        raise ValueError("withdrawal did not survive guest restart on the same disk")
    lab.crash_restart("agent-a")
    recovered_a = lab.command("agent-a", "status")
    if recovered_a["boot_id"] == stale["boot_id"] or recovered_a["machine_id_sha256"] != stale["machine_id_sha256"] or recovered_a["records"] != 1:
        raise ValueError("partitioned live snapshot did not survive guest restart")
    lab.stage, lab.active_role = "restore-guest-network", "agent-b"
    lab.run("ip", "link", "set", lab.taps[2], "up")
    for role in ("agent-b", "relay", "agent-a"):
        lab.command(role, "gossip")
    final = {role: lab.command(role, "status") for role in ROLES}
    if any(v["records"] != 0 or v["tombstones"] != 1 for v in final.values()):
        raise ValueError("withdrawal did not converge after partition recovery")
    drained = {role: lab.drain(role) for role in ROLES}
    return {"schema": "asb.discovery-three-vm/v1", "passed": True, "physical_runner_count": 1,
            "guest_count": 3, "independent_physical_hosts": False, "organization_deployment_qualified": False,
            "network": "private bridge without gateway or NAT", "image": image,
            "binary_sha256": digest(lab.binary), "acceleration": lab.guest_acceleration,
            "initial": initial, "interaction": interaction, "before_partition": baseline,
            "withdrawn": withdrawn, "stale_during_partition": stale,
            "restarted": {"agent-a": recovered_a, "agent-b": recovered_b}, "final": final, "drained": drained,
            "checks": {"distinct_guest_kernels_and_disks": True, "authenticated_dht_and_task": True,
                       "network_partition_withdrawal": True, "guest_restart_persistence": True, "withdrawal_convergence": True,
                       "graceful_service_drain": True},
            "limits": ["Synthetic ephemeral credentials and sum task; no external provider.",
                       "Guest termination tests virtual-disk recovery, not physical power-loss durability.",
                       "One physical runner does not establish independent-host failure tolerance or organization SLOs."]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--execute-disposable-linux-lab", action="store_true")
    args = parser.parse_args()
    if not args.execute_disposable_linux_lab or platform.system() != "Linux" or os.geteuid() != 0:
        parser.error("requires explicit execution on a disposable Linux runner as root")
    if not args.binary.is_file() or not args.report.is_absolute() or args.report.exists():
        parser.error("provide an existing binary and a new absolute report path")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    def interrupted(_signum: int, _frame: object) -> None:
        raise InterruptedError("qualification interrupted; cleanup required")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    report = {"schema": "asb.discovery-three-vm/v1", "passed": False, "physical_runner_count": 1, "guest_count": 3}
    with tempfile.TemporaryDirectory(prefix="asb-three-vm-") as temporary:
        lab = Lab(Path(temporary), args.binary.resolve())
        try:
            report = qualify(lab)
        except (OSError, ValueError, RuntimeError, TimeoutError, KeyError, TypeError, subprocess.SubprocessError) as error:
            report["failure_type"] = type(error).__name__
            # Detailed process output is private and is never uploaded.
            report["failure"] = str(error) if not isinstance(error, subprocess.SubprocessError) else "bounded subprocess failed"
        finally:
            # Finish bounded cleanup even if the outer timeout sends another signal.
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            report["progress"] = lab.diagnostics()
            report["cleanup_passed"] = lab.cleanup()
            report["passed"] = report["passed"] and report["cleanup_passed"]
            write_json(args.report, report)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
