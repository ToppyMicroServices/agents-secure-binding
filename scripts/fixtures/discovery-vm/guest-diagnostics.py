#!/usr/bin/python3
"""Fixed installation and execution diagnostics for the disposable Linux lab."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import struct
import subprocess
import tempfile

BINARY = Path("/usr/local/bin/asb-interaction")
PATHS = ("/", "/usr", "/usr/local", "/usr/local/bin", str(BINARY))
PHASES = {"mounts", "directories", "config-copy", "binary-copy", "binary-verify", "unit-start", "complete"}
EXEC_ERRORS = {"none", "missing", "permission", "exec-format", "text-file-busy", "io", "no-memory", "other", "unavailable"}


def publish(name, value):
    target = Path("/evidence") / (name + ".json")
    temporary = target.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True) + "\n")
    temporary.chmod(0o644)
    temporary.replace(target)


def mounted(path, source, readonly):
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        before, after = line.split(" - ", 1)
        fields, filesystem = before.split(), after.split()
        if fields[4] == path:
            return (filesystem[:2] == ["9p", source]
                    and ("ro" if readonly else "rw") in fields[5].split(","))
    return False


def path_metadata():
    result = {}
    for path in PATHS:
        try:
            value = os.lstat(path)
            result[path] = {"exists": True, "mode": stat.S_IMODE(value.st_mode), "uid": value.st_uid,
                            "gid": value.st_gid, "symlink": stat.S_ISLNK(value.st_mode)}
        except FileNotFoundError:
            result[path] = {"exists": False}
    return result


def static_elf(payload):
    if len(payload) < 64 or payload[:7] != b"\x7fELF\x02\x01\x01":
        return False
    header = struct.unpack("<16sHHIQQQIHHHHHH", payload[:64])
    offset, stride, count = header[5], header[9], header[10]
    if header[2] != 62 or stride != 56 or not 1 <= count <= 128 or offset + count * stride > len(payload):
        return False
    types = [struct.unpack_from("<I", payload, offset + index * stride)[0] for index in range(count)]
    return 1 in types and 3 not in types


def journal_exec_error(raw):
    # Match only systemd's invocation failures for this fixed executable.
    # Payloads and all other journal text are discarded without being emitted.
    for line in raw.splitlines():
        if b"asb-interaction" not in line or not any(token in line for token in
                (b"Failed at step EXEC", b"Failed to execute", b"Failed to locate executable")):
            continue
        for reason, category in ((b"No such file or directory", "missing"), (b"Permission denied", "permission"),
                                 (b"Exec format error", "exec-format"), (b"Text file busy", "text-file-busy"),
                                 (b"Input/output error", "io"), (b"Cannot allocate memory", "no-memory")):
            if reason in line:
                return category
        return "other"
    return "unavailable"


def exit_marker():
    result = os.environ.get("SERVICE_RESULT", "other")
    if result not in {"success", "resources", "timeout", "exit-code", "signal", "core-dump", "watchdog", "start-limit-hit", "oom-kill", "exec-condition"}:
        result = "other"
    code = os.environ.get("EXIT_CODE", "unknown")
    if code not in {"exited", "killed", "dumped"}:
        code = "unknown"
    status = os.environ.get("EXIT_STATUS", "unknown")
    signals = {"HUP", "INT", "QUIT", "ILL", "ABRT", "BUS", "FPE", "KILL", "SEGV", "PIPE", "ALRM", "TERM"}
    if not (status in signals or (status.isascii() and status.isdecimal() and len(status) <= 3 and int(status) <= 255)):
        status = "unknown"
    category = "none" if result == "success" else "unavailable"
    if status == "203":
        try:
            with tempfile.TemporaryFile() as output:
                subprocess.run(["/usr/bin/journalctl", "--boot", "--unit=asb-vm.service", "--no-pager", "--output=cat", "-n", "20"],
                               stdout=output, stderr=subprocess.DEVNULL, check=True, timeout=5)
                output.seek(0)
                raw = output.read(65537)
            if len(raw) <= 65536:
                category = journal_exec_error(raw)
        except (OSError, subprocess.SubprocessError):
            pass
    publish("service-exit", {"result": result, "exit_code": code, "exit_status": status,
                             "exec_error": category, "paths": path_metadata()})


def bootstrap(expected):
    record = {"phase": "mounts", "passed": False, "category": "none", "input_mount": False, "evidence_mount": False,
              "config_copied": False, "binary_copied": False, "binary_sha256": "", "binary_static_elf": False, "paths": {}}

    def phase(name):
        record["phase"] = name
        publish("bootstrap", record)

    def run(*arguments):
        subprocess.run(arguments, check=True, timeout=30, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        record["input_mount"] = mounted("/mnt/asb-input", "asb-input", True)
        record["evidence_mount"] = mounted("/evidence", "asb-evidence", False)
        if not record["input_mount"] or not record["evidence_mount"]:
            raise ValueError("mount-verification")
        phase("directories")
        run("/usr/bin/install", "-d", "-m", "0700", "-o", "asb", "-g", "asb", "/var/lib/asb-vm", "/etc/asb-vm")
        phase("config-copy")
        run("/usr/bin/install", "-m", "0600", "-o", "asb", "-g", "asb", "/mnt/asb-input/config.json", "/etc/asb-vm/config.json")
        config = os.stat("/etc/asb-vm/config.json")
        if stat.S_IMODE(config.st_mode) != 0o600 or config.st_uid != pwd.getpwnam("asb").pw_uid:
            raise ValueError("config-permissions")
        record["config_copied"] = True
        phase("binary-copy")
        run("/usr/bin/install", "-m", "0755", "/mnt/asb-input/asb-interaction", str(BINARY))
        record["binary_copied"] = True
        phase("binary-verify")
        with BINARY.open("rb") as stream:
            payload = stream.read(128 * 1024 * 1024 + 1)
        record["binary_sha256"] = hashlib.sha256(payload).hexdigest()
        record["binary_static_elf"] = static_elf(payload)
        record["paths"] = path_metadata()
        metadata = record["paths"][str(BINARY)]
        if (len(payload) > 128 * 1024 * 1024 or record["binary_sha256"] != expected or not record["binary_static_elf"]
                or metadata != {"exists": True, "mode": 0o755, "uid": 0, "gid": 0, "symlink": False}):
            raise ValueError("binary-verification")
        phase("unit-start")
        run("/usr/bin/systemctl", "daemon-reload")
        run("/usr/bin/systemctl", "enable", "--now", "asb-vm.service")
        record["passed"] = True
        phase("complete")
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        if isinstance(error, PermissionError):
            record["category"] = "permission"
        elif isinstance(error, FileNotFoundError):
            record["category"] = "missing"
        elif isinstance(error, subprocess.TimeoutExpired):
            record["category"] = "timeout"
        elif isinstance(error, subprocess.SubprocessError):
            record["category"] = "command-failed"
        else:
            record["category"] = "verification-failed"
        record["paths"] = path_metadata()
        if record["evidence_mount"]:
            publish("bootstrap", record)
        print("ASB_VM_BOOTSTRAP_FAILURE:" + record["phase"], flush=True)
        return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("bootstrap", "exit"))
    parser.add_argument("--sha256", default="")
    args = parser.parse_args()
    if args.mode == "bootstrap":
        if len(args.sha256) != 64 or any(char not in "0123456789abcdef" for char in args.sha256):
            parser.error("requires the fixed binary digest")
        raise SystemExit(bootstrap(args.sha256))
    exit_marker()
