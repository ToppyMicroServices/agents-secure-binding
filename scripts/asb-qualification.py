#!/usr/bin/env python3
"""Run and verify bounded ASB environment-qualification bundles."""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path


REPORT_VERSION = 1
MAX_LOG_BYTES = 1_048_576
MAX_PROFILE_BYTES = 1_048_576
MAX_BUNDLE_FILE_BYTES = 4 * 1_048_576
MAX_BUNDLE_BYTES = 128 * 1_048_576
MAX_CHECKS = 64
SIGNATURE_NAME = "SHA256SUMS.asc"
CHECKSUMS_NAME = "SHA256SUMS"
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(rb"(?i)(authorization\s*:\s*bearer\s+)[^\s]+"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
)


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def write_private_atomic(path: Path, data: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def load_profile_bytes(data: bytes) -> dict:
    profile = json.loads(data.decode("utf-8"))
    required = {"profileVersion", "id", "claim", "targetOs", "checks"}
    if set(profile) != required or profile["profileVersion"] != 1:
        raise ValueError("profile must contain only the version-1 fields")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,63}", profile["id"]):
        raise ValueError("invalid profile id")
    if not isinstance(profile["claim"], str) or not profile["claim"].strip():
        raise ValueError("profile claim must be non-empty")
    if not isinstance(profile["targetOs"], list) or not profile["targetOs"] or not all(isinstance(name, str) and name for name in profile["targetOs"]):
        raise ValueError("targetOs must be a non-empty list")
    if not isinstance(profile["checks"], list) or not profile["checks"] or len(profile["checks"]) > MAX_CHECKS:
        raise ValueError("checks must be a non-empty list")
    seen = set()
    for check in profile["checks"]:
        if set(check) - {"id", "required", "command", "timeoutSeconds", "environment"}:
            raise ValueError("check contains unknown fields")
        check_id = check.get("id")
        if not isinstance(check_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,63}", check_id) or check_id in seen:
            raise ValueError("invalid or duplicate check id")
        seen.add(check_id)
        command = check.get("command")
        if not isinstance(command, list) or not command or not all(isinstance(item, str) and item for item in command):
            raise ValueError(f"check {check_id} must use a non-empty argument array")
        timeout = check.get("timeoutSeconds")
        if not isinstance(timeout, int) or timeout < 1 or timeout > 3600:
            raise ValueError(f"check {check_id} has an invalid timeout")
        if not isinstance(check.get("required"), bool):
            raise ValueError(f"check {check_id} must declare required")
        environment = check.get("environment", {})
        if not isinstance(environment, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in environment.items()):
            raise ValueError(f"check {check_id} has an invalid environment")
    if not any(check["required"] for check in profile["checks"]):
        raise ValueError("profile must contain at least one required check")
    return profile


def git_value(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args], cwd=root, check=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, timeout=30,
    )
    return completed.stdout.strip()


def git_bytes(root: Path, *args: str) -> bytes:
    completed = subprocess.run(
        ["git", *args], cwd=root, check=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=30,
    )
    return completed.stdout


def committed_profile(root: Path, profile_path: Path, commit: str) -> tuple[dict, str]:
    try:
        relative = profile_path.relative_to(root).as_posix()
    except ValueError as exc:
        raise ValueError("profile must be inside the source root") from exc
    git_value(root, "ls-files", "--error-unmatch", "--", relative)
    committed = git_bytes(root, "show", f"{commit}:{relative}")
    if len(committed) > MAX_PROFILE_BYTES:
        raise ValueError("profile is too large")
    if profile_path.is_symlink() or not profile_path.is_file() or profile_path.read_bytes() != committed:
        raise ValueError("profile must be a regular tracked file identical to HEAD")
    return load_profile_bytes(committed), relative


@contextlib.contextmanager
def committed_worktree(root: Path, commit: str):
    parent = Path(tempfile.mkdtemp(prefix="asb-qualification-source-"))
    os.chmod(parent, 0o700)
    snapshot = parent / "source"
    git_prefix = ["git", "-c", f"core.hooksPath={os.devnull}"]
    added = False
    try:
        subprocess.run(
            [*git_prefix, "worktree", "add", "--detach", "--force", str(snapshot), commit],
            cwd=root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120,
        )
        added = True
        yield snapshot
    finally:
        if added:
            subprocess.run(
                [*git_prefix, "worktree", "remove", "--force", str(snapshot)],
                cwd=root, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120,
            )
        shutil.rmtree(parent, ignore_errors=True)


def redact_log(data: bytes) -> tuple[bytes, bool]:
    found = False
    for pattern in SECRET_PATTERNS:
        if pattern.search(data):
            found = True
            data = pattern.sub(b"[REDACTED_SECRET]", data)
    if len(data) > MAX_LOG_BYTES:
        data = data[:MAX_LOG_BYTES] + b"\n[TRUNCATED]\n"
    return data, found


def run_check(root: Path, output: Path, check: dict) -> dict:
    started = time.monotonic()
    environment = os.environ.copy()
    environment.update(check.get("environment", {}))
    status = "failed"
    return_code = None
    reason = ""
    stdout = b""
    stderr = b""
    executable = shutil.which(check["command"][0], path=environment.get("PATH"))
    if executable is None:
        status = "unavailable"
        reason = f"executable not found: {check['command'][0]}"
    else:
        try:
            completed = subprocess.run(
                check["command"], cwd=root, env=environment,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=check["timeoutSeconds"], check=False,
            )
            return_code = completed.returncode
            stdout, stderr = completed.stdout, completed.stderr
            status = "passed" if completed.returncode == 0 else "failed"
            if completed.returncode != 0:
                reason = f"exit status {completed.returncode}"
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or b""
            stderr = exc.stderr or b""
            status = "failed"
            reason = f"timeout after {check['timeoutSeconds']} seconds"
    stdout, stdout_secret = redact_log(stdout)
    stderr, stderr_secret = redact_log(stderr)
    secret_detected = stdout_secret or stderr_secret
    if secret_detected:
        status = "failed"
        reason = "secret-like material was redacted from check output"
    stdout_path = output / f"{check['id']}.stdout.log"
    stderr_path = output / f"{check['id']}.stderr.log"
    stdout_path.write_bytes(stdout)
    stderr_path.write_bytes(stderr)
    os.chmod(stdout_path, 0o600)
    os.chmod(stderr_path, 0o600)
    return {
        "id": check["id"],
        "required": check["required"],
        "command": check["command"],
        "timeoutSeconds": check["timeoutSeconds"],
        "status": status,
        "returnCode": return_code,
        "reason": reason,
        "durationMilliseconds": round((time.monotonic() - started) * 1000),
        "secretMaterialDetected": secret_detected,
        "stdout": stdout_path.name,
        "stderr": stderr_path.name,
    }


def write_checksums(output: Path) -> bytes:
    targets = sorted(
        path for path in output.iterdir()
        if path.is_file() and not path.is_symlink() and path.name not in {CHECKSUMS_NAME, SIGNATURE_NAME}
    )
    lines = [f"{sha256_file(path).removeprefix('sha256:')}  {path.name}\n" for path in targets]
    data = "".join(lines).encode("utf-8")
    write_private_atomic(output / CHECKSUMS_NAME, data)
    return data


def run_bundle(args: argparse.Namespace) -> int:
    started_at = dt.datetime.now(dt.timezone.utc).isoformat()
    root = args.source_root.resolve()
    profile_path = args.profile.resolve()
    output = args.output.resolve()
    if output == root or root in output.parents:
        raise ValueError("output directory must be outside the source root")
    commit = git_value(root, "rev-parse", "HEAD")
    tree = git_value(root, "rev-parse", "HEAD^{tree}")
    if git_value(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("source tree must be clean before qualification checks run")
    profile, profile_relative = committed_profile(root, profile_path, commit)
    with committed_worktree(root, commit) as execution_root:
        if output.exists() and any(output.iterdir()):
            raise ValueError("output directory must be absent or empty")
        output.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(output, 0o700)
        profile_copy = output / "profile.json"
        write_private_atomic(profile_copy, canonical_json(profile))

        target_os = platform.system().lower()
        os_allowed = target_os in {name.lower() for name in profile["targetOs"]}
        results = []
        if os_allowed:
            for check in profile["checks"]:
                results.append(run_check(execution_root, output, check))
        else:
            for check in profile["checks"]:
                results.append({
                    "id": check["id"], "required": check["required"],
                    "command": check["command"], "timeoutSeconds": check["timeoutSeconds"],
                    "status": "unavailable", "returnCode": None,
                    "reason": f"target OS {target_os} is outside {profile['targetOs']}",
                    "durationMilliseconds": 0, "secretMaterialDetected": False,
                    "stdout": None, "stderr": None,
                })
        final_commit = git_value(execution_root, "rev-parse", "HEAD")
        final_tree = git_value(execution_root, "rev-parse", "HEAD^{tree}")
        dirty = bool(git_value(execution_root, "status", "--porcelain=v1", "--untracked-files=all"))
        stable_source = not dirty and final_commit == commit and final_tree == tree
    required_pass = all(result["status"] == "passed" for result in results if result["required"])
    passed = stable_source and os_allowed and required_pass
    report = {
        "documentType": "asb.qualification-report",
        "version": REPORT_VERSION,
        "profile": {
            "id": profile["id"], "claim": profile["claim"],
            "path": profile_relative, "sha256": sha256_file(profile_copy),
        },
        "source": {"commit": commit, "tree": tree, "dirty": dirty, "stable": stable_source},
        "environment": {
            "os": target_os,
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "startedAt": started_at,
        "status": "passed" if passed else "failed",
        "qualificationClaim": False,
        "checks": results,
        "limitations": [
            "The result applies only to the recorded profile, source revision, and target environment.",
            "A passing bundle is not a proof that the software has no vulnerabilities.",
        ],
    }
    report_path = output / "qa-report.json"
    write_private_atomic(report_path, canonical_json(report))
    write_checksums(output)
    print(json.dumps({"event": "qualification_complete", "status": report["status"], "report": str(report_path)}, separators=(",", ":")))
    return 0 if passed else 1


def read_regular_file_once(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("bundle entries must be regular files")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            data = stream.read(MAX_BUNDLE_FILE_BYTES + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(data) > MAX_BUNDLE_FILE_BYTES:
        raise ValueError(f"bundle file is too large: {path.name}")
    return data


def read_bundle(bundle: Path) -> tuple[dict, dict[str, str], bytes | None, bytes]:
    entries = list(bundle.iterdir())
    if len(entries) > 2 * MAX_CHECKS + 4:
        raise ValueError("bundle contains too many files")
    if any(path.is_symlink() or not path.is_file() for path in entries):
        raise ValueError("bundle entries must be regular files")
    files = {path.name: read_regular_file_once(path) for path in entries}
    if sum(len(data) for data in files.values()) > MAX_BUNDLE_BYTES:
        raise ValueError("bundle is too large")
    if "qa-report.json" not in files or CHECKSUMS_NAME not in files:
        raise ValueError("bundle is missing qa-report.json or SHA256SUMS")
    sums_data = files[CHECKSUMS_NAME]
    signature_data = files.get(SIGNATURE_NAME)
    expected = {}
    for line in sums_data.decode("utf-8").splitlines():
        digest, separator, name = line.partition("  ")
        if not separator or not re.fullmatch(r"[0-9a-f]{64}", digest) or Path(name).name != name or name in expected:
            raise ValueError("invalid SHA256SUMS entry")
        expected[name] = digest
    actual_names = set(files) - {CHECKSUMS_NAME, SIGNATURE_NAME}
    if actual_names != set(expected):
        raise ValueError("bundle file set does not match SHA256SUMS")
    for name, digest in expected.items():
        if sha256_bytes(files[name]).removeprefix("sha256:") != digest:
            raise ValueError(f"digest mismatch: {name}")
    report = json.loads(files["qa-report.json"].decode("utf-8"))
    if report.get("documentType") != "asb.qualification-report" or report.get("version") != REPORT_VERSION or report.get("status") not in {"passed", "failed"} or not isinstance(report.get("qualificationClaim"), bool):
        raise ValueError("invalid qualification report")
    profile = report.get("profile")
    source = report.get("source")
    checks = report.get("checks")
    if not isinstance(profile, dict) or not isinstance(source, dict) or not isinstance(checks, list):
        raise ValueError("invalid qualification report structure")
    if "profile.json" not in files or profile.get("sha256") != sha256_bytes(files["profile.json"]):
        raise ValueError("profile digest mismatch")
    for check in checks:
        if not isinstance(check, dict) or not isinstance(check.get("required"), bool):
            raise ValueError("invalid qualification check")
        for field in ("stdout", "stderr"):
            name = check.get(field)
            if name is not None and name not in expected:
                raise ValueError("check references an unbound log")
        if check.get("required") and report["status"] == "passed" and check.get("status") != "passed":
            raise ValueError("passing report contains an incomplete required check")
        if check.get("secretMaterialDetected") and report["status"] == "passed":
            raise ValueError("passing report contains detected secret material")
    if report["status"] == "failed" and report["qualificationClaim"]:
        raise ValueError("failed report cannot contain a qualification claim")
    if report["status"] == "passed" and (source.get("dirty") is not False or source.get("stable") is not True):
        raise ValueError("passing report must bind a clean, stable source")
    return report, expected, signature_data, sums_data


def normalize_fingerprint(value: str) -> str:
    fingerprint = re.sub(r"\s+", "", value).upper()
    if not re.fullmatch(r"(?:[0-9A-F]{40}|[0-9A-F]{64})", fingerprint):
        raise ValueError("trusted signer must be a full OpenPGP fingerprint")
    return fingerprint


def gpg_executable() -> str:
    executable = shutil.which("gpg")
    if executable is None:
        raise ValueError("gpg executable not found")
    return executable


def verify_signature(signature_data: bytes, sums_data: bytes, trusted_signer: str) -> str:
    fingerprint = normalize_fingerprint(trusted_signer)
    with tempfile.TemporaryDirectory(prefix="asb-qualification-signature-") as temporary:
        signature_path = Path(temporary) / SIGNATURE_NAME
        signature_path.write_bytes(signature_data)
        os.chmod(signature_path, 0o600)
        completed = subprocess.run(
            [gpg_executable(), "--batch", "--no-auto-key-retrieve", "--status-fd", "1", "--verify",
             str(signature_path), "-"], input=sums_data,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False,
        )
    if completed.returncode != 0:
        raise ValueError("qualification signature verification failed")
    valid_fingerprints = set()
    for line in completed.stdout.decode("utf-8", errors="replace").splitlines():
        if line.startswith("[GNUPG:] VALIDSIG "):
            valid_fingerprints.update(
                token.upper() for token in line.split()
                if re.fullmatch(r"(?:[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})", token)
            )
    if fingerprint not in valid_fingerprints:
        raise ValueError("qualification signature is not from the trusted signer")
    return fingerprint


def sign_bundle(args: argparse.Namespace) -> int:
    bundle = args.bundle.resolve()
    report, _, signature_data, _ = read_bundle(bundle)
    if signature_data is not None or report["qualificationClaim"]:
        raise ValueError("bundle is already claimed or signed")
    source = report["source"]
    if report["status"] != "passed" or source.get("dirty") is not False or source.get("stable") is not True:
        raise ValueError("only a clean, stable passing bundle can be signed")
    if any(check.get("required") and check.get("status") != "passed" for check in report["checks"]):
        raise ValueError("required qualification checks are incomplete")
    if any(check.get("secretMaterialDetected") for check in report["checks"]):
        raise ValueError("bundle records detected secret material")

    fingerprint = normalize_fingerprint(args.signing_key)
    report_path = bundle / "qa-report.json"
    sums_path = bundle / CHECKSUMS_NAME
    old_report = report_path.read_bytes()
    old_sums = sums_path.read_bytes()
    signature_path = bundle / SIGNATURE_NAME
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{SIGNATURE_NAME}.", dir=bundle)
    os.close(descriptor)
    temporary_signature = Path(temporary_name)
    temporary_signature.unlink()
    try:
        report["qualificationClaim"] = True
        write_private_atomic(report_path, canonical_json(report))
        signed_sums = write_checksums(bundle)
        completed = subprocess.run(
            [gpg_executable(), "--batch", "--no-auto-key-retrieve", "--local-user", fingerprint,
             "--armor", "--detach-sign", "--output", str(temporary_signature)],
            input=signed_sums, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False,
        )
        if completed.returncode != 0:
            raise ValueError("qualification signing failed")
        os.chmod(temporary_signature, 0o600)
        os.replace(temporary_signature, signature_path)
        final_report, _, final_signature, final_sums = read_bundle(bundle)
        if not final_report["qualificationClaim"] or final_signature is None:
            raise ValueError("signed qualification bundle is incomplete")
        verify_signature(final_signature, final_sums, fingerprint)
    except Exception:
        signature_path.unlink(missing_ok=True)
        temporary_signature.unlink(missing_ok=True)
        write_private_atomic(report_path, old_report)
        write_private_atomic(sums_path, old_sums)
        raise
    print(json.dumps({"event": "qualification_bundle_signed", "signer": fingerprint, "report": str(report_path)}, separators=(",", ":")))
    return 0


def verify_bundle(args: argparse.Namespace) -> int:
    bundle = args.bundle.resolve()
    report, _, signature_data, sums_data = read_bundle(bundle)
    verified_signer = None
    if report["qualificationClaim"]:
        if report["status"] != "passed" or signature_data is None or not args.trusted_signer:
            raise ValueError("positive qualification claim requires a signature and trusted signer")
        verified_signer = verify_signature(signature_data, sums_data, args.trusted_signer)
    elif signature_data is not None:
        raise ValueError("non-claim bundle must not contain a qualification signature")
    print(json.dumps({
        "event": "qualification_bundle_verified", "status": report["status"],
        "qualificationClaim": report["qualificationClaim"], "signer": verified_signer,
        "report": str(bundle / "qa-report.json"),
    }, separators=(",", ":")))
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("run", help="run a qualification profile")
    run.add_argument("--profile", type=Path, required=True)
    run.add_argument("--source-root", type=Path, default=Path.cwd())
    run.add_argument("--output", type=Path, required=True)
    run.set_defaults(func=run_bundle)
    sign = subparsers.add_parser("sign", help="sign a clean passing qualification bundle")
    sign.add_argument("--bundle", type=Path, required=True)
    sign.add_argument("--signing-key", required=True, help="full OpenPGP primary or signing-key fingerprint")
    sign.set_defaults(func=sign_bundle)
    verify = subparsers.add_parser("verify", help="verify a qualification bundle")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--trusted-signer", help="full trusted OpenPGP primary or signing-key fingerprint")
    verify.set_defaults(func=verify_bundle)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        return args.func(args)
    except (OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": str(exc)}, separators=(",", ":")), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
