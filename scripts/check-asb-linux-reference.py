#!/usr/bin/env python3
"""Bind existing offline gates to one named GitHub Linux reference environment."""

import argparse
import hashlib
import json
import os
import platform
import re
import selectors
import signal
import stat
import subprocess
import time
from pathlib import Path


REPOSITORY = "ToppyMicroServices/agents-secure-binding"
MODULE = "github.com/ToppyMicroServices/agents-secure-binding/v2/"
RELAY_TESTS = {
    MODULE + "pkg/humanrelay": [
        "TestFileRelayCrashAfterProviderEffectRecoversWithoutRedispatch",
        "TestFileRelayConcurrentProcessesReserveOneProviderAttempt",
        "TestFileRelayFailedDispatchCheckpointNeverCallsProvider",
        "TestFileRelayLockWaitHonorsCancellation",
    ],
    MODULE + "pkg/taskcoord/sqlitestore": [
        "TestSQLiteAuthorityAndDurableRelayRestartRevocation",
        "TestSQLiteAuthorityAndRelayUnknownReconciliation",
        "TestRelayGrantGuardProcessCrash",
        "TestOutboxLeaseFencingBackupAndRollback",
        "TestOutboxQuarantinePreservesEvidenceAndRestoresOnlyAuthorizedHistory",
        "TestProcessCrashAtomicHumanOutcome",
        "TestExpiredLeaseAndUnknownOutcomeRequireReconciliation",
    ],
}
OFFLINE_TESTS = {
    "qa-product.txt": [
        "TestOfflineProductActiveStopAndCrash", "TestOfflineProductResourceQualification",
        "TestOfflineProductMaximumConfiguration", "TestOfflineProductRestoreSignal",
        "TestOfflineProductIdentityRotation",
    ],
    "qa-systemd.txt": ["TestOfflineSystemdLifecycle"],
    "qa-boot.txt": ["TestOfflineSystemdBoot"],
    "qa-capacity.txt": ["TestSQLiteHistoryMonitoringAndBackupQualification"],
    "qa-full.txt": ["TestSQLiteFilesystemFullRecovery"],
}
CORE_TESTS = {
    MODULE + "pkg/leastprivilege": [
        "TestSQLiteMonitoringDoesNotWaitForWriter", "TestSQLiteMonitoringRejectsSealedAndChangedNamespace",
        "TestSQLiteLockCancellationRecovers", "TestSQLiteBackupRecoveryPreservesPublishedAndActiveFiles",
        "TestSQLiteBackupCrashBoundaries", "TestSQLiteCopyCancellationDoesNotPublishOutput",
        "TestSQLiteKernelWriteFailureRecovery", "TestSQLiteReaderReleasesWALAndKeepsHistory",
    ],
    MODULE + "internal/s3product": [
        "TestConnectionLimitBoundsAcceptAndRecovers", "TestConnectionCyclesReleaseDescriptorsAndGoroutines",
        "TestDiagnosticsAreBoundedAndRedactUntrustedText", "TestJournalFailureIsDiagnosableWithoutChangingUnknown",
    ],
    MODULE + "pkg/leastprivilege/awsiam": [
        "TestProviderDiagnosticStagesDiscardPrivateText", "TestCLICancellationStopsChildGroupAndRemovesIdentity",
    ],
}
LIMITATIONS = {
    "live_aws_tested": False,
    "live_delivery_provider_tested": False,
    "relay_systemd_service_tested": False,
    "coordinated_relay_backup_restore_tested": False,
    "organization_deployment_qualified": False,
    "physical_power_loss_qualified": False,
    "long_term_leak_absence_proven": False,
}


class EvidenceError(ValueError):
    """Only fixed, public diagnostic text may be supplied here."""


def require(condition, reason):
    if not condition:
        raise EvidenceError(reason)


def bounded_command(command, timeout=30, limit=4 << 20):
    """Bound output and time, and reap the child process group on every exit."""
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          start_new_session=True) as child:
        output = bytearray()
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                deadline = time.monotonic() + timeout
                while selector.get_map():
                    require(time.monotonic() < deadline, "command timed out")
                    for key, _ in selector.select(min(0.2, max(0, deadline - time.monotonic()))):
                        block = os.read(key.fd, 65536)
                        if not block:
                            selector.unregister(key.fileobj)
                        else:
                            output.extend(block)
                            require(len(output) <= limit, "command output limit exceeded")
                require(child.wait(timeout=max(0.1, deadline - time.monotonic())) == 0,
                        "required command failed")
        finally:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=10)
        return bytes(output)


def regular_bytes(path, limit=4 << 20):
    require(stat.S_ISREG(path.lstat().st_mode) and path.stat().st_size <= limit,
            "evidence must be a bounded regular file")
    data = path.read_bytes()
    require(len(data) <= limit, "evidence size changed")
    return data


def digest(path):
    require(stat.S_ISREG(path.lstat().st_mode) and path.stat().st_size <= 128 << 20,
            "hashed evidence must be a bounded regular file")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def named_environment(env, system, machine, release):
    required = {
        "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64", "ImageOS": "ubuntu24",
        "GITHUB_REPOSITORY": REPOSITORY, "GITHUB_JOB": "conformance",
    }
    require(all(env.get(key) == value for key, value in required.items()) and
            system == "Linux" and machine == "x86_64" and
            release.get("ID") == "ubuntu" and release.get("VERSION_ID") == "24.04",
            "outside named GitHub Ubuntu 24.04 reference environment")
    patterns = {
        "GITHUB_SHA": r"[0-9a-f]{40}", "GITHUB_RUN_ID": r"[1-9][0-9]{0,19}",
        "GITHUB_RUN_ATTEMPT": r"[1-9][0-9]{0,9}",
        "ImageVersion": r"[0-9][0-9A-Za-z._-]{0,79}",
        "GITHUB_WORKFLOW_REF": re.escape(REPOSITORY + "/.github/workflows/aws-s3-linux.yaml@") + r"refs/[A-Za-z0-9._/-]{1,200}",
    }
    require(all(re.fullmatch(pattern, env.get(key, "")) for key, pattern in patterns.items()),
            "missing or invalid reference run identity")
    return {key: env[key] for key in (*required, *patterns)}


def environment_evidence():
    facts = named_environment(os.environ, platform.system(), platform.machine(), platform.freedesktop_os_release())
    commit = bounded_command(["git", "rev-parse", "HEAD"]).decode().strip()
    require(commit == facts["GITHUB_SHA"], "run and checked-out source differ")
    kernel = platform.release()
    require(re.fullmatch(r"[A-Za-z0-9._+-]{1,120}", kernel), "invalid kernel release")
    systemd = bounded_command(["systemctl", "--version"]).decode().splitlines()[0]
    require(re.fullmatch(r"systemd [0-9]{1,5}(?: \([A-Za-z0-9 .:~+_-]{1,160}\))?", systemd),
            "invalid systemd version")
    filesystems = {}
    for label, path in {"checkout": ".", "service_state": "/var/lib/asb-s3"}.items():
        fs = bounded_command(["findmnt", "--noheadings", "--output", "FSTYPE", "--target", path]).decode().strip()
        require(re.fullmatch(r"[a-zA-Z0-9._-]{1,32}", fs), "invalid filesystem type")
        filesystems[label] = fs
    return {"profile": "github-linux-reference", "runner": facts, "kernel": kernel,
            "systemd": systemd, "filesystems": filesystems,
            "environment_identity_is_remote_attestation": False, **LIMITATIONS}


def validate_offline(directory, commit, installed):
    report = json.loads(regular_bytes(directory / "qa-result.json"))
    require(isinstance(report, dict) and report.get("schema") == "asb.s3-operational-qa/v1" and
            report.get("status") == "passed" and report.get("source_commit") == commit,
            "offline report did not pass for this source")
    checks = report.get("checks")
    required_checks = {"workflow_prior_steps", "source_commit", "binary_sha256", "core:no_failure"}
    required_checks.update(name + ":no_failure" for name in OFFLINE_TESTS)
    required_checks.update(test for tests in OFFLINE_TESTS.values() for test in tests)
    required_checks.update(test for tests in CORE_TESTS.values() for test in tests)
    require(isinstance(checks, dict) and required_checks <= checks.keys() and
            all(value is True for value in checks.values()),
            "incomplete offline checks")
    for key in ("real_aws", "container_boot_is_physical_reboot", "physical_power_loss_qualified",
                "organization_deployment_qualified", "long_term_leak_absence_proven"):
        require(report.get(key) is False, "offline scope differs")
    files = report.get("files_sha256")
    required = {*OFFLINE_TESTS, "tests.jsonl", "asb-s3", "source-commit.txt", "binary.sha256"}
    require(isinstance(files, dict) and required <= set(files), "missing offline artifacts")
    for name, expected in files.items():
        require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9._-]{1,100}", name) and
                name not in {".", ".."} and isinstance(expected, str) and
                re.fullmatch(r"[0-9a-f]{64}", expected), "invalid artifact manifest")
        require(digest(directory / name) == expected, "offline artifact hash mismatch")
    require(regular_bytes(directory / "source-commit.txt").decode().strip() == commit,
            "offline source differs")
    passed_go_tests(regular_bytes(directory / "tests.jsonl"), CORE_TESTS)
    binary = digest(directory / "asb-s3")
    require(digest(installed) == binary and
            regular_bytes(directory / "binary.sha256").decode().split()[0] == binary,
            "installed executable differs")
    for name, tests in OFFLINE_TESTS.items():
        raw = regular_bytes(directory / name).decode()
        require("--- FAIL:" not in raw and "panic:" not in raw, "offline test failure")
        for test in tests:
            require(bool(re.search(r"^--- PASS: " + re.escape(test) + r" \(", raw, re.M)) and
                    not re.search(r"^--- SKIP: " + re.escape(test) + r" \(", raw, re.M),
                    "required offline test did not run")
    runtime = re.findall(
        r"systemd_runtime_identity main_pid=([1-9][0-9]*) uid=([1-9][0-9]*) "
        r"no_new_privileges=true effective_capabilities_zero=true executable_sha256=([0-9a-f]{64})",
        regular_bytes(directory / "qa-systemd.txt").decode())
    require(len(runtime) == 1 and runtime[0][2] == binary, "live service identity missing or differs")
    return {"scope": "offline-s3-systemd", "source_commit": commit, "binary_sha256": binary,
            "offline_report_sha256": digest(directory / "qa-result.json"),
            "live_main_pid": int(runtime[0][0]), "service_uid": int(runtime[0][1]),
            "no_new_privileges": True, "effective_capabilities_zero": True,
            "installed_path": "/usr/local/bin/asb-s3", **LIMITATIONS}


def passed_go_tests(raw, expected):
    events = [json.loads(line) for line in raw.splitlines()]
    require(events and all(isinstance(event, dict) and event.get("Action") != "fail" for event in events),
            "Go tests failed")
    passed = {(event.get("Package"), event.get("Test")) for event in events if event.get("Action") == "pass"}
    skipped = {(event.get("Package"), event.get("Test")) for event in events if event.get("Action") == "skip"}
    required = {(package, test) for package, tests in expected.items() for test in tests}
    require(required <= passed and not required & skipped and
            all((package, None) in passed for package in expected),
            "required Go test or package did not pass")
    return required


def relay_evidence(raw):
    required = passed_go_tests(raw, RELAY_TESTS)
    return {"scope": "durable-relay-library-with-synthetic-provider",
            "tests": [{"package": package, "test": test, "status": "passed"} for package, test in sorted(required)],
            "go_json_sha256": hashlib.sha256(raw).hexdigest(), **LIMITATIONS}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("check", choices=("environment", "offline-s3", "relay-library"))
    args = parser.parse_args()
    try:
        environment = environment_evidence()  # Every check fails outside the named environment.
        if args.check == "environment":
            result = environment
        elif args.check == "offline-s3":
            directory = Path(os.environ.get("ASB_REFERENCE_S3_EVIDENCE", ""))
            require(directory.is_absolute(), "absolute offline evidence path required")
            result = validate_offline(directory, environment["runner"]["GITHUB_SHA"], Path("/usr/local/bin/asb-s3"))
        else:
            pattern = "^(" + "|".join(test for tests in RELAY_TESTS.values() for test in tests) + ")$"
            raw = bounded_command(["go", "test", "-race", "-count=1", "-timeout=6m", "-json", "-run", pattern,
                                   "./pkg/humanrelay", "./pkg/taskcoord/sqlitestore"], timeout=420)
            result = relay_evidence(raw)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError) as error:
        # Avoid exposing fixture paths, child output, or external error text.
        reason = str(error) if isinstance(error, EvidenceError) else "reference evidence unavailable or invalid"
        print(json.dumps({"check": args.check, "status": "failed_or_incomplete", "reason": reason}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
