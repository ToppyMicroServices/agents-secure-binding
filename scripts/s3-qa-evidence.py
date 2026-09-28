#!/usr/bin/env python3
"""Summarize actual offline Linux QA evidence; missing/skipped gates fail closed."""

import hashlib
import json
import os
import re
import sys
from pathlib import Path


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    directory = Path(sys.argv[1] if len(sys.argv) > 1 else "evidence")
    required = {
        "qa-product.txt": [
            "TestOfflineProductActiveStopAndCrash",
            "TestOfflineProductResourceQualification",
            "TestOfflineProductMaximumConfiguration",
            "TestOfflineProductRestoreSignal",
            "TestOfflineProductIdentityRotation",
        ],
        "qa-systemd.txt": ["TestOfflineSystemdLifecycle"],
        "qa-boot.txt": ["TestOfflineSystemdBoot"],
        "qa-capacity.txt": ["TestSQLiteHistoryMonitoringAndBackupQualification"],
        "qa-full.txt": ["TestSQLiteFilesystemFullRecovery"],
    }
    checks = {"workflow_prior_steps": os.environ.get("ASB_QA_PRIOR_STATUS") == "success"}
    for name, tests in required.items():
        path = directory / name
        text = path.read_text() if path.is_file() else ""
        for test in tests:
            checks[test] = bool(re.search(r"^--- PASS: " + test + r" \(", text, re.M))
        checks[name + ":no_failure"] = "--- FAIL:" not in text and "panic:" not in text

    core = directory / "tests.jsonl"
    events = [json.loads(line) for line in core.read_text().splitlines()] if core.is_file() else []
    passed = {event.get("Test") for event in events if event.get("Action") == "pass"}
    for name in [
        "TestSQLiteMonitoringDoesNotWaitForWriter",
        "TestSQLiteMonitoringRejectsSealedAndChangedNamespace",
        "TestSQLiteLockCancellationRecovers",
        "TestSQLiteBackupRecoveryPreservesPublishedAndActiveFiles",
        "TestSQLiteBackupCrashBoundaries",
        "TestSQLiteCopyCancellationDoesNotPublishOutput",
        "TestSQLiteKernelWriteFailureRecovery",
        "TestSQLiteReaderReleasesWALAndKeepsHistory",
        "TestConnectionLimitBoundsAcceptAndRecovers",
        "TestConnectionCyclesReleaseDescriptorsAndGoroutines",
        "TestDiagnosticsAreBoundedAndRedactUntrustedText",
        "TestJournalFailureIsDiagnosableWithoutChangingUnknown",
        "TestProviderDiagnosticStagesDiscardPrivateText",
        "TestCLICancellationStopsChildGroupAndRemovesIdentity",
    ]:
        checks[name] = name in passed
    checks["core:no_failure"] = bool(events) and all(event.get("Action") != "fail" for event in events)
    source = directory / "source-commit.txt"
    commit = source.read_text().strip() if source.is_file() else ""
    checks["source_commit"] = bool(re.fullmatch(r"[0-9a-f]{40}", commit))
    binary, manifest = directory / "asb-s3", directory / "binary.sha256"
    checks["binary_sha256"] = binary.is_file() and manifest.is_file() and digest(binary) == manifest.read_text().split()[0]
    hashes = {path.name: digest(path) for path in sorted(directory.iterdir()) if path.is_file() and not path.is_symlink() and path.name != "qa-result.json"}
    result = {
        "schema": "asb.s3-operational-qa/v1",
        "source_commit": commit,
        "status": "passed" if all(checks.values()) else "failed_or_incomplete",
        "checks": checks,
        "files_sha256": hashes,
        "real_aws": False,
        "container_boot_is_physical_reboot": False,
        "physical_power_loss_qualified": False,
        "organization_deployment_qualified": False,
        "long_term_leak_absence_proven": False,
    }
    (directory / "qa-result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": result["status"], "checks": len(checks), "failed": [key for key, value in checks.items() if not value]}))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
