#!/usr/bin/env python3
# Copyright (c) 2026 ToppyMicroServices OÜ
# SPDX-License-Identifier: Apache-2.0
"""Run approved real-model A2A success and artifact rejection tests on CPU.

Use only a disposable fixture from prepare-real-model-lora.py. Negative cases
temporarily change its files and restore them in finally blocks. Approval pins
are captured before any mutation and are never recomputed from an attack.
"""

import argparse
import contextlib
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile
import time


def digest(path):
    hasher = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(block)
    return "sha256:" + hasher.hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def command_text(arguments, cwd):
    return subprocess.check_output(arguments, cwd=cwd, text=True).strip()


def verify_fixture(config):
    """Check trusted pins and every declared input before and after the suite."""
    root = Path(config["root_path"])
    verified = {}
    for kind in ("base", "lora"):
        path = Path(config[kind + "_manifest_path"])
        if digest(path) != config[kind + "_manifest_sha256"]:
            raise ValueError("approved manifest changed: " + kind)
        manifest = json.loads(path.read_text(encoding="utf-8"))
        for component in ("model", "adapter"):
            for entry in manifest.get(component, {}).get("files", []):
                relative = Path(component) / entry["path"]
                if relative.is_absolute() or ".." in relative.parts:
                    raise ValueError("invalid fixture path")
                source = root / relative
                if source.is_symlink() or source.stat().st_size != entry["size"] or digest(source) != entry["sha256"]:
                    raise ValueError("approved fixture changed: " + str(relative))
                verified[str(relative)] = entry["sha256"]
    if digest(config["python_path"]) != config["python_sha256"]:
        raise ValueError("approved Python executable changed")
    return verified


@contextlib.contextmanager
def altered_byte(path):
    path = Path(path)
    offset = path.stat().st_size - 1
    with path.open("r+b") as stream:
        stream.seek(offset)
        original = stream.read(1)
        stream.seek(offset)
        stream.write(bytes([original[0] ^ 1]))
    try:
        yield {"operation": "xor final byte with 1", "offset": offset, "changed_sha256": digest(path)}
    finally:
        with path.open("r+b") as stream:
            stream.seek(offset)
            stream.write(original)


@contextlib.contextmanager
def altered_json(path, change):
    path = Path(path)
    original = path.read_bytes()
    value = json.loads(original)
    change(value)
    try:
        write_json(path, value)
        yield {"operation": "change JSON", "changed_sha256": digest(path), "changed_value": value}
    finally:
        path.write_bytes(original)


@contextlib.contextmanager
def missing_file(path):
    path = Path(path)
    withheld = path.with_name(path.name + ".withheld")
    if withheld.exists():
        raise ValueError("withheld fixture already exists")
    path.rename(withheld)
    try:
        yield {"operation": "remove declared file"}
    finally:
        withheld.rename(path)


def run_case(binary, config, output, name, profile="v1", rejected_agent=None,
             rejection="digest mismatch", b_kind="lora", b_manifest_path=None, mutation=None):
    case = output / name
    case.mkdir()
    prompt = case / "prompt.txt"
    prompt.write_text("Ask Agent B to reply with one short sentence confirming receipt.\n", encoding="utf-8")
    report = case / "a2a-report.json"
    log = case / "a2a.log"
    with tempfile.TemporaryDirectory(prefix="asb-real-state-", dir="/private/tmp") as state:
        arguments = [str(binary), "--debug-simple", "--workflow", "llm-conversation",
                     "--binding-profile", profile, "--state-dir", state, "--report", str(report),
                     "--prompt-file", str(prompt), "--transformers-device", "cpu", "--llm-request-timeout", "5m",
                     "--python-path", config["python_path"], "--python-sha256", config["python_sha256"],
                     "--python-site-packages", config["python_site_packages"]]
        for role, kind in (("a", "base"), ("b", b_kind)):
            manifest_path = b_manifest_path if role == "b" and b_manifest_path else config[kind + "_manifest_path"]
            arguments.extend(["--agent-" + role + "-model-dir", config["root_path"],
                              "--agent-" + role + "-model-manifest", str(manifest_path),
                              "--agent-" + role + "-model-manifest-sha256", config[kind + "_manifest_sha256"]])
        write_json(case / "command.json", arguments)
        print(json.dumps({"case": name, "status": "running"}), flush=True)
        started = time.monotonic()
        timed_out = False
        with log.open("wb") as stream:
            process = subprocess.Popen(arguments, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                returncode = process.wait(timeout=900)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                returncode = process.returncode
        elapsed = time.monotonic() - started
        text = log.read_text(encoding="utf-8", errors="replace")
        raw_report = json.loads(report.read_text(encoding="utf-8")) if report.exists() else {}
        scenarios = raw_report.get("scenarios", [])
        success = [entry for entry in scenarios if entry.get("id") == "ASB-A2A-LLM-001" and entry.get("status") == "PASS"]
        expected_profile = ("direct-agent-v1" if profile == "v1" else profile) + "+llm-conversation-v1"
        ready_b = (Path(state) / ".ready-agent-b").exists()
        if rejected_agent:
            expected_error = "configure Agent " + rejected_agent + " LLM: llm runtime: " + rejection
            passed = (not timed_out and returncode != 0 and expected_error in text
                      and raw_report.get("status") == "ERROR" and raw_report.get("summary", {}).get("passed") == 0
                      and not success and "Agent A -> Agent B:" not in text
                      and "Agent A text is bound before delivery" not in text
                      and (rejected_agent != "B" or not ready_b))
            detail = {"expected_error": expected_error, "phase": "pre-runtime artifact validation",
                      "phase_evidence": "exact configuration error plus NewManagedModel call ordering; no inference counter is instrumented"}
        else:
            a_marker, b_marker = "Agent A -> Agent B:\n", "Agent B -> Agent A:\n"
            a_text = text.split(a_marker, 1)[1].split(b_marker, 1)[0].strip() if a_marker in text and b_marker in text else ""
            b_text = text.split(b_marker, 1)[1].rsplit("\nsummary: ", 1)[0].strip() if b_marker in text else ""
            passed = (not timed_out and returncode == 0 and raw_report.get("status") == "PASS"
                      and raw_report.get("profile") == expected_profile
                      and raw_report.get("summary", {}).get("total") == 1
                      and raw_report.get("summary", {}).get("passed") == 1
                      and len(success) == 1 and bool(a_text) and bool(b_text) and ready_b)
            detail = {"agent_a_text": a_text, "agent_b_text": b_text}
        result = {"name": name, "status": "PASS" if passed else "FAIL", "profile": profile,
                  "expected": "reject" if rejected_agent else "accept", "exit_code": returncode,
                  "duration_seconds": round(elapsed, 3), "timed_out": timed_out,
                  "agent_b_ready": ready_b, "cli_report_status": raw_report.get("status"),
                  "observed_profile": raw_report.get("profile"), "attestation": raw_report.get("attestation"),
                  "log_sha256": digest(log), "mutation": mutation, **detail}
        if report.exists():
            result["report_sha256"] = digest(report)
        write_json(case / "result.json", result)
        print(json.dumps({"case": name, "status": result["status"], "seconds": result["duration_seconds"]}), flush=True)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding="utf-8"))
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    root = Path(config["root_path"])
    repo = Path(__file__).resolve().parent.parent
    before = verify_fixture(config)
    approval_path = args.config.parent / "approval.json"
    approval = json.loads(approval_path.read_text(encoding="utf-8"))
    if set(approval["approved_manifest_sha256"]) != {config[kind + "_manifest_sha256"] for kind in ("base", "lora")}:
        raise ValueError("test approval does not match the configured manifest pins")
    runtime_diff = command_text(["git", "diff", "HEAD", "--", "pkg", "examples/a2a-multiprocess", "go.mod", "go.sum"], repo)
    if runtime_diff:
        raise ValueError("runtime tracked files differ from the recorded source commit")
    binary = output / "a2a-multiprocess"
    build_command = ["go", "build", "-o", str(binary), "./examples/a2a-multiprocess"]
    with (output / "build.log").open("wb") as log:
        subprocess.run(build_command, cwd=repo, stdout=log, stderr=subprocess.STDOUT, check=True)
    evidence = {"schema": "asb.real-model-system-test/v1", "started_at": datetime.now(timezone.utc).isoformat(),
                "source_commit": command_text(["git", "rev-parse", "HEAD"], repo),
                "source_tree_diff": command_text(["git", "diff", "--stat"], repo),
                "runner_sha256": digest(__file__), "binary_sha256": digest(binary),
                "build_command": build_command, "go_version": command_text(["go", "version"], repo),
                "approval_sha256": digest(approval_path),
                "preparation_artifacts": {name: digest(args.config.parent / name) for name in
                                          ("preparation-evidence.json", "training.json", "training-dataset.json", "source-files.json")},
                "config_sha256": digest(args.config), "platform": platform.platform(), "machine": platform.machine(),
                "device": "cpu", "python": sys.version, "attestation": "simulation",
                "versions": {name: importlib.metadata.version(name) for name in ("torch", "transformers", "peft", "safetensors", "tokenizers")},
                "approved_pins": {kind: config[kind + "_manifest_sha256"] for kind in ("base", "lora")},
                "approved_files_before": before, "cases": [], "status": "RUNNING",
                "limits": ["test-only artifact approval; no model-wide safety claim", "CPU on one Mac; MPS/CUDA not tested",
                           "simulated attestation; not peer-verifiable loaded-weight evidence", "no live IPFS retrieval"]}
    evidence_path = output / "evidence.json"

    def check(name, **options):
        result = run_case(binary, config, output, name, **options)
        evidence["cases"].append(result)
        write_json(evidence_path, evidence)
        if result["status"] != "PASS":
            raise RuntimeError("system case failed: " + name)

    try:
        check("approved_v1")
        check("approved_v2", profile="draft06-v2")
        for name, relative in (("changed_base", "model/model.safetensors"),
                               ("changed_lora", "adapter/adapter_model.safetensors"),
                               ("changed_tokenizer", "model/tokenizer.json"),
                               ("changed_model_config", "model/config.json"),
                               ("changed_adapter_config", "adapter/adapter_config.json")):
            with altered_byte(root / relative) as change:
                check(name, rejected_agent="B", mutation={"file": relative, **change})
        with altered_json(root / "model/tokenizer_config.json", lambda value: value.update(chat_template="unapproved " + value["chat_template"])) as change:
            check("changed_chat_template", rejected_agent="B", mutation=change)
        with missing_file(root / "adapter/adapter_model.safetensors") as change:
            check("missing_lora", rejected_agent="B", rejection="invalid configuration: bundle file must be regular and not a symlink", mutation=change)
        with altered_json(config["lora_manifest_path"], lambda value: value.pop("adapter")) as change:
            check("removed_adapter_from_manifest", rejected_agent="B", mutation=change)
        adapter = json.loads(Path(config["lora_manifest_path"]).read_text(encoding="utf-8"))["adapter"]
        # Separate candidate file: this changes B's base-only policy input without
        # changing Agent A's manifest or its independently captured approval pin.
        candidate = output / "added-adapter-manifest.json"
        base = json.loads(Path(config["base_manifest_path"]).read_text(encoding="utf-8"))
        write_json(candidate, {**base, "adapter": adapter})
        check("added_adapter_to_manifest", rejected_agent="B", b_kind="base", b_manifest_path=candidate,
              mutation={"changed_sha256": digest(candidate)})
        with altered_byte(root / "adapter/adapter_model.safetensors") as tensor_change:
            def rehash(value):
                for entry in value["adapter"]["files"]:
                    if entry["path"] == "adapter_model.safetensors":
                        entry["sha256"] = tensor_change["changed_sha256"]
            with altered_json(config["lora_manifest_path"], rehash) as manifest_change:
                check("attacker_rehashed_manifest", rejected_agent="B", mutation={"tensor": tensor_change, "manifest": manifest_change})
        with altered_json(config["base_manifest_path"], lambda value: value.update(adapter=adapter)) as change:
            check("agent_a_policy_changed", rejected_agent="A", mutation=change)
        if len(evidence["cases"]) != 13:
            raise RuntimeError("incomplete system-test matrix")
        evidence["status"] = "PASS"
    except Exception as error:
        evidence["status"] = "FAIL"
        evidence["error"] = str(error)
    finally:
        try:
            evidence["approved_files_after"] = verify_fixture(config)
            evidence["approved_fixture_restored"] = evidence["approved_files_after"] == before
        except Exception as error:
            evidence["approved_fixture_restored"] = False
            evidence["restoration_error"] = str(error)
            evidence["status"] = "FAIL"
        evidence["finished_at"] = datetime.now(timezone.utc).isoformat()
        write_json(evidence_path, evidence)
    raise SystemExit(0 if evidence["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
