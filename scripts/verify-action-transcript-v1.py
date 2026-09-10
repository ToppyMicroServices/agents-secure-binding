#!/usr/bin/env python3
"""Recompute the Action v1 golden transcripts independently of the Go encoder."""

import calendar
import hashlib
import json
from pathlib import Path
import re
import struct
import sys


def string(value):
    raw = value.encode("utf-8", errors="strict")
    return struct.pack(">H", len(raw)) + raw


def u32(value):
    return struct.pack(">I", value)


def u64(value):
    return struct.pack(">Q", value)


def timestamp(value):
    match = re.fullmatch(
        r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z",
        value,
    )
    if match is None:
        raise ValueError("golden timestamp must be an exact UTC instant")
    parts = [int(part) for part in match.groups()[:6]]
    seconds = calendar.timegm((*parts, 0, 0, 0))
    nanos = int((match.group(7) or "").ljust(9, "0"))
    return struct.pack(">qI", seconds, nanos)


def optional(value, encode):
    return b"\x00" if value is None else b"\x01" + encode(value)


def fields(value, names):
    return b"".join(string(value[name]) for name in names)


def fence(value):
    return fields(value, ("lease_id", "executor_id")) + u64(value["generation"])


def lease(value):
    return fence(value) + timestamp(value["issued_at"]) + timestamp(value["expires_at"])


def resume(value):
    return (
        string(value["type"])
        + optional(value["not_before"], timestamp)
        + optional(value["probe_after"], timestamp)
        + fields(value, ("target", "dependency_action_id", "signal"))
    )


def checkpoint(value):
    return (
        u64(value["sequence"])
        + fields(value, ("payload_digest", "storage_ref"))
        + timestamp(value["created_at"])
    )


def transcript(name, value):
    if name == "acceptance_context":
        return (
            string("asb.task-action-accept-context/v1")
            + string(value["assignment_id"])
            + u64(value["expected_assignment_revision"])
            + fields(value, ("task_id", "participant_id", "role", "authority_digest", "assignment_status"))
        )
    if name == "acceptance_request":
        return (
            string("asb.action-accept-request/v1")
            + fields(value, ("operation", "event_id", "action_id", "action_digest", "owner_id", "recovery_mode"))
            + u32(value["recovery_max_attempts"])
            + fields(value, ("recovery_idempotency_key", "acceptance_context_digest"))
        )
    if name == "acceptance_attempt":
        return (
            string("asb.task-action-accept-attempt/v1")
            + fields(value, ("actor_id", "authorization_id", "proof_id", "operation", "action_id", "action_digest", "mutation_digest", "verifier_nonce"))
            + timestamp(value["issued_at"])
            + timestamp(value["expires_at"])
        )
    if name == "mutation_request":
        return (
            string("asb.action-mutation-request/v1")
            + fields(value, ("event_id", "kind"))
            + u64(value["expected_revision"])
            + timestamp(value["at"])
            + fields(value, ("reason_code", "reason_detail"))
            + optional(value["fence"], fence)
            + optional(value["lease"], lease)
            + optional(value["resume_condition"], resume)
            + optional(value["checkpoint"], checkpoint)
            + fields(value, ("evidence_ref", "reconciliation_result", "result_ref", "error_code"))
        )
    raise ValueError(f"unknown golden vector: {name}")


def main():
    path = Path(sys.argv[1]) if len(sys.argv) == 2 else Path(__file__).resolve().parents[1] / "testdata/action-transcript-v1-vectors.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    vectors = document["vectors"]
    if document["profile"] != "asb.action-transcript-golden/v1" or set(vectors) != {
        "acceptance_context", "acceptance_request", "acceptance_attempt", "mutation_request"
    }:
        raise ValueError("unexpected golden profile or vector set")
    for name, vector in vectors.items():
        raw = transcript(name, vector["input"])
        if len(raw) > 16_384 or raw.hex() != vector["transcript_hex"]:
            raise ValueError(f"{name}: transcript mismatch")
        if "sha256:" + hashlib.sha256(raw).hexdigest() != vector["digest"]:
            raise ValueError(f"{name}: digest mismatch")
        print(f"PASS {name}")


if __name__ == "__main__":
    main()
