#!/usr/bin/env python3
# Copyright (c) 2026 ToppyMicroServices OÜ
# SPDX-License-Identifier: Apache-2.0

"""Verify the draft06-v2 Appendix B context vector without Go code."""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path


CONTEXT_DOMAIN = b"SBAIP-CONTEXT-v2\x00"
ATTESTATION_DOMAIN = b"SBAIP-ATTESTATION-BINDING-v1\x00"


class VectorError(ValueError):
    pass


def object_without_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise VectorError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def require_members(value, expected, where):
    if not isinstance(value, dict):
        raise VectorError(f"{where} must be an object")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise VectorError(
            f"{where} member mismatch; missing={missing}, unknown={unknown}"
        )


def utf8(value, name):
    if not isinstance(value, str):
        raise VectorError(f"{name} must be a string")
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise VectorError(f"{name} is not valid UTF-8") from exc


def canonical_hex(value, name, exact_length=None):
    if not isinstance(value, str) or value != value.lower():
        raise VectorError(f"{name} must be lowercase hexadecimal")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise VectorError(f"{name} must be hexadecimal") from exc
    if decoded.hex() != value:
        raise VectorError(f"{name} must be canonical hexadecimal")
    if exact_length is not None and len(decoded) != exact_length:
        raise VectorError(f"{name} must contain {exact_length} octets")
    return decoded


def field(name, value):
    name_bytes = name.encode("ascii")
    if len(name_bytes) > 0xFFFF or len(value) > 0xFFFFFFFF:
        raise VectorError(f"field too long: {name}")
    return (
        struct.pack(">H", len(name_bytes))
        + name_bytes
        + struct.pack(">I", len(value))
        + value
    )


def sha256_hex(value):
    return hashlib.sha256(value).hexdigest()


def check_equal(name, actual, expected):
    if not isinstance(expected, str):
        raise VectorError(f"expected.{name} must be a string")
    if actual != expected:
        raise VectorError(f"{name} mismatch: got {actual}, want {expected}")


def verify(path):
    if path.stat().st_size > 1024 * 1024:
        raise VectorError("fixture exceeds 1 MiB")
    with path.open("r", encoding="utf-8") as source:
        vector = json.load(source, object_pairs_hook=object_without_duplicates)

    require_members(
        vector, {"fixture_version", "id", "profile", "inputs", "expected"}, "root"
    )
    if vector["fixture_version"] != "1":
        raise VectorError("unsupported fixture_version")
    if vector["profile"] != "draft06-v2":
        raise VectorError("unexpected profile")

    inputs = vector["inputs"]
    require_members(
        inputs,
        {
            "endpoint_role",
            "interaction_type",
            "protocol_id",
            "audience",
            "grant_hash_hex",
            "task_context_utf8",
            "target_context_utf8",
            "verifier_nonce_hex",
            "attempt_id_utf8",
            "accepted_endpoint_spki_hex",
            "tls_exporter_hex",
        },
        "inputs",
    )
    expected = vector["expected"]
    require_members(
        expected,
        {
            "binding_context_hex",
            "binding_context_sha256",
            "accepted_endpoint_spki_sha256",
            "tls_exporter_sha256",
            "attestation_binder_sha256",
        },
        "expected",
    )

    grant_hash = canonical_hex(inputs["grant_hash_hex"], "grant_hash_hex", 32)
    nonce = canonical_hex(inputs["verifier_nonce_hex"], "verifier_nonce_hex")
    if len(nonce) < 16:
        raise VectorError("verifier_nonce_hex must contain at least 16 octets")
    leaf_spki = canonical_hex(
        inputs["accepted_endpoint_spki_hex"], "accepted_endpoint_spki_hex"
    )
    if not leaf_spki:
        raise VectorError("accepted_endpoint_spki_hex must not be empty")
    exporter = canonical_hex(inputs["tls_exporter_hex"], "tls_exporter_hex", 32)

    context = CONTEXT_DOMAIN + b"".join(
        (
            field("endpoint_role", utf8(inputs["endpoint_role"], "endpoint_role")),
            field(
                "interaction_type",
                utf8(inputs["interaction_type"], "interaction_type"),
            ),
            field("protocol_id", utf8(inputs["protocol_id"], "protocol_id")),
            field("aud", utf8(inputs["audience"], "audience")),
            field("grant_hash", grant_hash),
            field(
                "task_context", utf8(inputs["task_context_utf8"], "task_context_utf8")
            ),
            field(
                "target_context",
                utf8(inputs["target_context_utf8"], "target_context_utf8"),
            ),
            field("verifier_nonce", nonce),
            field("attempt_id", utf8(inputs["attempt_id_utf8"], "attempt_id_utf8")),
        )
    )
    attestation_input = (
        ATTESTATION_DOMAIN
        + field("leaf_spki", leaf_spki)
        + field("ekm", exporter)
    )

    check_equal("binding_context_hex", context.hex(), expected["binding_context_hex"])
    check_equal(
        "binding_context_sha256",
        sha256_hex(context),
        expected["binding_context_sha256"],
    )
    check_equal(
        "accepted_endpoint_spki_sha256",
        sha256_hex(leaf_spki),
        expected["accepted_endpoint_spki_sha256"],
    )
    check_equal(
        "tls_exporter_sha256",
        sha256_hex(exporter),
        expected["tls_exporter_sha256"],
    )
    check_equal(
        "attestation_binder_sha256",
        sha256_hex(attestation_input),
        expected["attestation_binder_sha256"],
    )
    return vector["id"]


def main():
    parser = argparse.ArgumentParser(
        description="Independently verify the draft06-v2 Appendix B context vector."
    )
    parser.add_argument("fixture", type=Path)
    args = parser.parse_args()
    try:
        vector_id = verify(args.fixture)
    except (OSError, UnicodeError, json.JSONDecodeError, VectorError) as exc:
        print(f"verification failed: {exc}", file=sys.stderr)
        return 1
    print(f"verified {vector_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
