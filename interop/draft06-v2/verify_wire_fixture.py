#!/usr/bin/env python3
"""Independently verify the repository's draft06-v2 full-wire fixture."""

import argparse
import base64
import datetime
import hashlib
import json
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


MAX_FIXTURE_BYTES = 1024 * 1024

SECURITY_BINDING = "urn:agents-secure-binding:security-binding:v2"
ATTESTATION_RESULT = "urn:agents-secure-binding:attestation-result:v2"

TASK_DOMAIN = b"ASB-A2A-TASK-v2\x00"
TARGET_DOMAIN = b"ASB-A2A-TARGET-v2\x00"
CONTEXT_DOMAIN = b"SBAIP-CONTEXT-v2\x00"
ATTESTATION_DOMAIN = b"SBAIP-ATTESTATION-BINDING-v1\x00"
GRANT_HASH_DOMAIN = b"sbaip.identity-grant.jwt.v1\x00"


class FixtureError(ValueError):
    pass


def object_without_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise FixtureError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def load_json_bytes(raw, where):
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FixtureError(f"{where} is not UTF-8") from exc
    try:
        return json.loads(text, object_pairs_hook=object_without_duplicates)
    except json.JSONDecodeError as exc:
        raise FixtureError(f"{where} is not valid JSON: {exc}") from exc


def require_members(value, expected, where):
    if not isinstance(value, dict):
        raise FixtureError(f"{where} must be an object")
    actual = set(value)
    if actual != set(expected):
        missing = sorted(set(expected) - actual)
        unknown = sorted(actual - set(expected))
        raise FixtureError(
            f"{where} member mismatch; missing={missing}, unknown={unknown}"
        )


def require_list(value, length, where):
    if not isinstance(value, list) or len(value) != length:
        raise FixtureError(f"{where} must contain exactly {length} values")
    return value


def require_string(value, where, nonempty=True):
    if not isinstance(value, str) or (nonempty and not value):
        raise FixtureError(f"{where} must be a non-empty string")
    if "\ufffd" in value or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise FixtureError(f"{where} contains a disallowed character")
    return value


def require_int(value, where):
    if isinstance(value, bool) or not isinstance(value, int):
        raise FixtureError(f"{where} must be an integer")
    return value


def check_equal(where, actual, expected):
    if actual != expected:
        raise FixtureError(f"{where} mismatch: got {actual!r}, want {expected!r}")


def b64url_decode(value, where, exact_length=None, minimum_length=None):
    require_string(value, where)
    if "=" in value:
        raise FixtureError(f"{where} must be unpadded base64url")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise FixtureError(f"{where} is not base64url") from exc
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise FixtureError(f"{where} is not canonical base64url")
    if exact_length is not None and len(raw) != exact_length:
        raise FixtureError(f"{where} must contain {exact_length} octets")
    if minimum_length is not None and len(raw) < minimum_length:
        raise FixtureError(f"{where} must contain at least {minimum_length} octets")
    return raw


def b64url_encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def sha256_label(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def require_sha256(value, where):
    require_string(value, where)
    if len(value) != 71 or not value.startswith("sha256:"):
        raise FixtureError(f"{where} is not a canonical SHA-256 value")
    digest = value[7:]
    if digest != digest.lower():
        raise FixtureError(f"{where} is not lowercase")
    try:
        raw = bytes.fromhex(digest)
    except ValueError as exc:
        raise FixtureError(f"{where} is not hexadecimal") from exc
    if len(raw) != 32 or raw.hex() != digest:
        raise FixtureError(f"{where} is not a canonical SHA-256 value")
    return raw


def parse_time(value, where):
    require_string(value, where)
    try:
        parsed = datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise FixtureError(f"{where} must use canonical UTC RFC 3339 form") from exc
    return parsed.replace(tzinfo=datetime.timezone.utc)


def field(name, value):
    name_bytes = name.encode("ascii")
    if len(name_bytes) > 0xFFFF or len(value) > 0xFFFFFFFF:
        raise FixtureError(f"field too long: {name}")
    return (
        struct.pack(">H", len(name_bytes))
        + name_bytes
        + struct.pack(">I", len(value))
        + value
    )


def canonical_list(values, where):
    if not isinstance(values, list) or not values:
        raise FixtureError(f"{where} must be a non-empty list")
    encoded = [require_string(value, f"{where} value").encode("utf-8") for value in values]
    encoded.sort()
    if any(encoded[index] == encoded[index - 1] for index in range(1, len(encoded))):
        raise FixtureError(f"{where} contains a duplicate")
    return struct.pack(">I", len(encoded)) + b"".join(
        struct.pack(">I", len(value)) + value for value in encoded
    )


def parse_compact_jws(token, where, expected_type, jwk):
    require_string(token, where)
    parts = token.split(".")
    if len(parts) != 3:
        raise FixtureError(f"{where} is not a compact JWS")
    protected_raw = b64url_decode(parts[0], f"{where} protected header")
    payload_raw = b64url_decode(parts[1], f"{where} payload")
    signature = b64url_decode(parts[2], f"{where} signature", exact_length=64)
    protected = load_json_bytes(protected_raw, f"{where} protected header")
    require_members(protected, {"alg", "kid", "typ"}, f"{where} protected header")
    check_equal(f"{where} alg", protected["alg"], "ES256")
    check_equal(f"{where} kid", protected["kid"], jwk["kid"])
    check_equal(f"{where} typ", protected["typ"], expected_type)
    payload = load_json_bytes(payload_raw, f"{where} payload")
    if not isinstance(payload, dict):
        raise FixtureError(f"{where} payload must be an object")
    return payload, (parts[0] + "." + parts[1]).encode("ascii"), signature


def der_length(length):
    if length < 0 or length >= 128:
        raise FixtureError("unexpected DER length")
    return bytes((length,))


def der_integer(raw):
    value = raw.lstrip(b"\x00") or b"\x00"
    if value[0] & 0x80:
        value = b"\x00" + value
    return b"\x02" + der_length(len(value)) + value


def ecdsa_signature_der(raw):
    if len(raw) != 64:
        raise FixtureError("ES256 signature must contain 64 octets")
    body = der_integer(raw[:32]) + der_integer(raw[32:])
    return b"\x30" + der_length(len(body)) + body


def jwk_spki(jwk, where):
    require_members(jwk, {"kty", "crv", "kid", "use", "x", "y"}, where)
    check_equal(f"{where}.kty", jwk["kty"], "EC")
    check_equal(f"{where}.crv", jwk["crv"], "P-256")
    check_equal(f"{where}.use", jwk["use"], "sig")
    require_string(jwk["kid"], f"{where}.kid")
    x_coord = b64url_decode(jwk["x"], f"{where}.x", exact_length=32)
    y_coord = b64url_decode(jwk["y"], f"{where}.y", exact_length=32)
    # SubjectPublicKeyInfo for id-ecPublicKey with the prime256v1 named curve.
    algorithm = bytes.fromhex("301306072a8648ce3d020106082a8648ce3d030107")
    public_point = b"\x04" + x_coord + y_coord
    bit_string = b"\x03" + der_length(len(public_point) + 1) + b"\x00" + public_point
    body = algorithm + bit_string
    return b"\x30" + der_length(len(body)) + body


def pem_public_key(spki):
    encoded = base64.b64encode(spki).decode("ascii")
    lines = [encoded[index : index + 64] for index in range(0, len(encoded), 64)]
    return ("-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n").encode("ascii")


def verify_es256(openssl, where, signing_input, signature, jwk):
    with tempfile.TemporaryDirectory(prefix="asb-wire-") as directory:
        key_path = Path(directory) / "public.pem"
        signature_path = Path(directory) / "signature.der"
        key_path.write_bytes(pem_public_key(jwk_spki(jwk, f"{where} JWK")))
        signature_path.write_bytes(ecdsa_signature_der(signature))
        result = subprocess.run(
            [
                openssl,
                "dgst",
                "-sha256",
                "-verify",
                str(key_path),
                "-signature",
                str(signature_path),
            ],
            input=signing_input,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
    if result.returncode != 0:
        raise FixtureError(f"{where} signature verification failed")


def validate_fixture_shape(fixture):
    require_members(
        fixture,
        {
            "binding_inputs",
            "claim_scope",
            "expected",
            "fixture_version",
            "http_request",
            "now",
            "profile",
            "public_keys",
            "verifier_inputs",
        },
        "root",
    )
    check_equal("fixture_version", fixture["fixture_version"], "1")
    check_equal("profile", fixture["profile"], "draft06-v2")
    check_equal("claim_scope", fixture["claim_scope"], "repository-profile-evidence")
    require_members(
        fixture["http_request"],
        {"method", "path", "headers", "must_be_absent_headers", "body_base64url", "body_sha256"},
        "http_request",
    )
    require_members(
        fixture["binding_inputs"],
        {"endpoint_spki_der_base64url", "tls_exporter_base64url", "verifier_nonce", "attempt_id"},
        "binding_inputs",
    )
    require_members(
        fixture["verifier_inputs"],
        {
            "accepted_profile",
            "endpoint_credential_expires_at",
            "evidence_challenge_expires_at",
            "local_policy_expires_at",
            "policy",
        },
        "verifier_inputs",
    )
    check_equal("verifier policy", fixture["verifier_inputs"]["policy"], "receiverPolicyV2")
    require_members(
        fixture["verifier_inputs"]["accepted_profile"],
        {"profile_type", "profile_version", "binding_profile", "protocol_id"},
        "verifier_inputs.accepted_profile",
    )
    check_equal(
        "accepted profile selection",
        fixture["verifier_inputs"]["accepted_profile"],
        {
            "profile_type": "sbaip.session-binding",
            "profile_version": "2",
            "binding_profile": "draft06-v2",
            "protocol_id": "urn:agents-secure-binding:a2a-http-json:v2",
        },
    )
    require_members(
        fixture["public_keys"],
        {"manager", "agent", "attestation_verifier"},
        "public_keys",
    )
    require_members(
        fixture["expected"],
        {
            "accepted_assertion",
            "accepted_endpoint_spki_sha256",
            "attestation_binder_sha256",
            "attestation_report_data_sha512_base64url",
            "binding_context_base64url",
            "binding_context_sha256",
            "grant_hash",
            "identity_grant_sha256",
            "session_binding_sha256",
            "target_context_base64url",
            "target_context_sha256",
            "task_context_base64url",
            "task_context_sha256",
            "tls_exporter_sha256",
        },
        "expected",
    )


def validate_http_and_body(fixture):
    request = fixture["http_request"]
    check_equal("HTTP method", request["method"], "POST")
    check_equal("HTTP path", request["path"], "/message:send")
    require_members(
        request["headers"],
        {"Host", "Content-Type", "A2A-Version", "A2A-Extensions"},
        "http_request.headers",
    )
    check_equal("Host", request["headers"]["Host"], "agent-b.example.test")
    check_equal("Content-Type", request["headers"]["Content-Type"], "application/a2a+json")
    check_equal("A2A-Version", request["headers"]["A2A-Version"], "1.0")
    check_equal(
        "A2A-Extensions",
        request["headers"]["A2A-Extensions"],
        SECURITY_BINDING + "," + ATTESTATION_RESULT,
    )
    absent = [
        "Early-Data",
        "Forwarded",
        "Via",
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Forwarded-Proto",
    ]
    check_equal("must_be_absent_headers", request["must_be_absent_headers"], absent)
    if any(name in request["headers"] for name in absent):
        raise FixtureError("HTTP request contains a forbidden transport header")

    body_raw = b64url_decode(request["body_base64url"], "http_request.body_base64url")
    require_sha256(request["body_sha256"], "http_request.body_sha256")
    check_equal("HTTP body SHA-256", sha256_label(body_raw), request["body_sha256"])
    body = load_json_bytes(body_raw, "HTTP body")
    require_members(body, {"message", "configuration"}, "HTTP body")
    require_members(body["configuration"], {"acceptedOutputModes"}, "configuration")
    check_equal("acceptedOutputModes", body["configuration"]["acceptedOutputModes"], ["text/plain"])
    message = body["message"]
    require_members(
        message,
        {"messageId", "contextId", "taskId", "role", "parts", "metadata", "extensions"},
        "message",
    )
    for name in ("messageId", "contextId", "taskId", "role"):
        require_string(message[name], f"message.{name}")
    extensions = require_list(message["extensions"], 2, "message.extensions")
    if set(extensions) != {SECURITY_BINDING, ATTESTATION_RESULT}:
        raise FixtureError("message.extensions does not select the two v2 extensions")
    part = require_list(message["parts"], 1, "message.parts")[0]
    require_members(part, {"text", "metadata", "mediaType"}, "message part")
    require_string(part["text"], "message part text")
    check_equal("message part mediaType", part["mediaType"], "text/plain")
    require_members(part["metadata"], {"resource", "operation"}, "message part metadata")
    require_string(part["metadata"]["resource"], "target resource")
    require_string(part["metadata"]["operation"], "target operation")
    require_members(message["metadata"], {SECURITY_BINDING, ATTESTATION_RESULT}, "message metadata")
    return body, message, part


def build_contexts(message, part):
    task = TASK_DOMAIN + b"".join(
        (
            field("a2a_version", b"1.0"),
            field("method", b"POST"),
            field("path", b"/message:send"),
            field("message_id", message["messageId"].encode("utf-8")),
            field("context_id", message["contextId"].encode("utf-8")),
            field("task_id", message["taskId"].encode("utf-8")),
            field("role", message["role"].encode("utf-8")),
            field(
                "accepted_output_modes",
                canonical_list(["text/plain"], "acceptedOutputModes"),
            ),
            field("part_media_type", part["mediaType"].encode("utf-8")),
            field("part_text_sha256", hashlib.sha256(part["text"].encode("utf-8")).digest()),
            field("selected_extensions", canonical_list(message["extensions"], "message.extensions")),
        )
    )
    target = TARGET_DOMAIN + field(
        "resource", part["metadata"]["resource"].encode("utf-8")
    ) + field("operation", part["metadata"]["operation"].encode("utf-8"))
    return task, target


def validate_token_payloads(fixture, message, part, sbo, grant, proof, attestation, now):
    grant_members = {
        "agent", "aud", "capability_ref", "cnf", "deployment", "exp", "iat",
        "intent_ref", "iss", "jti", "profile_type", "profile_version", "resource",
        "scope", "service", "sub", "target_operation", "target_resource", "task_id",
        "thread_id", "workload",
    }
    proof_members = {
        "accepted_endpoint_spki_sha256", "attempt_id", "attestation_binder_sha256",
        "aud", "binding_context_sha256", "endpoint_role", "exp", "grant_hash", "iat",
        "interaction_type", "iss", "jti", "profile_type", "profile_version",
        "tls_exporter_sha256", "verifier_nonce",
    }
    attestation_members = {
        "iss", "sub", "aud", "exp", "iat", "jti", "profile_type", "profile_version",
        "appraisal_policy_id", "platform", "simulation", "binder_sha256",
        "evidence_sha256", "measurement_sha256",
    }
    require_members(grant, grant_members, "identity grant payload")
    require_members(proof, proof_members, "session binding payload")
    require_members(attestation, attestation_members, "attestation result payload")

    audience = sbo["aud"]
    actor = grant["sub"]
    check_equal("grant audience", grant["aud"], audience)
    check_equal("proof audience", proof["aud"], audience)
    check_equal("attestation audience", attestation["aud"], [audience])
    check_equal("grant agent", grant["agent"], actor)
    check_equal("proof issuer", proof["iss"], actor)
    check_equal("attestation subject", attestation["sub"], actor)
    check_equal("grant confirmation key", grant["cnf"], {"kid": fixture["public_keys"]["agent"]["kid"]})
    check_equal("grant task", grant["task_id"], message["taskId"])
    check_equal("grant thread", grant["thread_id"], message["contextId"])
    check_equal("grant target resource", grant["target_resource"], part["metadata"]["resource"])
    check_equal("grant resource", grant["resource"], part["metadata"]["resource"])
    check_equal("grant target operation", grant["target_operation"], part["metadata"]["operation"])

    for where, payload in (("grant", grant), ("proof", proof), ("attestation", attestation)):
        issued = require_int(payload["iat"], f"{where}.iat")
        expires = require_int(payload["exp"], f"{where}.exp")
        if issued > int(now.timestamp()) or expires <= int(now.timestamp()) or expires <= issued:
            raise FixtureError(f"{where} is outside its validity interval")
        require_string(payload["jti"], f"{where}.jti")
    check_equal("grant profile_type", grant["profile_type"], "sbaip.identity-grant")
    check_equal("grant profile_version", grant["profile_version"], "1")
    check_equal("proof profile_type", proof["profile_type"], "sbaip.session-binding")
    check_equal("proof profile_version", proof["profile_version"], "2")
    check_equal("attestation profile_type", attestation["profile_type"], "sbaip.attestation-result")
    check_equal("attestation profile_version", attestation["profile_version"], "2")
    check_equal("SBO iat", sbo["iat"], proof["iat"])
    check_equal("SBO exp", sbo["exp"], proof["exp"])
    check_equal("attestation binder", attestation["binder_sha256"], proof["attestation_binder_sha256"])
    if attestation["platform"] != "SIMULATED" or attestation["simulation"] is not True:
        raise FixtureError("fixture attestation must be marked as simulated")
    for name in ("evidence_sha256", "measurement_sha256"):
        require_sha256(attestation[name], f"attestation.{name}")


def validate_accepted_assertion(fixture, message, part, grant, proof, attestation, now):
    accepted = fixture["expected"]["accepted_assertion"]
    require_members(
        accepted,
        {
            "scope", "accepted_profile", "accepted_channel", "accepted_actor",
            "accepted_authority", "accepted_interaction", "accepted_target",
            "attestation_result", "replay_commit", "effective_authorization", "expiry",
        },
        "accepted_assertion",
    )
    check_equal(
        "accepted scope",
        accepted["scope"],
        {
            "audience": proof["aud"],
            "binding_context_sha256": proof["binding_context_sha256"],
        },
    )
    check_equal("accepted profile", accepted["accepted_profile"], fixture["verifier_inputs"]["accepted_profile"])
    check_equal(
        "accepted channel",
        accepted["accepted_channel"],
        {
            "endpoint_role": proof["endpoint_role"],
            "accepted_endpoint_spki_sha256": proof["accepted_endpoint_spki_sha256"],
            "tls_exporter_sha256": proof["tls_exporter_sha256"],
        },
    )
    check_equal("accepted actor", accepted["accepted_actor"], {"id": grant["sub"]})
    check_equal("accepted authority", accepted["accepted_authority"], {"issuer": grant["iss"]})
    check_equal(
        "accepted interaction",
        accepted["accepted_interaction"],
        {
            "type": proof["interaction_type"],
            "service": grant["service"],
            "deployment": grant["deployment"],
            "task_id": message["taskId"],
            "thread_id": message["contextId"],
            "intent_ref": grant["intent_ref"],
        },
    )
    check_equal(
        "accepted target",
        accepted["accepted_target"],
        {"resource": part["metadata"]["resource"], "operation": part["metadata"]["operation"]},
    )
    check_equal(
        "accepted attestation result",
        accepted["attestation_result"],
        {
            "profile_type": attestation["profile_type"],
            "profile_version": attestation["profile_version"],
            "subject": attestation["sub"],
            "appraisal_policy_id": attestation["appraisal_policy_id"],
        },
    )
    scopes = grant["scope"].split(" ")
    if any(not value for value in scopes):
        raise FixtureError("grant scope is not a canonical space-separated list")
    check_equal(
        "effective authorization",
        accepted["effective_authorization"],
        {
            "capability_ref": grant["capability_ref"],
            "scopes": scopes,
            "resources": [grant["resource"]],
        },
    )

    verifier = fixture["verifier_inputs"]
    challenge_expiry = parse_time(verifier["evidence_challenge_expires_at"], "challenge expiry")
    proof_expiry = datetime.datetime.fromtimestamp(proof["exp"], datetime.timezone.utc)
    grant_expiry = datetime.datetime.fromtimestamp(grant["exp"], datetime.timezone.utc)
    attestation_expiry = datetime.datetime.fromtimestamp(attestation["exp"], datetime.timezone.utc)
    endpoint_expiry = parse_time(verifier["endpoint_credential_expires_at"], "endpoint expiry")
    policy_expiry = parse_time(verifier["local_policy_expires_at"], "policy expiry")
    if min(challenge_expiry, proof_expiry, grant_expiry, attestation_expiry, endpoint_expiry, policy_expiry) <= now:
        raise FixtureError("an accepted freshness source is already expired")
    expected_expiry = min(
        challenge_expiry,
        proof_expiry,
        grant_expiry,
        attestation_expiry,
        endpoint_expiry,
        policy_expiry,
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    check_equal("accepted assertion expiry", accepted["expiry"], expected_expiry)
    check_equal(
        "replay commit",
        accepted["replay_commit"],
        {
            "state": "committed",
            "retain_until": max(challenge_expiry, proof_expiry).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
    )


def verify(path, openssl):
    if path.stat().st_size > MAX_FIXTURE_BYTES:
        raise FixtureError("fixture exceeds 1 MiB")
    fixture = load_json_bytes(path.read_bytes(), "fixture")
    validate_fixture_shape(fixture)
    now = parse_time(fixture["now"], "now")
    _, message, part = validate_http_and_body(fixture)

    metadata = message["metadata"]
    sbo = metadata[SECURITY_BINDING]
    require_members(
        sbo,
        {
            "sbo_type", "sbo_version", "aud", "jti", "iat", "exp", "mode",
            "identity_grant_format", "identity_grant", "identity_grant_sha256",
            "session_binding_format", "session_binding", "session_binding_sha256",
            "endpoint_role", "interaction_type", "accepted_endpoint_spki_sha256",
            "tls_exporter_sha256", "binding_context_sha256", "attestation_binder_sha256",
            "verifier_nonce", "attempt_id",
        },
        "Security Binding Object",
    )
    if (
        sbo["sbo_type"] != "sbaip.security-binding"
        or sbo["sbo_version"] != 2
        or sbo["aud"] != "agent-b"
        or sbo["mode"] != "identity-grant+jws-session-binding"
        or sbo["identity_grant_format"] != "jwt"
        or sbo["session_binding_format"] != "jwt"
        or sbo["endpoint_role"] != "client-tls-endpoint"
        or sbo["interaction_type"] != "agent-to-agent"
    ):
        raise FixtureError("Security Binding Object contract mismatch")
    for name in ("jti", "aud"):
        require_string(sbo[name], f"SBO.{name}")
    sbo_issued = require_int(sbo["iat"], "SBO.iat")
    sbo_expires = require_int(sbo["exp"], "SBO.exp")
    if sbo_issued > int(now.timestamp()) or sbo_expires <= int(now.timestamp()) or sbo_expires <= sbo_issued:
        raise FixtureError("Security Binding Object is outside its validity interval")

    public_keys = fixture["public_keys"]
    manager_spki = jwk_spki(public_keys["manager"], "manager JWK")
    agent_spki = jwk_spki(public_keys["agent"], "agent JWK")
    verifier_spki = jwk_spki(public_keys["attestation_verifier"], "attestation verifier JWK")
    if len({manager_spki, agent_spki, verifier_spki}) != 3:
        raise FixtureError("fixture signing keys must be distinct")
    if len({value["kid"] for value in public_keys.values()}) != 3:
        raise FixtureError("fixture signing key identifiers must be distinct")

    grant, grant_input, grant_signature = parse_compact_jws(
        sbo["identity_grant"], "identity grant JWS", "JWT", public_keys["manager"]
    )
    proof, proof_input, proof_signature = parse_compact_jws(
        sbo["session_binding"],
        "session binding JWS",
        "sbaip-session-binding+jwt",
        public_keys["agent"],
    )
    attestation_token = metadata[ATTESTATION_RESULT]
    attestation, attestation_input, attestation_signature = parse_compact_jws(
        attestation_token,
        "attestation result JWS",
        "JWT",
        public_keys["attestation_verifier"],
    )
    if openssl:
        verify_es256(openssl, "identity grant JWS", grant_input, grant_signature, public_keys["manager"])
        verify_es256(openssl, "session binding JWS", proof_input, proof_signature, public_keys["agent"])
        verify_es256(
            openssl,
            "attestation result JWS",
            attestation_input,
            attestation_signature,
            public_keys["attestation_verifier"],
        )

    validate_token_payloads(fixture, message, part, sbo, grant, proof, attestation, now)

    expected = fixture["expected"]
    grant_token = sbo["identity_grant"].encode("ascii")
    proof_token = sbo["session_binding"].encode("ascii")
    exact_grant_hash = sha256_label(grant_token)
    exact_proof_hash = sha256_label(proof_token)
    grant_hash = sha256_label(GRANT_HASH_DOMAIN + grant_token)
    check_equal("SBO identity grant SHA-256", sbo["identity_grant_sha256"], exact_grant_hash)
    check_equal("fixture identity grant SHA-256", expected["identity_grant_sha256"], exact_grant_hash)
    check_equal("SBO session binding SHA-256", sbo["session_binding_sha256"], exact_proof_hash)
    check_equal("fixture session binding SHA-256", expected["session_binding_sha256"], exact_proof_hash)
    check_equal("grant hash", proof["grant_hash"], grant_hash)
    check_equal("fixture grant hash", expected["grant_hash"], grant_hash)

    task_context, target_context = build_contexts(message, part)
    for name, value in (("task", task_context), ("target", target_context)):
        check_equal(
            f"{name} context bytes",
            b64url_encode(value),
            expected[f"{name}_context_base64url"],
        )
        check_equal(
            f"{name} context SHA-256",
            sha256_label(value),
            expected[f"{name}_context_sha256"],
        )

    inputs = fixture["binding_inputs"]
    endpoint_spki = b64url_decode(inputs["endpoint_spki_der_base64url"], "endpoint SPKI")
    tls_exporter = b64url_decode(inputs["tls_exporter_base64url"], "TLS exporter", exact_length=32)
    nonce = b64url_decode(inputs["verifier_nonce"], "verifier nonce", minimum_length=16)
    attempt_id = b64url_decode(inputs["attempt_id"], "attempt ID", minimum_length=1)
    check_equal("proof verifier nonce", proof["verifier_nonce"], inputs["verifier_nonce"])
    check_equal("proof attempt ID", proof["attempt_id"], inputs["attempt_id"])
    check_equal("SBO verifier nonce", sbo["verifier_nonce"], inputs["verifier_nonce"])
    check_equal("SBO attempt ID", sbo["attempt_id"], inputs["attempt_id"])
    check_equal("SBO endpoint role", sbo["endpoint_role"], proof["endpoint_role"])
    check_equal("SBO interaction type", sbo["interaction_type"], proof["interaction_type"])

    binding_context = CONTEXT_DOMAIN + b"".join(
        (
            field("endpoint_role", sbo["endpoint_role"].encode("utf-8")),
            field("interaction_type", sbo["interaction_type"].encode("utf-8")),
            field("protocol_id", fixture["verifier_inputs"]["accepted_profile"]["protocol_id"].encode("utf-8")),
            field("aud", sbo["aud"].encode("utf-8")),
            field("grant_hash", hashlib.sha256(GRANT_HASH_DOMAIN + grant_token).digest()),
            field("task_context", task_context),
            field("target_context", target_context),
            field("verifier_nonce", nonce),
            field("attempt_id", attempt_id),
        )
    )
    attestation_binder = ATTESTATION_DOMAIN + field("leaf_spki", endpoint_spki) + field("ekm", tls_exporter)
    derived = {
        "accepted_endpoint_spki_sha256": sha256_label(endpoint_spki),
        "tls_exporter_sha256": sha256_label(tls_exporter),
        "binding_context_sha256": sha256_label(binding_context),
        "attestation_binder_sha256": sha256_label(attestation_binder),
    }
    check_equal("binding context bytes", b64url_encode(binding_context), expected["binding_context_base64url"])
    for name, value in derived.items():
        require_sha256(expected[name], f"expected.{name}")
        check_equal(f"expected {name}", expected[name], value)
        check_equal(f"SBO {name}", sbo[name], value)
        check_equal(f"proof {name}", proof[name], value)
    report_data = hashlib.sha512(attestation_binder).digest()
    check_equal(
        "attestation report data",
        b64url_encode(report_data),
        expected["attestation_report_data_sha512_base64url"],
    )
    check_equal("attestation result binder", attestation["binder_sha256"], derived["attestation_binder_sha256"])

    challenge_expiry = parse_time(
        fixture["verifier_inputs"]["evidence_challenge_expires_at"],
        "evidence challenge expiry",
    )
    check_equal("proof/challenge expiry", proof["exp"], int(challenge_expiry.timestamp()))
    check_equal("SBO/challenge expiry", sbo["exp"], int(challenge_expiry.timestamp()))
    validate_accepted_assertion(fixture, message, part, grant, proof, attestation, now)


def main():
    parser = argparse.ArgumentParser(
        description="Independently verify the repository's draft06-v2 full-wire fixture."
    )
    parser.add_argument("fixture", type=Path)
    parser.add_argument(
        "--openssl",
        metavar="PATH",
        help="OpenSSL executable used to verify all three ES256 signatures",
    )
    parser.add_argument(
        "--skip-signatures",
        action="store_true",
        help="verify structure and hashes only; report that signatures were not checked",
    )
    args = parser.parse_args()
    if args.openssl and args.skip_signatures:
        parser.error("--openssl and --skip-signatures cannot be used together")
    openssl = args.openssl
    if not args.skip_signatures:
        openssl = openssl or shutil.which("openssl")
        if not openssl:
            parser.error("OpenSSL is required unless --skip-signatures is specified")
    try:
        verify(args.fixture, openssl)
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        FixtureError,
        subprocess.SubprocessError,
    ) as exc:
        print(f"verification failed: {exc}", file=sys.stderr)
        return 1
    suffix = "3 ES256 signatures checked" if openssl else "signatures not checked"
    print(f"verified draft06-v2 full-wire fixture ({suffix})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
