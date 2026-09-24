#!/usr/bin/env python3
"""Independently verify the Human outcome-recovery transcript vector.

The expected hashes are also pinned by Go's TestRecoveryDigestVector.
No Go encoder or generated transcript bytes are used here.
"""

import hashlib
import struct


def field(name: str, value: bytes) -> bytes:
    label = name.encode("utf-8")
    return struct.pack(">H", len(label)) + label + struct.pack(">I", len(value)) + value


def main() -> None:
    original = bytes.fromhex(
        "88a80a9ce13faca8b0f1aa49484880449228766739439202907a3bf08117723a"
    )
    transcript = (
        b"ASB-TASKCOORD-HUMAN-REQUEST-v1\x00"
        + field("request_kind", b"OPERATION_RECOVER")
        + field("participant_id", b"human:alice")
        + field("operation_id", b"event:accept:1")
        + field("request_digest", original)
    )
    digest = hashlib.sha256(transcript).digest()
    expected = "fd1ae41106783df5316952a99dce80ee6e5c60def4fab0eac2eccb352c96b6df"
    if digest.hex() != expected or digest == original:
        raise SystemExit("Human recovery request digest mismatch")
    context = b"ASB-TASKCOORD-HUMAN-CONTEXT-v1\x00" + field("request_digest", digest)
    expected_context = "1feb5e15ed482ccedc812e22015f5b503835314572f1183355a97249dc575b26"
    if hashlib.sha256(context).hexdigest() != expected_context:
        raise SystemExit("Human recovery context digest mismatch")
    print("Human recovery transcript and context: 2 checks passed")


if __name__ == "__main__":
    main()
