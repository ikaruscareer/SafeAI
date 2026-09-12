"""Offline manifest/inventory integrity — artifact integrity, nothing more.

A generated document carries an ``integrity`` block with a SHA-256 digest
over a canonical payload. Verification recomputes the digest locally: no
network, no keys, no execution. This detects *post-generation edits*; it
does not prove source authenticity, developer identity, runtime truth, or
deployment attestation. Detached-signature workflows (GPG) are documented
in ``docs/manifest/INTEGRITY.md`` as an external CI/release step — this
module implements hash integrity only, using the standard library.

Canonicalization ``safeai-manifest-v1`` (exact):
  * UTF-8 JSON, ``sort_keys=True``, separators ``(",", ":")``.
  * The ``integrity`` block itself is excluded (avoids recursion).
  * Volatile, non-semantic fields are excluded: top-level
    ``generated_at``; ``scan.scan_id``, ``scan.started_at``,
    ``scan.completed_at``.
  * Everything else — including findings, agents, policy decision,
    assurance boundary — is covered. Changing any semantic field changes
    the digest.
"""

from __future__ import annotations

import copy
import hashlib
import json

from safeai.kya.contract import COMPATIBLE_SCHEMA_VERSIONS

ALGORITHM = "sha256"
CANONICALIZATION = "safeai-manifest-v1"

_VOLATILE_TOP = ("generated_at",)
_VOLATILE_SCAN = ("scan_id", "started_at", "completed_at")

NO_INTEGRITY = "no-integrity"
MISMATCH = "mismatch"
OK = "ok"
UNSUPPORTED_CANONICALIZATION = "unsupported-canonicalization"
UNSUPPORTED_VERSION = "unsupported-version"
MALFORMED_BLOCK = "malformed-block"


def canonical_payload(document):
    """Return the canonical bytes covered by the integrity digest."""
    payload = copy.deepcopy(document)
    payload.pop("integrity", None)
    for key in _VOLATILE_TOP:
        payload.pop(key, None)
    scan = payload.get("scan")
    if isinstance(scan, dict):
        for key in _VOLATILE_SCAN:
            scan.pop(key, None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      default=str).encode("utf-8")


def payload_digest(document):
    """Return the hex SHA-256 digest of the canonical payload."""
    return hashlib.sha256(canonical_payload(document)).hexdigest()


def stamp_integrity(document):
    """Attach a fresh ``integrity`` block to a generated document.

    ``verified`` is always ``False`` at generation time: it may only
    reflect the result of a local verification action, never a proof claim.
    """
    document["integrity"] = {
        "algorithm": ALGORITHM,
        "canonicalization": CANONICALIZATION,
        "payload_sha256": payload_digest(document),
        "verified": False,
    }
    return document


def verify_document(document):
    """Verify a loaded document. Returns ``(status, detail)``.

    ``status`` is one of ``ok``, ``mismatch``, ``no-integrity``,
    ``unsupported-canonicalization``, ``unsupported-version``,
    ``malformed-block``. ``detail`` never contains document values, so
    failures cannot leak redacted content. Note: a mismatch cannot name
    the changed section — only the whole-payload digest is stored — so
    the detail says exactly that.
    """
    if not isinstance(document, dict):
        return (MALFORMED_BLOCK, "root must be a JSON object")
    schema_version = document.get("schema_version")
    if schema_version not in COMPATIBLE_SCHEMA_VERSIONS:
        return (UNSUPPORTED_VERSION,
                f"schema_version {schema_version!r} is not supported by this reader")
    block = document.get("integrity")
    if block is None:
        return (NO_INTEGRITY,
                ("no integrity block: generated before integrity support "
                 "or integrity stripped (still importable by default)"))
    if not isinstance(block, dict):
        return (MALFORMED_BLOCK, "integrity must be an object")
    if block.get("algorithm") != ALGORITHM:
        return (MALFORMED_BLOCK,
                f"integrity.algorithm must be {ALGORITHM!r}")
    if block.get("canonicalization") != CANONICALIZATION:
        return (UNSUPPORTED_CANONICALIZATION,
                f"canonicalization {block.get('canonicalization')!r} is not supported")
    expected = block.get("payload_sha256") or ""
    if not (isinstance(expected, str) and len(expected) == 64
            and all(c in "0123456789abcdef" for c in expected)):
        return (MALFORMED_BLOCK, "integrity.payload_sha256 must be 64 hex characters")
    actual = payload_digest(document)
    if actual != expected:
        return (MISMATCH, ("content changed after generation "
                "(which section changed is not recorded; re-generate to compare)"))
    return (OK, f"sha256:{actual}")


def verify_manifest_file(path):
    """Verify a manifest file on disk. Prints one line, returns exit code."""
    try:
        with open(path, encoding="utf-8") as fh:
            document = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: unable to read {path}: {exc}")
        return 1
    status, detail = verify_document(document)
    if status == OK:
        print(f"verified: {path} ({detail})")
        return 0
    print(f"{status}: {path} ({detail})")
    return 1
