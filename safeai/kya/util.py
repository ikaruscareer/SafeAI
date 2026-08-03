"""Shared helpers for KYA modules: hashing, timestamps, and redaction.

Everything here is deterministic and offline. No network access, no
randomness except where explicitly documented (scan IDs).
"""

import hashlib
import re
import uuid
from datetime import UTC, datetime

# Generic credential-looking assignments used to redact secret values
# before evidence is persisted to manifests or the registry. Mirrors the
# spirit of ``analyzers.data_leakage.mask_secret_evidence`` but operates
# on arbitrary text, not only single source lines.
_SECRET_VALUE_RE = re.compile(
    r"((?:api[_-]?key|token|password|passwd|secret|credential)[\"']?\s*[:=]\s*[\"']?)([^\s\"',}]{4,})",
    re.IGNORECASE,
)

# Long opaque tokens commonly seen in keys (e.g. sk-..., ghp_..., xoxb-...).
_OPAQUE_TOKEN_RE = re.compile(r"\b(sk-[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9]{8,}|xox[baprs]-[A-Za-z0-9-]{8,}|AKIA[0-9A-Z]{12,})\b")

# URL userinfo credentials, e.g. ``https://user:pass@example.com``.
_URL_USERINFO_RE = re.compile(r"\b([a-z][a-z0-9+.-]*://)([^\s/@:]+):([^\s/@]+)@", re.IGNORECASE)

# CLI credential pair patterns such as ``-u user:pass`` or
# ``--user user:pass``.
_CLI_USERPASS_RE = re.compile(r"(\s(?:-u|--user)\s+)([^\s:]+):([^\s]+)", re.IGNORECASE)


def sha256_text(text):
    """Return the hex SHA-256 digest of ``text`` (UTF-8)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def utc_now_iso():
    """Return the current UTC time as an ISO-8601 string with ``Z`` suffix."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_scan_id():
    """Return a unique scan identifier.

    Scan IDs are allowed to be unique per run (they identify an event,
    not an artifact). Agent and finding identities never use this value.
    """
    return str(uuid.uuid4())


def redact_secrets(text, full_mask=False):
    """Mask credential values in arbitrary text.

    Display mode (default) keeps at most the first four characters of a
    detected secret value for identification. ``full_mask=True`` removes
    the value entirely — used where stability across secret rotation
    matters (fingerprints). Applied before evidence is written to
    manifests, exports, or the local registry; raw secret values are
    never persisted.
    """
    if not text or not isinstance(text, str):
        return text

    def _assignment_repl(match):
        value = match.group(2)
        kept = "" if full_mask else value[:4]
        return f"{match.group(1)}{kept}***MASKED***"

    def _opaque_repl(match):
        token = match.group(1)
        kept = "" if full_mask else token[:4]
        return f"{kept}***MASKED***"

    def _url_userinfo_repl(match):
        scheme = match.group(1)
        user = match.group(2)
        user_kept = "" if full_mask else user[:2]
        return f"{scheme}{user_kept}***MASKED***:***MASKED***@"

    def _cli_userpass_repl(match):
        prefix = match.group(1)
        user = match.group(2)
        user_kept = "" if full_mask else user[:2]
        return f"{prefix}{user_kept}***MASKED***:***MASKED***"

    redacted = _SECRET_VALUE_RE.sub(_assignment_repl, text)
    redacted = _OPAQUE_TOKEN_RE.sub(_opaque_repl, redacted)
    redacted = _URL_USERINFO_RE.sub(_url_userinfo_repl, redacted)
    return _CLI_USERPASS_RE.sub(_cli_userpass_repl, redacted)


def normalize_evidence(text):
    """Normalize evidence text for fingerprinting.

    Collapses all whitespace runs to single spaces, strips ends, and
    redacts secrets so that harmless formatting changes do not alter
    derived fingerprints and no secret material feeds the hash.
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    collapsed = re.sub(r"\s+", " ", text).strip()
    return redact_secrets(collapsed, full_mask=True)


def confidence_label(value, default="medium"):
    """Map a confidence value to the canonical ``high|medium|low`` label.

    Accepts existing labels (passed through), numeric confidences in
    ``[0.0, 1.0]`` (``>=0.8`` high, ``>=0.5`` medium, else low), and
    ``None`` (returns ``default``).
    """
    if value is None:
        return default
    if isinstance(value, str):
        label = value.strip().lower()
        if label in {"high", "medium", "low"}:
            return label
        return default
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return default
    if numeric >= 0.8:
        return "high"
    if numeric >= 0.5:
        return "medium"
    return "low"
