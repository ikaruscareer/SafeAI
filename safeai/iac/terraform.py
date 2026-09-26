"""Terraform authority extraction (v2.5 IaC evidence, Lane B).

Parses in-repo ``*.tf`` files with a stdlib-only brace-block scanner
(no HCL dependency — see ADR-0006) and emits **Grant triples**::

    (principal, action-pattern, resource-pattern, source_ref)

Extractable: ``aws_iam_policy`` / ``aws_iam_role_policy`` documents
(actions/resources), ``aws_iam_role`` names, policy attachments
(``aws_iam_policy_attachment``, ``aws_iam_role_policy_attachment``),
and ``aws_iam_policy_document`` data blocks.

Fidelity ceiling (documented honestly, enforced in code): variable
interpolation (``${...}``), ``for_each``/``dynamic``/``count``,
``jsonencode(``/``file(``/``templatefile(`` payloads, and modules are
**not resolved** — affected grants carry
``provenance="partially-resolved"`` with ``fidelity_notes``. Repository
IaC is evidence of declared grants, never proof of deployed permission.
"""

import re

#: Terraform resource types we extract authority from.
_IAM_POLICY_TYPES = {
    "aws_iam_policy",
    "aws_iam_role_policy",
    "aws_iam_policy_document",
}

_IAM_ROLE_TYPES = {
    "aws_iam_role",
}

_IAM_ATTACHMENT_TYPES = {
    "aws_iam_policy_attachment",
    "aws_iam_role_policy_attachment",
}

_WATCHED_TYPES = _IAM_POLICY_TYPES | _IAM_ROLE_TYPES | _IAM_ATTACHMENT_TYPES

#: Markers that force partially-resolved provenance.
_UNRESOLVED_MARKERS = ("${", "for_each", "dynamic", "count", "jsonencode(",
                       "file(", "templatefile(")

#: String-list statements inside policy documents. The optional closing
#: quote covers JSON-style keys (``"Action" = [...]``) as well as HCL
#: bare keys (``actions = [...]``); ``:`` covers JSON payloads embedded
#: as strings (``"Action": [...]``). Matching is case-insensitive.
_STATEMENT_RES = (
    re.compile(r'''(?i)\bactions?"?\s*[:=]\s*\[(?P<body>[^\]]*)\]'''),
    re.compile(r'''(?i)\bresources?"?\s*[:=]\s*\[(?P<body>[^\]]*)\]'''),
)

_QUOTED = re.compile(r'''"([^"\\]*(?:\\.[^"\\]*)*)"''')

_NAME_RES = (
    re.compile(r'''(?i)\bname\s*=\s*"([^"]+)"'''),
    re.compile(r'''(?i)\brole\s*=\s*(?P<ref>[^\s,\n\]]+)'''),
    re.compile(r'''(?i)\broles\s*=\s*\[(?P<body>[^\]]*)\]'''),
    re.compile(r'''(?i)\bpolicy_arn\s*=\s*(?P<ref>[^\s,\n\]]+)'''),
)

_MAX_BLOCK_DEPTH = 32


def _strip_comments(text):
    """Remove ``#`` and ``//`` comments outside quoted strings."""
    out = []
    in_str = False
    escaped = False
    i = 0
    while i < len(text):
        ch = text[i]
        if in_str:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if ch == "#" or (ch == "/" and i + 1 < len(text) and text[i + 1] == "/"):
            while i < len(text) and text[i] != "\n":
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _iter_blocks(text):
    """Yield ``(kind, type, name, body, start_line)`` for top-level blocks.

    ``kind`` is ``resource`` or ``data``; ``type``/``name`` are the quoted
    labels. Brace matching is depth-capped; unbalanced input ends the
    scan (fail-closed: unparseable tail is skipped, never guessed).
    """
    header = re.compile(
        r'''(?m)^\s*(?P<kind>resource|data)\s+\"(?P<type>[^\"]+)\"\s+\"(?P<name>[^\"]+)\"\s*\{''')
    for match in header.finditer(text):
        depth = 1
        i = match.end()
        in_str = False
        escaped = False
        exceeded = False
        while i < len(text) and depth > 0:
            ch = text[i]
            if in_str:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_str = False
            elif ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
                if depth > _MAX_BLOCK_DEPTH:
                    exceeded = True
                    break
            elif ch == "}":
                depth -= 1
            i += 1
        if exceeded or depth != 0:
            continue
        body = text[match.end():i - 1]
        start_line = text.count("\n", 0, match.start()) + 1
        yield (match.group("kind"), match.group("type"),
               match.group("name"), body, start_line)


def _line_of(block_text, pos, base_line):
    """Best-effort 1-indexed line of ``pos`` within a block body."""
    return base_line + block_text.count("\n", 0, pos)


def _quoted_list(body):
    """All double-quoted strings inside a bracket body."""
    return _QUOTED.findall(body)


def _fidelity(body):
    """Return (provenance, notes) for a block body."""
    notes = sorted({m.rstrip("(") for m in _UNRESOLVED_MARKERS if m in body})
    if notes:
        return "partially-resolved", [f"unresolved:{n}" for n in notes]
    return "repo-iac-observed", []


def parse_terraform_file(rel_path, text):
    """Extract Grant dicts from one Terraform file's text.

    ``rel_path`` is the root-relative forward-slash path used in all
    evidence refs. Never raises: unparseable content yields zero grants.
    """
    grants = []
    try:
        clean = _strip_comments(text)
    except Exception:
        return grants
    try:
        blocks = list(_iter_blocks(clean))
    except Exception:
        return grants

    roles = {}
    for _kind, rtype, name, body, _line in blocks:
        if rtype in _IAM_ROLE_TYPES:
            roles[name] = name

    for kind, rtype, name, body, start_line in blocks:
        if rtype not in _WATCHED_TYPES:
            continue
        provenance, notes = _fidelity(body)
        if rtype in _IAM_POLICY_TYPES:
            actions, resources = [], []
            action_pos, resource_pos = None, None
            # Prefer the declared AWS object name over the Terraform
            # resource label — it is what linkage matches against.
            display = name
            name_match = _NAME_RES[0].search(body)
            if name_match:
                display = name_match.group(1)
            # JSON documents embedded as HCL strings carry backslash-
            # escaped quotes (\"Action\": ...). De-escape for statement
            # search only: newline counts are unchanged, so line numbers
            # computed from these positions stay correct.
            scan = body.replace('\\"', '"')
            for pattern, slot in ((_STATEMENT_RES[0], "a"), (_STATEMENT_RES[1], "r")):
                for match in pattern.finditer(scan):
                    quoted = _quoted_list(match.group("body"))
                    if slot == "a":
                        actions.extend(quoted)
                        if action_pos is None:
                            action_pos = match.start()
                    else:
                        resources.extend(quoted)
                        if resource_pos is None:
                            resource_pos = match.start()
            if not actions and not resources:
                continue
            stmt_line = _line_of(
                scan, action_pos if action_pos is not None else resource_pos,
                start_line)
            grants.append({
                "principal": display,
                "action": ",".join(actions) if actions else "*",
                "resource": ",".join(resources) if resources else "*",
                "source": "terraform",
                "source_file": rel_path,
                "line": stmt_line,
                "provenance": provenance,
                "fidelity_notes": notes,
                "family": "cloud",
            })
        elif rtype in _IAM_ATTACHMENT_TYPES:
            attached_roles = []
            for match in _NAME_RES[2].finditer(body):
                attached_roles.extend(_quoted_list(match.group("body")))
            for match in _NAME_RES[1].finditer(body):
                ref = match.group("ref").strip().strip('"')
                if ref and ref not in attached_roles:
                    attached_roles.append(ref)
            if not attached_roles:
                attached_roles = ["<unattached>"]
                if "unattached-policy" not in notes:
                    notes = notes + ["unattached-policy"]
                    provenance = "partially-resolved"
            for role in attached_roles:
                grants.append({
                    "principal": role,
                    "action": "attached-policy",
                    "resource": name,
                    "source": "terraform",
                    "source_file": rel_path,
                    "line": start_line,
                    "provenance": provenance,
                    "fidelity_notes": notes,
                    "family": "cloud",
                })
    return grants
