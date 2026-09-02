"""Environment and credential dependency inventory analyzer.

Scans source and configuration for *references* to external configuration:
environment variables, ``.env`` files, secret-manager lookups, Kubernetes
Secrets, and cloud vault providers.

Critical constraint — **names and sources only, never values.** SafeAI records
that an agent depends on ``DATABASE_URL`` (``os.getenv("DATABASE_URL")`` at
``app.py:12``), not any value it could hold. This keeps the inventory useful
for correlation while preserving the project's existing source-private,
no-raw-secret guarantee.

The analyzer emits one carrying finding (``ENV_DEP_INVENTORY``) that
orchestration uses to attach the inventory to the report, mirroring the
MCP ``MCP_ASSETS_DISCOVERED`` pattern. No inventory entry ever contains a
user-facing value.
"""

import re

INVENTORY_RULE_ID = "ENV_DEP_INVENTORY"

#: Python ``os.getenv(...)`` / ``os.environ[...]`` / ``os.environ.get(...)``.
_OS_GETENV_RE = re.compile(
    r"\bos\.(?:environ\.get|getenv)\s*\(\s*[\"']([A-Za-z_][A-Za-z0-9_.-]*)[\"']",
    re.IGNORECASE,
)
_OS_ENVIRON_RE = re.compile(
    r"\bos\.environ\s*\[\s*[\"']([A-Za-z_][A-Za-z0-9_.-]*)[\"']\s*\]",
    re.IGNORECASE,
)

#: Node ``process.env.X`` references.
_PROCESS_ENV_RE = re.compile(
    r"\bprocess\.env(?:\.([A-Za-z_][A-Za-z0-9_]*)|\[\s*[\"']([A-Za-z_][A-Za-z0-9_.-]*)[\"']\s*\])"
)

#: Shell ``${VAR}`` / ``$VAR`` interpolation.
_SHELL_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$(?![0-9])([A-Za-z_][A-Za-z0-9_]*)")

#: Jinja / dot-template ``{{ env('X') }}``.
_JINJA_ENV_RE = re.compile(r"\{\{\s*env\s*\(\s*['\"]([A-Za-z_][A-Za-z0-9_.-]*)['\"]\s*\)\s*\}\}")

#: ``.env``-style ``KEY=value`` lines.
_DOTENV_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*=")

#: AWS Secrets Manager ``get_secret_value(SecretId="...")``.
_AWS_SECRET_RE = re.compile(
    r"\b(?:get_secret_value|GetSecretValue)\s*\(\s*['\"]?([A-Za-z_][A-Za-z0-9_\-/.]*)['\"]?",
    re.IGNORECASE,
)

#: Azure Key Vault ``SecretClient(...)`` / ``get_secret("...")``.
_AZURE_VAULT_RE = re.compile(
    r"\b(?:SecretClient|get_secret)\s*\([^)]*?['\"]?([A-Za-z_][A-Za-z0-9_\-/.]*)['\"]?",
    re.IGNORECASE,
)

#: GCP Secret Manager.
_GCP_SECRET_RE = re.compile(
    r"\b(?:secretmanager|access_secret_version)\b[^\"']*[\"']([A-Za-z0-9_\-/.]{3,})[\"']",
    re.IGNORECASE,
)

#: HashiCorp Vault reads.
_VAULT_RE = re.compile(
    r"\b(?:vault\.read|hvac\.|\.read_secret)\s*\([^)]*?[\"']([A-Za-z_][A-Za-z0-9_\-/.]*)[\"']",
    re.IGNORECASE,
)

#: Kubernetes ``secretKeyRef.name`` / ``secretRef.name`` in manifests
#: (brace or same-line block form; multi-line YAML is handled by the name
#: keyword heuristics via ``mark_secret_name``).
_K8S_SECRET_RE = re.compile(
    r"\b(?:secretKeyRef|secretRef)\s*:\s*(?:\{[^}]*?\bname\s*:\s*([A-Za-z_][A-Za-z0-9_\-.]*)|\s*([A-Za-z_][A-Za-z0-9_\-.]*))",
    re.IGNORECASE,
)

#: Secret-ish name keywords used to flag an entry as credential-backed even
#: when it comes from an env var (e.g. ``AWS_SECRET_ACCESS_KEY``).
_SECRET_NAME_TOKENS = ("secret", "token", "password", "_key", "credential", "passwd", "api_key")


def _is_secret_name(name):
    low = str(name or "").lower()
    return any(tok in low for tok in _SECRET_NAME_TOKENS)

#: Files whose path or name marks them as dotenv-style load points.
DOTENV_MARKERS = (".env", "dotenv", "create_env", "load_env")


def analyze_file_inventory(path, content):
    """Collect credential/config names referenced in a single file.

    Returns a list of dicts ``{"name", "detector", "line"}``. Only the name
    and location are captured; no value is ever returned.
    """
    refs = []
    is_dotenv = any(m in str(path).replace("\\", "/").lower() for m in DOTENV_MARKERS)

    for i, line in enumerate(content.splitlines(), 1):
        for match in _OS_GETENV_RE.finditer(line):
            refs.append({"name": match.group(1), "detector": "os.getenv", "line": i})
        for match in _OS_ENVIRON_RE.finditer(line):
            refs.append({"name": match.group(1), "detector": "os.environ", "line": i})
        for match in _PROCESS_ENV_RE.finditer(line):
            name = match.group(1) or match.group(2)
            if name:
                refs.append({"name": name, "detector": "process.env", "line": i})
        for match in _SHELL_VAR_RE.finditer(line):
            name = match.group(1) or match.group(2)
            if name:
                refs.append({"name": name, "detector": "shell", "line": i})
        for match in _JINJA_ENV_RE.finditer(line):
            refs.append({"name": match.group(1), "detector": "template", "line": i})
        for match in _AWS_SECRET_RE.finditer(line):
            name = match.group(1)
            if name and len(name) >= 2:
                refs.append({"name": name, "detector": "aws_secrets", "line": i})
        for match in _AZURE_VAULT_RE.finditer(line):
            name = match.group(1)
            if name and len(name) >= 2:
                refs.append({"name": name, "detector": "azure_keyvault", "line": i})
        for match in _GCP_SECRET_RE.finditer(line):
            refs.append({"name": match.group(1), "detector": "gcp_secret", "line": i})
        for match in _VAULT_RE.finditer(line):
            refs.append({"name": match.group(1), "detector": "vault", "line": i})
        for match in _K8S_SECRET_RE.finditer(line):
            name = match.group(1) or match.group(2)
            if name:
                refs.append({"name": name, "detector": "k8s_secret", "line": i})

        # .env style lines: record only the key.
        if is_dotenv:
            dotenv = _DOTENV_RE.match(line)
            if dotenv:
                key = dotenv.group(1)
                if key:
                    refs.append({"name": key, "detector": "dotenv", "line": i})

    return refs


class EnvDependencyAnalyzer:
    """Detects references to external configuration and credentials."""

    name = "env_dependency"

    def run(self, file_cache, rules, agent_models=None):
        """Return a carrying ``ENV_DEP_INVENTORY`` finding with the inventory.

        Entries dedupe by name across files; each carries its source
        locations. Secret-manager-backed names are flagged ``secret=True``
        for the correlation step.
        """
        by_name = {}

        for path, content in file_cache.items():
            for ref in analyze_file_inventory(path, content):
                name = ref["name"]
                if not name:
                    continue
                entry = by_name.get(name)
                if entry is None:
                    entry = {"name": name, "sources": []}
                    by_name[name] = entry
                source = {"file": path, "line": ref["line"], "detector": ref["detector"]}
                if source not in entry["sources"]:
                    entry["sources"].append(source)

        inventory = []
        secret_detectors = {"aws_secrets", "azure_keyvault", "gcp_secret", "vault", "k8s_secret"}
        for name in sorted(by_name):
            entry = by_name[name]
            detectors = {s["detector"] for s in entry["sources"]}
            entry["secret"] = bool(detectors & secret_detectors) or _is_secret_name(name)
            entry["source_count"] = len(entry["sources"])
            entry["sources"] = sorted(entry["sources"], key=lambda s: (s["file"], s["line"]))
            inventory.append(entry)

        return _wrap_inventory(inventory, rules)


def _wrap_inventory(inventory, rules):
    rule_map = {r.get("id"): r for r in (rules or [])}
    rule = rule_map.get(INVENTORY_RULE_ID, {})
    return [{
        "rule_id": INVENTORY_RULE_ID,
        "evidence_type": "static-config",  # #94 - inventories declared config references, names only
        "severity": rule.get("severity", "info"),
        "message": f"Referenced {len(inventory)} external configuration/credential names",
        "file": "<scan>",
        "line": 1,
        "owasp_llm": rule.get("owasp_llm", "LLM02"),
        "evidence": f"env-dependency inventory size={len(inventory)}",
        "reason": "Credential and config inventory gathered for dependency-to-capability correlation.",
        "risk_category": "Identity",
        "affected_framework": "generic",
        "affected_capability": "Environment",
        "score_contribution": 0,
        "remediation": "Confirm each referenced configuration/credential maps to a declared tool or capability; revise orphaned tools.",
        "dep_inventory": inventory,
    }]
