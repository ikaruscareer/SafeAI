"""Know Your Agent (KYA) — local, offline, static-evidence registry support.

This package implements Release 1.3: canonical scan manifests, stable
finding fingerprints, baseline comparison, suppressions, policy-as-code,
and a local SQLite registry of scan-derived agent records.

All data produced here is *static analysis evidence* only. Nothing in
this package verifies deployed runtime permissions, live identities,
executed tool calls, or production behavior.
"""

MANIFEST_SCHEMA_VERSION = "1.2"
MANIFEST_TYPE = "safeai.kya"
REGISTRY_SCHEMA_VERSION = 4

STATIC_ANALYSIS_DISCLAIMER = (
    "SafeAI results are static analysis evidence and do not verify "
    "deployed runtime permissions, identities, or behavior."
)
