"""SARIF 2.1.0 report writer.

Converts SafeAI findings into the SARIF format compatible with
GitHub Advanced Security, Azure DevOps, and other SARIF consumers.
Each finding becomes a SARIF result with OWASP LLM attribution
and SafeAI-specific properties (risk category, confidence,
remediation, etc.).
"""

import json


def write_sarif(report, path):
    sarif = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "safeai"}},
                "results": [
                    {
                        "ruleId": f["rule_id"],
                        "message": {"text": f["message"]},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": f["file"]},
                                    "region": {"startLine": f["line"]},
                                }
                            }
                        ],
                        "properties": {"owasp_llm": f.get("owasp_llm")},
                    }
                    for f in report["findings"]
                ],
            }
        ],
    }

    for result, finding in zip(sarif["runs"][0]["results"], report["findings"]):
        props = result.setdefault("properties", {})
        for key in [
            "risk_category",
            "affected_framework",
            "affected_capability",
            "score_contribution",
            "confidence",
            "resolved_definition",
            "schema_version",
            "validation_rule",
            "affected_object",
        ]:
            if key in finding:
                props[key] = finding.get(key)
        if finding.get("evidence"):
            props["evidence"] = finding.get("evidence")
        if finding.get("reason"):
            props["reason"] = finding.get("reason")
        if finding.get("remediation"):
            props["remediation"] = finding.get("remediation")

    with open(path, "w") as fh:
        json.dump(sarif, fh, indent=2)
