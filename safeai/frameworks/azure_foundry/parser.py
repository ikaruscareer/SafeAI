"""Azure AI Foundry configuration adapter.

Detects Azure AI Foundry projects via YAML config files containing
``azure`` keyword and dependency metadata. Extracts tools, models,
workflow names from YAML structure and infers cloud service capability.
"""

import yaml
from safeai.analysis.capabilities import make_capability


class AzureFoundryParser:
    name = "azure_foundry"

    def detect(self, path, content, scan_ctx=None):
        if path.endswith((".yaml", ".yml")) and "azure" in content.lower():
            return True
        if scan_ctx:
            deps = scan_ctx.get("dependencies", set())
            if "azure-ai-projects" in deps or "azure-ai-agents" in deps:
                return path.endswith(".py") and "azure" in content.lower()
        return False

    def parse(self, path, content, scan_ctx=None):
        try:
            data = yaml.safe_load(content)
        except Exception:
            return {}
        if not isinstance(data, dict):
            return {"framework": "azure_foundry", "keys": []}

        tools = data.get("tools") or data.get("actions") or []
        models = []
        for key in ["model", "models", "llm", "deployment"]:
            if key in data:
                value = data[key]
                if isinstance(value, list):
                    models.extend(value)
                else:
                    models.append(value)

        capabilities = [
            make_capability("cloud_service", "Cloud", self.name, "azure yaml config", confidence=0.95, risk_weight=1.2, source="configuration")
        ]

        return {
            "framework": "azure_foundry",
            "keys": list(data.keys()),
            "tools": [{"name": str(t), "evidence": "yaml.tools"} for t in (tools if isinstance(tools, list) else [str(tools)])],
            "models": [{"name": str(m), "evidence": "yaml.models"} for m in models],
            "workflows": [{"name": str(data.get("name", "azure_workflow")), "evidence": "yaml.name"}],
            "relationships": [{"from": str(data.get("name", "azure_workflow")), "to": "tools", "type": "uses", "framework": self.name, "evidence": "yaml.tools"}],
            "capabilities": capabilities,
            "discovery_method": "configuration",
            "parser_confidence": 0.84,
            "detection_evidence": ["yaml:azure", "dependencies"],
        }
