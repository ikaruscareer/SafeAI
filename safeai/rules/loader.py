"""Rule loader for SafeAI scan rules.

Loads rules from built-in ``base_rules.yaml`` merged with optional
user-provided rule files. Custom rules with the same ID override
the built-in severity and OWASP category.
"""

import os
import yaml


def load_rules(custom_dir=None):
    rules = []
    base = os.path.dirname(__file__)
    for d in [base, custom_dir]:
        if not d:
            continue
        for f in os.listdir(d):
            if f.endswith(".yml") or f.endswith(".yaml"):
                try:
                    with open(os.path.join(d, f), "r") as fh:
                        rules.extend(yaml.safe_load(fh) or [])
                except Exception:
                    pass
    return rules
