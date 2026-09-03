"""Pre-release checklist verification."""
import sys
import yaml


def main():
    tag_version = "2.0.1"

    # Check version matches tag
    from safeai.version import SAFEAI_VERSION
    if tag_version != SAFEAI_VERSION:
        print(f"FAIL: Tag version ({tag_version}) != code version ({SAFEAI_VERSION})")
        return 1
    print(f"Version match: {SAFEAI_VERSION}")

    # Check all rules have required fields
    with open("safeai/rules/base_rules.yaml") as f:
        rules = yaml.safe_load(f)
    required = {"id", "severity", "description"}
    bad = [r for r in rules if not required.issubset(r.keys())]
    if bad:
        for r in bad:
            print(f"Missing fields in rule: {r.get('id', 'UNKNOWN')}")
        return 1
    print(f"All {len(rules)} rules have required fields")

    # Check CHANGELOG
    with open("CHANGELOG.md") as f:
        changelog = f.read()
    if f"[{tag_version}]" not in changelog:
        print(f"CHANGELOG.md has no entry for v{tag_version}")
        return 1
    print(f"CHANGELOG entry found for v{tag_version}")

    # Check Action I/O contract
    with open("action.yml") as f:
        action = yaml.safe_load(f)
    expected_inputs = {
        "path", "version", "fail-on", "sarif", "rules", "baseline",
        "fail-on-new", "fail-on-escalation", "no-registry", "extra-args",
        "scorecard", "scorecard-json", "scorecard-summary", "scorecard-fail-under",
    }
    expected_outputs = {"sarif-path", "scorecard-path", "safeai-version"}
    missing_i = expected_inputs - set(action["inputs"].keys())
    missing_o = expected_outputs - set(action["outputs"].keys())
    if missing_i:
        print(f"Missing Action inputs: {missing_i}")
        return 1
    if missing_o:
        print(f"Missing Action outputs: {missing_o}")
        return 1
    print(f"Action I/O contract stable")

    print("\nAll pre-release checks passed!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
