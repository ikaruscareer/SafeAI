# HTML Score: Developer Hint

When reading an HTML SafeAI report, do not interpret `Overall AI Risk Score` as a percentage risk or as the number of vulnerabilities found.

Review the individual findings first. A repository can have one high finding and still display a value near 100 because the aggregate combines weighted category scores and unaffected categories may contribute clean values.

Use this checklist:

- Read all critical and high findings.
- Check each finding's rule ID, location, evidence, confidence, and remediation.
- Review new, regressed, and capability-escalation findings.
- Check whether secrets or sensitive evidence were withheld.
- Read the coverage and assurance-boundary sections.
- Treat the aggregate score as a triage signal only.

SafeAI findings are automated static-analysis observations. They require maintainer validation and do not prove exploitability or runtime security.