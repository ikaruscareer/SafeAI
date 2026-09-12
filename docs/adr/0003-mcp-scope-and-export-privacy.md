# ADR 0003 — MCP scope and export privacy

- Status: accepted
- Date: 2026-09-12
- Context: MCP and IDE configuration increasingly lives outside the
  scanned repository (user/global scopes). Ingesting it silently into
  portable artifacts would leak personal configuration into CI systems.
- Decision: repository-local scanning is the default; user/global scopes
  are opt-in (`--mcp-ide-scopes` and explicit gates), carry provenance on
  every entry, and are excluded from manifests and portable exports by
  default unless an explicit opt-in export flag is supplied.
- Alternatives: scan everything by default (rejected: privacy);
  refuse out-of-repo scanning entirely (rejected: legitimate local
  workflows need it with consent).
- Consequences: export/import code must preserve the provenance marking;
  any future opt-in export flag must be loud and documented.
