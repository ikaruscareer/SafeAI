# ADR 0005 — No integrations command namespace yet

- Status: accepted
- Date: 2026-09-16
- Context: CE 2.3 asked whether network paths deserve an explicit
  `safeai integrations` command namespace. Today exactly one network
  path exists: `--pr-comment-post` (one GitHub API request, announced
  on stderr, compatibility-guaranteed).
- Decision: keep `--pr-comment-post` as-is. A namespace for a single
  command adds surface without value; revisit when a second network
  integration lands, at which point the flag becomes a compat shim.
- Alternatives: introduce the namespace now with one member (rejected:
  premature structure); remove the flag (rejected: breaks CI workflows
  and the offline-boundary promise that names this exact flag).
- Consequences: `safeai rules check`, registry import/export, and all
  other commands stay offline; any future network command must announce
  itself on stderr like `--pr-comment-post` does.
