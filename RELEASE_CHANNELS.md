# SafeAI — Release Channels

SafeAI uses a trunk-based development model with clear release channels.

## Channels

### `main`

Primary development branch. All new features, fixes, and community PRs
land here. CI must be green before merge. Every push to `main` is a
potential release candidate.

**Use case**: bleeding-edge testing, contributing PRs.

### `stable` (PyPI `SafeAI-Static-Analyzer`)

The latest released version. Tagged as `vX.Y.Z`. Published to PyPI
as `SafeAI-Static-Analyzer`. This is what most users install.

```bash
pip install SafeAI-Static-Analyzer
```

**Use case**: production usage, CI pipelines.

### `prerelease` (PyPI `SafeAI-Static-Analyzer预发布`)

Release candidates and pre-release versions. Tagged as `vX.Y.Zrc1`,
`vX.Y.Zb1`, etc. Published to PyPI with `--pre` flag.

```bash
pip install --pre SafeAI-Static-Analyzer
```

**Use case**: testing upcoming features before stable release.

### `maintenance` (PyPI `SafeAI-Static-Analyzer-hotfix`)

Critical patches for older major versions. Branches named `vX.Y-maintenance`.
Only security fixes and critical bug fixes land here. No new features.

```bash
pip install SafeAI-Static-Analyzer==1.9.1
```

**Use case**: environments that cannot upgrade to the latest major version.

## Release Process

1. Features land on `main` via PR (CI must be green).
2. When ready to release, a release candidate is tagged and pushed:
   ```bash
   git tag -a vX.Y.Zrc1 -m "Release candidate vX.Y.Zrc1"
   git push origin vX.Y.Zrc1
   ```
3. RC is tested by the community for 1-7 days.
4. If no issues, the RC is promoted to stable:
   ```bash
   git tag -a vX.Y.Z -m "Stable vX.Y.Z"
   git push origin vX.Y.Z
   ```
5. GitHub Release is created with release notes, SBOM, checksums, and
   provenance attestation.
6. PyPI publish happens automatically via the CI workflow.

## Branch Protection

- `main`: requires PR, CI green, 1 approving review.
- `stable`: protected, only fast-forward merges from `main`.
- `vX.Y-maintenance`: protected, only cherry-picks of critical fixes.

## Versioning

Follows [Semantic Versioning](https://semver.org/):

- **Major** (X): breaking changes to rule IDs, JSON schema, exit codes, or
  Action inputs/outputs.
- **Minor** (Y): new rules, new framework adapters, new report sections
  (additive, backward-compatible).
- **Patch** (Z): bug fixes, documentation updates, rule content improvements.
