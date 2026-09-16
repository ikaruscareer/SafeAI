# SafeAI — Release Verification

Verify the integrity and authenticity of your SafeAI installation.
Current release: **v2.2.1**. Since v2.1.2, artifacts are signed
keyless with Sigstore/Cosign (`.sig` + `.pem` sidecars) — there are no
GPG `.asc` files. Check the asset names below against
https://github.com/ikaruscareer/SafeAI/releases/tag/v2.2.1 before trusting
any download.

## Quick Verify (any platform)

```bash
safeai --version
# Expected: 2.2.1
```

## Linux

### Verify checksum (SHA-256)

```bash
# Download the release assets
wget https://github.com/ikaruscareer/SafeAI/releases/download/v2.2.1/safeai_static_analyzer-2.2.1-py3-none-any.whl
wget https://github.com/ikaruscareer/SafeAI/releases/download/v2.2.1/SHA256SUMS

sha256sum -c SHA256SUMS --ignore-missing
# Expected: safeai_static_analyzer-2.2.1-py3-none-any.whl: OK
```

### Verify Cosign keyless signature

```bash
# Install cosign if not present: https://docs.sigstore.dev/cosign/installation/
wget https://github.com/ikaruscareer/SafeAI/releases/download/v2.2.1/safeai_static_analyzer-2.2.1-py3-none-any.whl.pem
wget https://github.com/ikaruscareer/SafeAI/releases/download/v2.2.1/safeai_static_analyzer-2.2.1-py3-none-any.whl.sig

cosign verify-blob \
  --certificate safeai_static_analyzer-2.2.1-py3-none-any.whl.pem \
  --signature safeai_static_analyzer-2.2.1-py3-none-any.whl.sig \
  --certificate-identity "https://github.com/ikaruscareer/SafeAI/.github/workflows/release.yml@refs/tags/v2.2.1" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  safeai_static_analyzer-2.2.1-py3-none-any.whl
# Expected: Verified OK
```

### Verify provenance (SLSA)

```bash
# Requires slsa-verifier (https://github.com/slsa-framework/slsa-verifier)
wget https://github.com/ikaruscareer/SafeAI/releases/download/v2.2.1/safeai-2.2.1-slsa-provenance.json

slsa-verifier verify-artifact safeai_static_analyzer-2.2.1-py3-none-any.whl \
  --provenance-path safeai-2.2.1-slsa-provenance.json \
  --source-uri github.com/ikaruscareer/SafeAI
# Expected: Verified SLSA provenance
```

## macOS

### Verify checksum (SHA-256)

```bash
curl -LO https://github.com/ikaruscareer/SafeAI/releases/download/v2.2.1/SHA256SUMS
curl -LO https://github.com/ikaruscareer/SafeAI/releases/download/v2.2.1/safeai_static_analyzer-2.2.1-py3-none-any.whl

shasum -a 256 -c SHA256SUMS --ignore-missing
# Expected: safeai_static_analyzer-2.2.1-py3-none-any.whl: OK
```

### Verify Cosign keyless signature

Same `cosign verify-blob` invocation as Linux (install via
`brew install cosign`).

## Windows (PowerShell)

### Verify checksum (SHA-256)

```powershell
Invoke-WebRequest -Uri "https://github.com/ikaruscareer/SafeAI/releases/download/v2.2.1/safeai_static_analyzer-2.2.1-py3-none-any.whl" -OutFile "safeai.whl"
Invoke-WebRequest -Uri "https://github.com/ikaruscareer/SafeAI/releases/download/v2.2.1/SHA256SUMS" -OutFile "SHA256SUMS"

# Compute hash
$hash = (Get-FileHash -Algorithm SHA256 safeai.whl).Hash.ToLower()
$expected = (Get-Content SHA256SUMS | Select-String "safeai_static_analyzer-2.2.1-py3-none-any.whl").Line.Split()[0]
if ($hash -eq $expected) { Write-Host "Checksum OK" } else { Write-Host "MISMATCH" }
```

### Verify with pip hash checking

```powershell
# Get the expected digest from the SHA256SUMS file above, then:
pip install --require-hashes --hash=sha256:<HASH> SafeAI-Static-Analyzer==2.2.1
```

## Verify Git Tag

```bash
# Fetch tags
git fetch --tags

# Inspect the tag object (a "Good signature" line appears only if the tag was signed)
git verify-tag v2.2.1

# Or clone and verify
git clone https://github.com/ikaruscareer/SafeAI.git
cd SafeAI
git checkout v2.2.1
```

## Verify PyPI Package

```bash
# Download from PyPI
pip download SafeAI-Static-Analyzer==2.2.1

# Verify hash matches release
sha256sum safeai_static_analyzer-2.2.1-py3-none-any.whl
# Compare with SHA256SUMS from GitHub release
```

## What to Expect (v2.2.1 assets)

| Artifact | Description |
|----------|-------------|
| `.whl` | Python wheel package |
| `.tar.gz` | Source distribution |
| `.whl.sig` / `.tar.gz.sig` | Cosign keyless signature |
| `.whl.pem` / `.tar.gz.pem` | Cosign signing certificate |
| `SHA256SUMS` | SHA-256 checksums for all artifacts |
| `safeai-2.2.1-slsa-provenance.json` | SLSA build provenance attestation |
| `safeai-2.2.1-sbom.spdx.json` | SPDX SBOM |

## Troubleshooting

### "No signature found" / 404 on an asset

Check the release assets listing — asset names change between
releases:
https://github.com/ikaruscareer/SafeAI/releases/tag/v2.2.1

### Cosign identity mismatch

The `--certificate-identity` must match the tag you verify
(`.../release.yml@refs/tags/vX.Y.Z`). Copy the exact tag, including
the leading `v`.

### Checksum mismatch

Re-download the artifact. If it persists, open an issue at
https://github.com/ikaruscareer/SafeAI/issues with the `security` label.
