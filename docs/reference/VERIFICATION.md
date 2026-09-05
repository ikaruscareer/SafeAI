# SafeAI — Release Verification

Verify the integrity and authenticity of your SafeAI installation.

## Quick Verify (any platform)

```bash
safeai --version
# Expected: 2.0.1
```

## Linux

### Verify GPG signature

```bash
# Import the maintainer's public key (one-time)
gpg --keyserver keyserver.ubuntu.com --recv-keys 0xYOUR_KEY_ID

# Download the release assets
wget https://github.com/ikaruscareer/SafeAI/releases/download/v2.0.1/safeai_static_analyzer-2.0.1-py3-none-any.whl
wget https://github.com/ikaruscareer/SafeAI/releases/download/v2.0.1/safeai_static_analyzer-2.0.1-py3-none-any.whl.asc

# Verify the signature
gpg --verify safeai_static_analyzer-2.0.1-py3-none-any.whl.asc \
            safeai_static_analyzer-2.0.1-py3-none-any.whl
# Expected: Good signature from "IkarusCareer"
```

### Verify SHA-256 checksum

```bash
wget https://github.com/ikaruscareer/SafeAI/releases/download/v2.0.1/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
# Expected: safeai_static_analyzer-2.0.1-py3-none-any.whl: OK
```

### Verify provenance (SLSA)

```bash
# Requires slsa-verifier (https://github.com/slsa-framework/slsa-verifier)
slsa-verifier verify-artifact safeai_static_analyzer-2.0.1-py3-none-any.whl \
  --provenance-path provenance.json \
  --source-uri github.com/ikaruscareer/SafeAI
```

## macOS

### Verify GPG signature

```bash
# Install gpg if not present
brew install gnupg

# Import the maintainer's public key (one-time)
gpg --keyserver keyserver.ubuntu.com --recv-keys 0xYOUR_KEY_ID

# Download and verify
curl -LO https://github.com/ikaruscareer/SafeAI/releases/download/v2.0.1/safeai_static_analyzer-2.0.1-py3-none-any.whl
curl -LO https://github.com/ikaruscareer/SafeAI/releases/download/v2.0.1/safeai_static_analyzer-2.0.1-py3-none-any.whl.asc

gpg --verify safeai_static_analyzer-2.0.1-py3-none-any.whl.asc \
            safeai_static_analyzer-2.0.1-py3-none-any.whl
# Expected: Good signature from "IkarusCareer"
```

### Verify SHA-256 checksum

```bash
curl -LO https://github.com/ikaruscareer/SafeAI/releases/download/v2.0.1/SHA256SUMS
shasum -a 256 -c SHA256SUMS --ignore-missing
# Expected: safeai_static_analyzer-2.0.1-py3-none-any.whl: OK
```

### Verify with Homebrew (if applicable)

```bash
# If SafeAI is distributed via Homebrew
brew update && brew upgrade safeai
```

## Windows (PowerShell)

### Verify GPG signature

```powershell
# Install Gpg4win if not present
winget install GnuPG.Gpg4win

# Import the maintainer's public key (one-time)
gpg --keyserver keyserver.ubuntu.com --recv-keys 0xYOUR_KEY_ID

# Download and verify
Invoke-WebRequest -Uri "https://github.com/ikaruscareer/SafeAI/releases/download/v2.0.1/safeai_static_analyzer-2.0.1-py3-none-any.whl" -OutFile "safeai.whl"
Invoke-WebRequest -Uri "https://github.com/ikaruscareer/SafeAI/releases/download/v2.0.1/safeai_static_analyzer-2.0.1-py3-none-any.whl.asc" -OutFile "safeai.whl.asc"

gpg --verify safeai.whl.asc safeai.whl
# Expected: Good signature from "IkarusCareer"
```

### Verify SHA-256 checksum

```powershell
Invoke-WebRequest -Uri "https://github.com/ikaruscareer/SafeAI/releases/download/v2.0.1/SHA256SUMS" -OutFile "SHA256SUMS"

# Compute hash
$hash = (Get-FileHash -Algorithm SHA256 safeai.whl).Hash.ToLower()
$expected = (Get-Content SHA256SUMS | Select-String "safeai.whl").Line.Split()[0]
if ($hash -eq $expected) { Write-Host "Checksum OK" } else { Write-Host "MISMATCH" }
```

### Verify with pip hash checking

```powershell
pip install --require-hashes --hash=sha256:<HASH> SafeAI-Static-Analyzer==2.0.1
```

## Verify Git Tag

```bash
# Fetch tags
git fetch --tags

# Verify tag is signed
git verify-tag v2.0.1
# Expected: Good signature from "IkarusCareer"

# Or clone and verify
git clone https://github.com/ikaruscareer/SafeAI.git
cd SafeAI
git checkout v2.0.1
git verify-tag v2.0.1
```

## Verify PyPI Package

```bash
# Download from PyPI
pip download SafeAI-Static-Analyzer==2.0.1

# Verify hash matches release
sha256sum safeai_static_analyzer-2.0.1-py3-none-any.whl
# Compare with SHA256SUMS from GitHub release
```

## What to Expect

| Artifact | Description |
|----------|-------------|
| `.whl` | Python wheel package |
| `.tar.gz` | Source distribution |
| `.asc` | GPG detached signature (for each artifact) |
| `SHA256SUMS` | SHA-256 checksums for all artifacts |
| `SHA256SUMS.asc` | GPG signature for the checksum file |
| `provenance.json` | SLSA provenance attestation |
| `provenance.json.asc` | GPG signature for provenance |
| `*.spdx.json` | SPDX SBOM |
| `*.spdx.json.asc` | GPG signature for SBOM |

## Troubleshooting

### "No signature found"

The `.asc` file may not have been uploaded yet. Check the release assets
at https://github.com/ikaruscareer/SafeAI/releases/tag/v2.0.1

### "Good signature" but wrong key

Verify the key ID matches the maintainer's published key:
https://github.com/ikaruscareer/SafeAI/blob/main/SECURITY.md

### Checksum mismatch

Re-download the artifact. If it persists, open an issue at
https://github.com/ikaruscareer/SafeAI/issues with the `security` label.
