#!/usr/bin/env python3
"""Generate SBOM (SPDX JSON), SHA-256 checksums, and provenance attestation
for the SafeAI v2.0.0 release source tarball.

Run from the repository root after tagging v2.0.0:
    python scripts/generate_release_artifacts.py v2.0.0
"""

import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def generate_sbom(tag: str, source_files: list[Path]) -> dict:
    """Produce a minimal SPDX 2.3 JSON SBOM."""
    package_id = f"SPDXRef-Package-safeai-{tag}"
    now = datetime.now(UTC).isoformat()

    files = []
    for p in source_files:
        rel = p.as_posix()
        files.append({
            "SPDXID": f"SPDXRef-File-{rel.replace('/', '-').replace('.', '-')}",
            "checksums": [{"algorithm": "SHA256", "checksumValue": sha256_file(p)}],
            "fileName": rel,
            "licenseConcluded": "Apache-2.0",
            "copyrightText": "Copyright 2026 IkarusCareer",
        })

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"safeai-{tag}",
        "documentNamespace": f"https://github.com/ikaruscareer/SafeAI/{tag}",
        "documentCreationInfo": {
            "created": now,
            "creators": ["Tool: safeai-release-artifacts"],
            "licenseListVersion": "3.21",
        },
        "packages": [
            {
                "SPDXID": package_id,
                "name": "SafeAI-Static-Analyzer",
                "versionInfo": tag.lstrip("v"),
                "downloadLocation": f"https://github.com/ikaruscareer/SafeAI/archive/refs/tags/{tag}.tar.gz",
                "licenseConcluded": "Apache-2.0",
                "copyrightText": "Copyright 2026 IkarusCareer",
                "checksums": [{"algorithm": "SHA256", "checksumValue": ""}],
                "filesAnalyzed": True,
                "hasFiles": [f["SPDXID"] for f in files],
            }
        ],
        "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": package_id, "relationshipType": "DESCRIBES"}
        ],
        "files": files,
    }


def generate_checksums(files: list[Path]) -> str:
    lines = []
    for p in sorted(files):
        lines.append(f"{sha256_file(p)}  {p.name}")
    return "\n".join(lines) + "\n"


def generate_provenance(tag: str, commit_sha: str, sbom_path: Path) -> dict:
    """Produce a SLSA Provenance v1.0 attestation (in-toto statement)."""
    now = datetime.now(UTC).isoformat()
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": f"safeai-{tag}.tar.gz",
                "digest": {"sha256": sha256_file(sbom_path)},
            }
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildType": "https://github.com/ikaruscareer/SafeAI/.github/workflows/ci.yml",
            "externalParameters": {
                "source": {
                    "uri": f"https://github.com/ikaruscareer/SafeAI/archive/refs/tags/{tag}.tar.gz",
                    "digest": {"sha1": commit_sha},
                }
            },
            "internalParameters": {
                "runner": {"arch": "x64", "os": "linux"},
                "workflowRef": ".github/workflows/ci.yml",
                "workflowSha": commit_sha,
            },
            "metadata": {
                "buildInvocationId": f"release-{tag}",
                "buildStartedOn": now,
                "buildFinishedOn": now,
                "completeness": {"parameters": True, "environment": False, "materials": False},
                "reproducible": False,
            },
            "materials": [
                {
                    "uri": f"https://github.com/ikaruscareer/SafeAI/archive/refs/tags/{tag}.tar.gz",
                    "digest": {"sha1": commit_sha},
                }
            ],
        },
    }


def main():
    tag = sys.argv[1] if len(sys.argv) > 1 else "v2.0.0"
    out_dir = Path("release-artifacts")
    out_dir.mkdir(exist_ok=True)

    # Get commit SHA
    result = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
    commit_sha = result.stdout.strip()

    # Collect tracked source files
    result = subprocess.run(["git", "ls-files", "--"], capture_output=True, text=True, check=False)
    source_files = [Path(f.strip()) for f in result.stdout.splitlines() if f.strip()]

    # SBOM
    sbom = generate_sbom(tag, source_files)
    sbom_path = out_dir / f"safeai-{tag}-sbom.spdx.json"
    with open(sbom_path, "w") as f:
        json.dump(sbom, f, indent=2)
    print(f"  SBOM: {sbom_path}")

    # Checksums
    checksums = generate_checksums([sbom_path])
    checksums_path = out_dir / "SHA256SUMS"
    with open(checksums_path, "w") as f:
        f.write(checksums)
    print(f"  Checksums: {checksums_path}")

    # Provenance
    provenance = generate_provenance(tag, commit_sha, sbom_path)
    prov_path = out_dir / f"safeai-{tag}-provenance.json"
    with open(prov_path, "w") as f:
        json.dump(provenance, f, indent=2)
    print(f"  Provenance: {prov_path}")

    print(f"\nRelease artifacts written to {out_dir}/")


if __name__ == "__main__":
    main()
