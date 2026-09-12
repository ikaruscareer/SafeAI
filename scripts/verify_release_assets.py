"""Verify release asset invariants for one tag (CI gate, stdlib only).

Every file staged for a GitHub release must unambiguously belong to the
running tag. Historical or generically named artifacts fail the release.

Usage:
    python scripts/verify_release_assets.py <assets-dir> <version>

    <version> is the bare version, e.g. ``2.2.1``.

Invariants:
    1. Any filename containing an X.Y.Z version must contain exactly
       <version> (no historical artifacts, e.g. safeai-2.0.1-*.json).
    2. Every wheel/sdist basename must contain <version>.
    3. Exactly one ``*-sbom.spdx.json`` and one ``*-slsa-provenance.json``,
       both carrying <version>; no generically named ``provenance.json``.
    4. Every wheel/sdist has a ``.sig`` + ``.pem`` Cosign sidecar.
    5. ``SHA256SUMS`` lists every wheel/sdist/SBOM/provenance file with a
       digest matching the recomputed SHA-256 (signature-to-artifact link).

Exit codes: 0 pass · 1 invariant violated · 2 usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys

VERSION_RE = re.compile(r"\d+\.\d+\.\d+")


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(assets_dir, version):
    """Return a list of violation strings (empty = pass)."""
    problems = []
    try:
        names = sorted(os.listdir(assets_dir))
    except OSError as exc:
        return [f"cannot list {assets_dir}: {exc}"]
    files = [n for n in names if os.path.isfile(os.path.join(assets_dir, n))]

    # 1. No foreign versions anywhere in filenames.
    for name in files:
        for found in VERSION_RE.findall(name):
            if found != version:
                problems.append(
                    f"{name}: carries foreign version {found} "
                    f"(release is {version})")

    # 2. Wheel/sdist must carry the release version.
    packages = [n for n in files
                if n.endswith((".whl", ".tar.gz"))]
    if not packages:
        problems.append("no wheel or sdist staged")
    for name in packages:
        if version not in name:
            problems.append(f"{name}: package filename lacks version {version}")

    # 3. Exactly one versioned SBOM + one versioned SLSA provenance.
    sboms = [n for n in files if n.endswith("-sbom.spdx.json")]
    slsa = [n for n in files if n.endswith("-slsa-provenance.json")]
    if len(sboms) != 1:
        problems.append(f"expected exactly one *-sbom.spdx.json, found {sboms}")
    if len(slsa) != 1:
        problems.append(
            f"expected exactly one *-slsa-provenance.json, found {slsa}")
    if "provenance.json" in files:
        problems.append("provenance.json: generically named provenance; "
                        "must be versioned *-slsa-provenance.json")

    # 4. Cosign sidecars per package.
    for name in packages:
        for suffix in (".sig", ".pem"):
            if name + suffix not in files:
                problems.append(f"{name}: missing Cosign sidecar {name + suffix}")

    # 5. SHA256SUMS linkage.
    sums_path = os.path.join(assets_dir, "SHA256SUMS")
    if not os.path.isfile(sums_path):
        problems.append("SHA256SUMS missing")
        return problems
    recorded = {}
    with open(sums_path, encoding="utf-8") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) >= 2:
                recorded[parts[1]] = parts[0]
    linked = [n for n in files if n == "SHA256SUMS" or n.endswith((".sig", ".pem"))]
    for name in files:
        if name in linked:
            continue
        expected = recorded.get(name)
        if expected is None:
            problems.append(f"{name}: absent from SHA256SUMS")
            continue
        actual = sha256_file(os.path.join(assets_dir, name))
        if actual != expected:
            problems.append(f"{name}: SHA256SUMS digest mismatch")

    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description="Verify release asset invariants")
    parser.add_argument("assets_dir")
    parser.add_argument("version")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"\d+\.\d+\.\d+", args.version or ""):
        print(f"usage error: version must be X.Y.Z, got {args.version!r}",
              file=sys.stderr)
        return 2
    problems = verify(args.assets_dir, args.version)
    if problems:
        print(f"release asset invariants FAILED for {args.version}:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print(f"release asset invariants OK for {args.version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
