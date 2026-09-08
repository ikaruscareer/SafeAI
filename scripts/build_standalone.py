#!/usr/bin/env python3
"""Build standalone SafeAI binaries using PyInstaller.

Usage:
    python scripts/build_standalone.py

Output:
    dist/safeai/  - standalone binary directory
    dist/safeai.zip - zipped binary for distribution
"""

import os
import subprocess
import sys
import zipfile
from pathlib import Path


def main():
    repo_root = Path(__file__).parent.parent
    os.chdir(repo_root)

    # Install PyInstaller if not present
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("Installing PyInstaller...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller>=6.0"])

    # Build
    print("Building standalone binary...")
    subprocess.check_call([
        sys.executable, "-m", "PyInstaller",
        "safeai.spec",
        "--clean",
        "--noconfirm",
    ])

    dist_dir = repo_root / "dist" / "safeai"
    if not dist_dir.exists():
        print("ERROR: Build failed - dist/safeai/ not found", file=sys.stderr)
        return 1

    # Create zip for distribution
    zip_path = repo_root / "dist" / "safeai.zip"
    print(f"Creating {zip_path}...")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for file in sorted(dist_dir.rglob("*")):
            if file.is_file():
                arcname = file.relative_to(dist_dir.parent)
                zf.write(file, arcname)

    # Report
    binary = dist_dir / ("safeai.exe" if sys.platform == "win32" else "safeai")
    size_mb = binary.stat().st_size / (1024 * 1024)
    print(f"\nBuild complete:")
    print(f"  Binary: {binary}")
    print(f"  Size: {size_mb:.1f} MB")
    print(f"  Zip: {zip_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
