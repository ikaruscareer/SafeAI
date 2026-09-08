# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec file for SafeAI standalone binaries

import sys
from pathlib import Path

block_cipher = None

# Collect all safeai package data
safeai_pkg = Path("safeai")
data_files = []
for ext in ("*.yaml", "*.yml", "*.md", "*.json"):
    for f in safeai_pkg.rglob(ext):
        rel = f.relative_to(safeai_pkg.parent)
        data_files.append((str(f), str(rel.parent)))

a = Analysis(
    ["safeai/cmd/cli.py"],
    pathex=[],
    binaries=[],
    datas=data_files,
    hiddenimports=[
        "safeai",
        "safeai.cmd",
        "safeai.cmd.cli",
        "safeai.cmd.scan",
        "safeai.cmd.postprocess",
        "safeai.cmd.registry_cli",
        "safeai.engine",
        "safeai.engine.scan",
        "safeai.analyzers",
        "safeai.analyzers.mcp",
        "safeai.analyzers.mcp.analyzer",
        "safeai.analyzers.mcp.validators",
        "safeai.analyzers.mcp.schema",
        "safeai.analyzers.mcp.compatibility",
        "safeai.frameworks",
        "safeai.frameworks.claude_code",
        "safeai.frameworks.claude_code.parser",
        "safeai.frameworks.claude_code.permissions",
        "safeai.frameworks.claude_code.settings",
        "safeai.frameworks.langchain",
        "safeai.frameworks.openai",
        "safeai.frameworks.autogen",
        "safeai.frameworks.llamaindex",
        "safeai.report",
        "safeai.report.json_report",
        "safeai.report.html",
        "safeai.report.sarif",
        "safeai.report.pr_comment",
        "safeai.kya",
        "safeai.kya.schema",
        "safeai.kya.exporter",
        "safeai.kya.importer",
        "safeai.kya.ci_context",
        "safeai.analysis",
        "safeai.analysis.tool_identity",
        "safeai.analysis.escalation",
        "safeai.severity",
        "safeai.policy",
        "safeai.scorecard",
        "yaml",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "unittest",
        "test",
        "xmlrpc",
        "pydoc",
        "pdb",
        "profile",
        "cProfile",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="safeai",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="safeai",
)
