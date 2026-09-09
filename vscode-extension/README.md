# SafeAI Static Analyzer for VS Code

Scan AI-agent code for capabilities, risks, and policy violations directly from VS Code.

## Features

- **Workspace Scan**: Scan the entire workspace for AI-agent patterns
- **File Scan**: Scan the active file for AI-agent patterns
- **Diagnostics**: Inline problem markers for findings
- **Output Channel**: Detailed scan results in the SafeAI output channel

## Requirements

- Python 3.11+ with SafeAI installed (`pip install safeai-static-analyzer`)
- Or the standalone binary (`safeai.exe`)

## Configuration

- `safeai.executablePath`: Path to the safeai executable (leave empty to use Python module)
- `safeai.failOn`: Minimum severity that triggers a problem marker (default: "critical")
- `safeai.noRegistry`: Do not create or update the local KYA registry (default: true)

## Usage

1. Open a workspace containing AI-agent code
2. Run `SafeAI: Scan Workspace` from the Command Palette (Ctrl+Shift+P)
3. View findings in the Output channel and as inline diagnostics

## Development

```bash
npm install
npm run compile
```

Press F5 to launch the extension in a new VS Code window.
