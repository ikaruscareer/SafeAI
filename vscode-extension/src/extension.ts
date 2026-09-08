import * as vscode from 'vscode';
import * as path from 'path';
import * as cp from 'child_process';

export function activate(context: vscode.ExtensionContext) {
    console.log('SafeAI Static Analyzer activated');

    const scanCommand = vscode.commands.registerCommand('safeai.scan', async () => {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) {
            vscode.window.showErrorMessage('No workspace folder open');
            return;
        }

        const config = vscode.workspace.getConfiguration('safeai');
        const executablePath = config.get<string>('executablePath', '');
        const failOn = config.get<string>('failOn', 'critical');
        const noRegistry = config.get<boolean>('noRegistry', true);

        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'SafeAI: Scanning workspace...',
            cancellable: true
        }, async (progress, token) => {
            try {
                const results = await runScan(
                    workspaceFolder.uri.fsPath,
                    executablePath,
                    failOn,
                    noRegistry,
                    token
                );

                if (results.findings.length === 0) {
                    vscode.window.showInformationMessage('SafeAI: No findings detected');
                    return;
                }

                // Show results in output channel
                const outputChannel = vscode.window.createOutputChannel('SafeAI');
                outputChannel.clear();
                outputChannel.appendLine(`SafeAI Scan Results (${results.findings.length} findings)`);
                outputChannel.appendLine('='.repeat(50));
                for (const finding of results.findings) {
                    outputChannel.appendLine(`[${finding.severity}] ${finding.file}:${finding.line} - ${finding.message}`);
                }
                outputChannel.show();

                // Create diagnostics
                const diagnostics: vscode.Diagnostic[] = results.findings.map(finding => {
                    const range = new vscode.Range(
                        Math.max(0, finding.line - 1),
                        0,
                        Math.max(0, finding.line - 1),
                        1000
                    );
                    const severity = mapSeverity(finding.severity);
                    const diagnostic = new vscode.Diagnostic(range, finding.message, severity);
                    diagnostic.source = 'safeai';
                    diagnostic.code = finding.rule_id;
                    return diagnostic;
                });

                const documentUri = vscode.Uri.file(path.join(workspaceFolder.uri.fsPath, results.findings[0]?.file || ''));
                vscode.languages.createDiagnosticCollection('safeai').set(documentUri, diagnostics);

            } catch (error) {
                vscode.window.showErrorMessage(`SafeAI scan failed: ${error}`);
            }
        });
    });

    const scanFileCommand = vscode.commands.registerCommand('safeai.scanFile', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('No active editor');
            return;
        }

        const config = vscode.workspace.getConfiguration('safeai');
        const executablePath = config.get<string>('executablePath', '');
        const failOn = config.get<string>('failOn', 'critical');
        const noRegistry = config.get<boolean>('noRegistry', true);

        const filePath = editor.document.uri.fsPath;
        const workspaceFolder = vscode.workspace.getWorkspaceFolder(editor.document.uri);

        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'SafeAI: Scanning file...',
            cancellable: true
        }, async (progress, token) => {
            try {
                const results = await runScan(
                    filePath,
                    executablePath,
                    failOn,
                    noRegistry,
                    token
                );

                if (results.findings.length === 0) {
                    vscode.window.showInformationMessage('SafeAI: No findings detected');
                    return;
                }

                // Create diagnostics for this file
                const diagnostics: vscode.Diagnostic[] = results.findings.map(finding => {
                    const range = new vscode.Range(
                        Math.max(0, finding.line - 1),
                        0,
                        Math.max(0, finding.line - 1),
                        1000
                    );
                    const severity = mapSeverity(finding.severity);
                    const diagnostic = new vscode.Diagnostic(range, finding.message, severity);
                    diagnostic.source = 'safeai';
                    diagnostic.code = finding.rule_id;
                    return diagnostic;
                });

                vscode.languages.createDiagnosticCollection('safeai').set(editor.document.uri, diagnostics);

            } catch (error) {
                vscode.window.showErrorMessage(`SafeAI scan failed: ${error}`);
            }
        });
    });

    context.subscriptions.push(scanCommand, scanFileCommand);
}

function mapSeverity(severity: string): vscode.DiagnosticSeverity {
    switch (severity) {
        case 'critical':
            return vscode.DiagnosticSeverity.Error;
        case 'high':
            return vscode.DiagnosticSeverity.Warning;
        case 'medium':
            return vscode.DiagnosticSeverity.Information;
        default:
            return vscode.DiagnosticSeverity.Hint;
    }
}

interface ScanResult {
    findings: Array<{
        rule_id: string;
        severity: string;
        message: string;
        file: string;
        line: number;
    }>;
}

async function runScan(
    targetPath: string,
    executablePath: string,
    failOn: string,
    noRegistry: boolean,
    token: vscode.CancellationToken
): Promise<ScanResult> {
    return new Promise((resolve, reject) => {
        const args = ['scan', targetPath, '--fail-on', failOn, '--json', '-'];
        if (noRegistry) {
            args.push('--no-registry');
        }

        let command: string;
        if (executablePath) {
            command = executablePath;
        } else {
            command = 'python';
            args.unshift('-m', 'safeai');
        }

        const proc = cp.spawn(command, args, {
            stdio: ['ignore', 'pipe', 'pipe']
        });

        let stdout = '';
        let stderr = '';

        proc.stdout.on('data', (data: Buffer) => {
            stdout += data.toString();
        });

        proc.stderr.on('data', (data: Buffer) => {
            stderr += data.toString();
        });

        token.onCancellationRequested(() => {
            proc.kill();
            reject(new Error('Scan cancelled'));
        });

        proc.on('close', (code) => {
            if (code === 2) {
                reject(new Error(`Scan failed: ${stderr}`));
                return;
            }

            try {
                const report = JSON.parse(stdout);
                const findings = report.findings || [];
                resolve({ findings });
            } catch (error) {
                reject(new Error(`Failed to parse scan output: ${error}`));
            }
        });

        proc.on('error', (error) => {
            reject(error);
        });
    });
}

export function deactivate() {}
