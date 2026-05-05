import * as vscode from 'vscode';
import { execSync, spawn } from 'child_process';

export function activate(context: vscode.ExtensionContext) {
    // Chat command — opens a panel and communicates with the agent CLI
    const chatCmd = vscode.commands.registerCommand('aiAgentOS.chat', async () => {
        const input = await vscode.window.showInputBox({ prompt: 'Ask AI Agent OS...' });
        if (!input) return;

        const panel = vscode.window.createOutputChannel('AI Agent OS');
        panel.show();
        panel.appendLine(`❯ ${input}`);
        panel.appendLine('');

        try {
            const result = execSync(`cargo run -q --package agent-cli -- -c "${input.replace(/"/g, '\\"')}"`, {
                cwd: vscode.workspace.workspaceFolders?.[0]?.uri.fsPath,
                encoding: 'utf-8',
                timeout: 60000,
                env: { ...process.env },
            });
            panel.appendLine(result);
        } catch (e: any) {
            panel.appendLine(`Error: ${e.message}`);
        }
    });

    // Plan command — generates a plan for a task
    const planCmd = vscode.commands.registerCommand('aiAgentOS.plan', async () => {
        const input = await vscode.window.showInputBox({ prompt: 'What task should the agent plan?' });
        if (!input) return;

        const panel = vscode.window.createOutputChannel('AI Agent OS');
        panel.show();
        panel.appendLine(`Planning: ${input}`);

        try {
            const result = execSync(`cargo run -q --package agent-cli -- -c "Create a plan for: ${input.replace(/"/g, '\\"')}"`, {
                cwd: vscode.workspace.workspaceFolders?.[0]?.uri.fsPath,
                encoding: 'utf-8',
                timeout: 60000,
            });
            panel.appendLine(result);
        } catch (e: any) {
            panel.appendLine(`Error: ${e.message}`);
        }
    });

    // Explain selection
    const explainCmd = vscode.commands.registerCommand('aiAgentOS.explain', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) return;

        const selection = editor.document.getText(editor.selection);
        if (!selection) { vscode.window.showWarningMessage('Select some code first'); return; }

        const panel = vscode.window.createOutputChannel('AI Agent OS');
        panel.show();

        try {
            const result = execSync(`echo '${selection.replace(/'/g, "\\'")}' | cargo run -q --package agent-cli -- "Explain this code concisely"`, {
                cwd: vscode.workspace.workspaceFolders?.[0]?.uri.fsPath,
                encoding: 'utf-8',
                timeout: 60000,
            });
            panel.appendLine(result);
        } catch (e: any) {
            panel.appendLine(`Error: ${e.message}`);
        }
    });

    context.subscriptions.push(chatCmd, planCmd, explainCmd);
}

export function deactivate() {}
