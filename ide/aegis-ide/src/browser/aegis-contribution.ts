/**
 * Commands, menus and keybindings, plus the bridge from audit results to
 * editor markers.
 *
 * Findings appear in two places on purpose: the panel carries the full path
 * trace, while the Problems view and the editor gutter carry the one-line
 * summary. A reviewer scanning code wants the squiggle; a reviewer judging a
 * report wants the trace.
 */

import {
    AbstractViewContribution,
    codicon,
    FrontendApplication,
    FrontendApplicationContribution
} from '@theia/core/lib/browser';
import { Command, CommandRegistry, MenuModelRegistry, MessageService } from '@theia/core/lib/common';
import { CommonMenus } from '@theia/core/lib/browser/common-frontend-contribution';
import { EditorManager } from '@theia/editor/lib/browser';
import { inject, injectable } from '@theia/core/shared/inversify';
import { ProblemManager } from '@theia/markers/lib/browser/problem/problem-manager';
import URI from '@theia/core/lib/common/uri';
import {
    Diagnostic,
    DiagnosticSeverity,
    Range
} from '@theia/core/shared/vscode-languageserver-protocol';

import {
    AegisAuditResult,
    AegisClient,
    AegisCommands,
    AegisFinding,
    AegisService,
    AegisStatus,
    FINDINGS_WIDGET_ID
} from '../common/aegis-protocol';
import { AegisFindingsWidget } from './findings-widget';

export const AuditCommand: Command = {
    id: AegisCommands.AUDIT,
    category: AegisCommands.CATEGORY,
    label: 'Audit Current File',
    iconClass: codicon('shield')
};

export const ShowFindingsCommand: Command = {
    id: AegisCommands.SHOW_FINDINGS,
    category: AegisCommands.CATEGORY,
    label: 'Show Findings Panel'
};

export const ExplainCommand: Command = {
    id: AegisCommands.EXPLAIN,
    category: AegisCommands.CATEGORY,
    label: 'Explain Function at Cursor'
};

export const BuildLlvmCommand: Command = {
    id: AegisCommands.BUILD_LLVM,
    category: AegisCommands.CATEGORY,
    label: 'Show Generated LLVM IR'
};

export const AdjudicateCommand: Command = {
    id: AegisCommands.ADJUDICATE,
    category: AegisCommands.CATEGORY,
    label: 'Review Findings with AI',
    iconClass: codicon('sparkle')
};

export const AiStatusCommand: Command = {
    id: AegisCommands.AI_STATUS,
    category: AegisCommands.CATEGORY,
    label: 'AI Adjudication Status'
};

const SEVERITY: Record<string, DiagnosticSeverity> = {
    error: DiagnosticSeverity.Error,
    warning: DiagnosticSeverity.Warning,
    note: DiagnosticSeverity.Information
};

@injectable()
export class AegisViewContribution
    extends AbstractViewContribution<AegisFindingsWidget>
    implements FrontendApplicationContribution, AegisClient
{
    @inject(AegisService) protected readonly aegis: AegisService;
    @inject(EditorManager) protected readonly editorManager: EditorManager;
    @inject(ProblemManager) protected readonly problemManager: ProblemManager;
    @inject(MessageService) protected readonly messageService: MessageService;

    constructor() {
        super({
            widgetId: FINDINGS_WIDGET_ID,
            widgetName: AegisFindingsWidget.LABEL,
            defaultWidgetOptions: { area: 'bottom' },
            toggleCommandId: AegisCommands.SHOW_FINDINGS
        });
    }

    async onStart(_app: FrontendApplication): Promise<void> {
        this.aegis.setClient(this);
    }

    // -- client notifications ----------------------------------------------

    onStatus(status: AegisStatus): void {
        if (status.state === 'failed') {
            this.messageService.error('Aegis: analysis failed. See the log for details.');
        }
    }

    onFindings(result: AegisAuditResult): void {
        void this.applyResult(result);
    }

    protected async applyResult(result: AegisAuditResult): Promise<void> {
        const widget = await this.openView({ activate: false, reveal: true });
        widget.setResult(result);
        this.publishMarkers(result);
    }

    /** Mirror findings into the Problems view and the editor gutter. */
    protected publishMarkers(result: AegisAuditResult): void {
        const byUri = new Map<string, Diagnostic[]>();
        for (const finding of result.findings) {
            const uri = finding.sink.uri;
            const list = byUri.get(uri) ?? [];
            list.push(this.toDiagnostic(finding));
            byUri.set(uri, list);
        }
        for (const [uri, diagnostics] of byUri) {
            this.problemManager.setMarkers(new URI(uri), 'aegis', diagnostics);
        }
    }

    protected toDiagnostic(finding: AegisFinding): Diagnostic {
        const line = Math.max(finding.sink.line - 1, 0);
        const character = Math.max(finding.sink.column - 1, 0);
        const range: Range = {
            start: { line, character },
            end: { line, character: character + 12 }
        };
        return {
            range,
            severity: SEVERITY[finding.severity] ?? DiagnosticSeverity.Warning,
            source: 'aegis',
            code: finding.ruleId,
            message: `${finding.title} — ${finding.message}`,
            relatedInformation: finding.steps.map(step => ({
                location: {
                    uri: step.uri,
                    range: {
                        start: { line: Math.max(step.line - 1, 0), character: 0 },
                        end: { line: Math.max(step.line - 1, 0), character: 200 }
                    }
                },
                message: `${step.kind}: ${step.explanation}`
            }))
        };
    }

    // -- commands -----------------------------------------------------------

    override registerCommands(registry: CommandRegistry): void {
        super.registerCommands(registry);

        registry.registerCommand(AuditCommand, {
            isEnabled: () => !!this.currentUri(),
            execute: () => this.runAudit()
        });

        registry.registerCommand(ExplainCommand, {
            isEnabled: () => !!this.currentUri(),
            execute: () => this.explainAtCursor()
        });

        registry.registerCommand(BuildLlvmCommand, {
            isEnabled: () => !!this.currentUri(),
            execute: () => this.showLlvm()
        });

        registry.registerCommand(AdjudicateCommand, {
            isEnabled: () => !!this.currentUri(),
            execute: () => this.runAdjudication()
        });

        registry.registerCommand(AiStatusCommand, {
            execute: () => this.showAiStatus()
        });
    }

    override registerMenus(menus: MenuModelRegistry): void {
        super.registerMenus(menus);
        menus.registerMenuAction(CommonMenus.EDIT_FIND, {
            commandId: AuditCommand.id,
            label: AuditCommand.label
        });
    }

    override registerKeybindings(keybindings: import('@theia/core/lib/browser').KeybindingRegistry): void {
        super.registerKeybindings(keybindings);
        keybindings.registerKeybinding({
            command: AuditCommand.id,
            keybinding: 'ctrlcmd+alt+a'
        });
    }

    // -- actions ------------------------------------------------------------

    protected currentUri(): string | undefined {
        return this.editorManager.currentEditor?.editor.uri.toString();
    }

    protected async runAudit(): Promise<void> {
        const uri = this.currentUri();
        if (!uri) {
            this.messageService.warn('Aegis: open a C file first.');
            return;
        }
        const widget = await this.openView({ activate: true, reveal: true });
        widget.setRunning();
        const result = await this.aegis.audit(uri);
        widget.setResult(result);
        this.publishMarkers(result);
        if (result.error) {
            this.messageService.error(`Aegis: ${result.error}`);
        }
    }

    /**
     * Audit and then review, reporting what the review actually did.
     *
     * The message distinguishes the three outcomes that matter to a user: no
     * model configured, a model that reviewed findings, and a model that could
     * not be reached. All three leave the compiler's findings on screen.
     */
    protected async runAdjudication(): Promise<void> {
        const uri = this.currentUri();
        if (!uri) {
            this.messageService.warn('Aegis: open a C file first.');
            return;
        }
        const widget = await this.openView({ activate: true, reveal: true });
        widget.setRunning('Reviewing findings…');
        const result = await this.aegis.adjudicate(uri);
        widget.setResult(result);
        this.publishMarkers(result);

        if (result.error) {
            this.messageService.error(`Aegis: ${result.error}`);
            return;
        }
        const summary = result.adjudication;
        if (summary && summary.enabled === false && summary.reason && !/API key/.test(summary.reason)) {
            // Configured, but refused: say what refused it rather than implying
            // the key is missing.
            this.messageService.warn(
                `Aegis: AI review unavailable (${summary.reason}). Static verdicts retained.`
            );
            return;
        }
        if (!summary || summary.enabled === false) {
            this.messageService.info(
                'Aegis: no model is configured, so the compiler\'s own verdicts stand. ' +
                    'Add OPENROUTER_API_KEY to the project .env and restart to enable review.'
            );
            return;
        }
        if (summary.errors > 0 && summary.adjudicated === 0) {
            this.messageService.warn(
                `Aegis: review unavailable (${summary.errors} failed). Static verdicts retained.`
            );
            return;
        }
        this.messageService.info(
            `Aegis: ${summary.adjudicated}/${summary.candidates} reviewed by ${summary.model} — ` +
                `${summary.dismissed} dismissed, ${summary.demoted} demoted` +
                (summary.cache_hits ? `, ${summary.cache_hits} cached` : '')
        );
    }

    protected async showAiStatus(): Promise<void> {
        const status = await this.aegis.aiStatus();
        if (status.error) {
            this.messageService.error(`Aegis: ${status.error}`);
            return;
        }
        this.messageService.info(
            status.configured
                ? `Aegis AI: ${status.model} via ${status.base_url} ` +
                      `(key ${status.key_fingerprint}) — cache ${status.cache}`
                : 'Aegis AI: not configured. Add OPENROUTER_API_KEY to the project .env to enable review; ' +
                      'the compiler and all analyses work without it.'
        );
    }

    protected async explainAtCursor(): Promise<void> {
        const editor = this.editorManager.currentEditor?.editor;
        if (!editor) {
            return;
        }
        const line = editor.cursor.line;
        const text = editor.document.getText();
        const name = findEnclosingFunction(text, line);
        if (!name) {
            this.messageService.info('Aegis: no function found at the cursor.');
            return;
        }
        const explanation = await this.aegis.explain(editor.uri.toString(), name);
        if (explanation.error) {
            this.messageService.error(`Aegis: ${explanation.error}`);
            return;
        }
        this.messageService.info(
            `${explanation.function}(${explanation.parameters.join(', ')}) → ${explanation.returnType} · ` +
                `${explanation.blocks} blocks, ${explanation.instructions} instructions · ` +
                `calls ${explanation.callees.join(', ') || 'nothing'} · ${explanation.taintSummary}`
        );
    }

    protected async showLlvm(): Promise<void> {
        const uri = this.currentUri();
        if (!uri) {
            return;
        }
        const result = await this.aegis.buildLlvm(uri);
        if (result.error || !result.llvm) {
            this.messageService.error(`Aegis: ${result.error ?? 'code generation produced no output'}`);
            return;
        }
        this.messageService.info(
            `Generated ${result.llvm.split('\n').length} lines of LLVM IR (see the Output view).`
        );
        console.log(result.llvm);
    }
}

/**
 * Find the function whose definition most closely precedes `line`.
 *
 * A brace-matching scan would be more precise, but the compiler already knows
 * the answer; this only has to name the function well enough for the backend to
 * look it up in the symbol table.
 */
export function findEnclosingFunction(text: string, line: number): string | undefined {
    const lines = text.split('\n');
    const pattern = /^[A-Za-z_][\w\s*]*\s\*?([A-Za-z_]\w*)\s*\([^;]*$/;
    for (let index = Math.min(line, lines.length - 1); index >= 0; index--) {
        const match = pattern.exec(lines[index].trim());
        if (match) {
            return match[1];
        }
    }
    return undefined;
}
