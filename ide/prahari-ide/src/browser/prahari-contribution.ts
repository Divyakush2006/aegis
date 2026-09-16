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
    PrahariAuditResult,
    PrahariClient,
    PrahariCommands,
    PrahariFinding,
    PrahariService,
    PrahariStatus,
    FINDINGS_WIDGET_ID
} from '../common/prahari-protocol';
import { PrahariFindingsWidget } from './findings-widget';

export const AuditCommand: Command = {
    id: PrahariCommands.AUDIT,
    category: PrahariCommands.CATEGORY,
    label: 'Audit Current File',
    iconClass: codicon('shield')
};

export const ShowFindingsCommand: Command = {
    id: PrahariCommands.SHOW_FINDINGS,
    category: PrahariCommands.CATEGORY,
    label: 'Show Findings Panel'
};

export const ExplainCommand: Command = {
    id: PrahariCommands.EXPLAIN,
    category: PrahariCommands.CATEGORY,
    label: 'Explain Function at Cursor'
};

export const BuildLlvmCommand: Command = {
    id: PrahariCommands.BUILD_LLVM,
    category: PrahariCommands.CATEGORY,
    label: 'Show Generated LLVM IR'
};

export const AdjudicateCommand: Command = {
    id: PrahariCommands.ADJUDICATE,
    category: PrahariCommands.CATEGORY,
    label: 'Review Findings with AI',
    iconClass: codicon('sparkle')
};

export const AiStatusCommand: Command = {
    id: PrahariCommands.AI_STATUS,
    category: PrahariCommands.CATEGORY,
    label: 'AI Adjudication Status'
};

const SEVERITY: Record<string, DiagnosticSeverity> = {
    error: DiagnosticSeverity.Error,
    warning: DiagnosticSeverity.Warning,
    note: DiagnosticSeverity.Information
};

@injectable()
export class PrahariViewContribution
    extends AbstractViewContribution<PrahariFindingsWidget>
    implements FrontendApplicationContribution, PrahariClient
{
    @inject(PrahariService) protected readonly prahari: PrahariService;
    @inject(EditorManager) protected readonly editorManager: EditorManager;
    @inject(ProblemManager) protected readonly problemManager: ProblemManager;
    @inject(MessageService) protected readonly messageService: MessageService;

    constructor() {
        super({
            widgetId: FINDINGS_WIDGET_ID,
            widgetName: PrahariFindingsWidget.LABEL,
            defaultWidgetOptions: { area: 'bottom' },
            toggleCommandId: PrahariCommands.SHOW_FINDINGS
        });
    }

    async onStart(_app: FrontendApplication): Promise<void> {
        this.prahari.setClient(this);
    }

    /**
     * Show the Explorer the first time the application is opened.
     *
     * Theia restores a saved layout when there is one, and `initializeLayout`
     * runs only when there is nothing to restore. So this applies to a fresh
     * installation and never overrides someone who collapsed the side panel
     * deliberately -- their layout is restored and this is not called.
     *
     * Without it a first run opens with the side panel collapsed and no view
     * selected, which is not what VS Code does and reads as an empty window.
     *
     * The id is `EXPLORER_VIEW_CONTAINER_ID` from `@theia/navigator`, written
     * out rather than imported so this extension keeps its small dependency
     * set. `desktop-check.js` asserts the Explorer is visible on a first run,
     * so if the id ever changes the check fails rather than the window quietly
     * coming up empty.
     */
    async initializeLayout(_app: FrontendApplication): Promise<void> {
        await this.shell.revealWidget('explorer-view-container');
    }

    // -- client notifications ----------------------------------------------

    onStatus(status: PrahariStatus): void {
        if (status.state === 'failed') {
            this.messageService.error('Prahari: analysis failed. See the log for details.');
        }
    }

    onFindings(result: PrahariAuditResult): void {
        void this.applyResult(result);
    }

    protected async applyResult(result: PrahariAuditResult): Promise<void> {
        const widget = await this.openView({ activate: false, reveal: true });
        widget.setResult(result);
        this.publishMarkers(result);
    }

    /** Mirror findings into the Problems view and the editor gutter. */
    protected publishMarkers(result: PrahariAuditResult): void {
        const byUri = new Map<string, Diagnostic[]>();
        for (const finding of result.findings) {
            const uri = finding.sink.uri;
            const list = byUri.get(uri) ?? [];
            list.push(this.toDiagnostic(finding));
            byUri.set(uri, list);
        }
        for (const [uri, diagnostics] of byUri) {
            this.problemManager.setMarkers(new URI(uri), 'prahari', diagnostics);
        }
    }

    protected toDiagnostic(finding: PrahariFinding): Diagnostic {
        const line = Math.max(finding.sink.line - 1, 0);
        const character = Math.max(finding.sink.column - 1, 0);
        const range: Range = {
            start: { line, character },
            end: { line, character: character + 12 }
        };
        return {
            range,
            severity: SEVERITY[finding.severity] ?? DiagnosticSeverity.Warning,
            source: 'prahari',
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

    /**
     * The URI to analyse, or undefined after telling the user why there is none.
     *
     * The compiler analyses C. Asked to audit a Python file it would report a
     * failed compilation, which reads as a fault in the IDE; saying what it
     * audits is the honest answer and not an error.
     */
    protected auditableUri(): string | undefined {
        const uri = this.editorManager.currentEditor?.editor.uri;
        if (!uri) {
            this.messageService.info('Prahari: open a C file (.c or .h) to audit it.');
            return undefined;
        }
        if (!/\.(c|h)$/i.test(uri.path.base)) {
            this.messageService.info(
                `Prahari audits C source (.c and .h files); ${uri.path.base} is not C. ` +
                    'Press Run to execute it, or ask Prahari AI to review it.'
            );
            return undefined;
        }
        return uri.toString();
    }

    protected async runAudit(): Promise<void> {
        const uri = this.auditableUri();
        if (!uri) {
            return;
        }
        const widget = await this.openView({ activate: true, reveal: true });
        widget.setRunning();
        const result = await this.prahari.audit(uri);
        widget.setResult(result);
        this.publishMarkers(result);
        if (result.error) {
            this.messageService.error(`Prahari: ${result.error}`);
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
        const uri = this.auditableUri();
        if (!uri) {
            return;
        }
        const widget = await this.openView({ activate: true, reveal: true });
        widget.setRunning('Reviewing findings…');
        const result = await this.prahari.adjudicate(uri);
        widget.setResult(result);
        this.publishMarkers(result);

        if (result.error) {
            this.messageService.error(`Prahari: ${result.error}`);
            return;
        }
        const summary = result.adjudication;
        if (summary && summary.enabled === false && summary.reason && !/API key/.test(summary.reason)) {
            // Configured, but refused: say what refused it rather than implying
            // the key is missing.
            this.messageService.warn(
                `Prahari: AI review unavailable (${summary.reason}). Static verdicts retained.`
            );
            return;
        }
        if (!summary || summary.enabled === false) {
            this.messageService.info(
                'Prahari: no model is configured, so the compiler\'s own verdicts stand. ' +
                    'Add OPENROUTER_API_KEY to the project .env and restart to enable review.'
            );
            return;
        }
        if (summary.errors > 0 && summary.adjudicated === 0) {
            this.messageService.warn(
                `Prahari: review unavailable (${summary.errors} failed). Static verdicts retained.`
            );
            return;
        }
        this.messageService.info(
            `Prahari: ${summary.adjudicated}/${summary.candidates} reviewed by ${summary.model} — ` +
                `${summary.dismissed} dismissed, ${summary.demoted} demoted` +
                (summary.cache_hits ? `, ${summary.cache_hits} cached` : '')
        );
    }

    protected async showAiStatus(): Promise<void> {
        const status = await this.prahari.aiStatus();
        if (status.error) {
            this.messageService.error(`Prahari: ${status.error}`);
            return;
        }
        this.messageService.info(
            status.configured
                ? `Prahari AI: ${status.model} via ${status.base_url} ` +
                      `(key ${status.key_fingerprint}) — cache ${status.cache}`
                : 'Prahari AI: not configured. Add OPENROUTER_API_KEY to the project .env to enable review; ' +
                      'the compiler and all analyses work without it.'
        );
    }

    protected async explainAtCursor(): Promise<void> {
        const editor = this.editorManager.currentEditor?.editor;
        if (!editor || !this.auditableUri()) {
            return;
        }
        const line = editor.cursor.line;
        const text = editor.document.getText();
        const name = findEnclosingFunction(text, line);
        if (!name) {
            this.messageService.info('Prahari: no function found at the cursor.');
            return;
        }
        const explanation = await this.prahari.explain(editor.uri.toString(), name);
        if (explanation.error) {
            this.messageService.error(`Prahari: ${explanation.error}`);
            return;
        }
        this.messageService.info(
            `${explanation.function}(${explanation.parameters.join(', ')}) → ${explanation.returnType} · ` +
                `${explanation.blocks} blocks, ${explanation.instructions} instructions · ` +
                `calls ${explanation.callees.join(', ') || 'nothing'} · ${explanation.taintSummary}`
        );
    }

    protected async showLlvm(): Promise<void> {
        const uri = this.auditableUri();
        if (!uri) {
            return;
        }
        const result = await this.prahari.buildLlvm(uri);
        if (result.error || !result.llvm) {
            this.messageService.error(`Prahari: ${result.error ?? 'code generation produced no output'}`);
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
