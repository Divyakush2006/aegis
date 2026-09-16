/**
 * Run and Stop: the play button for every file.
 *
 * The backend decides *how* a file runs (`node/run-planner.ts`); this side
 * saves the editor, carries the plan out — a terminal for programs, a preview
 * for pages and Markdown, the operating system for everything else — and keeps
 * one "Run" terminal, replaced on each run, as VS Code's Run does.
 */

import { codicon, KeybindingContribution, KeybindingRegistry, OpenerService, Widget } from '@theia/core/lib/browser';
import { Command, CommandContribution, CommandRegistry, Emitter, MenuContribution, MenuModelRegistry, MessageService } from '@theia/core/lib/common';
import { MAIN_MENU_BAR } from '@theia/core/lib/common/menu';
import URI from '@theia/core/lib/common/uri';
import { inject, injectable } from '@theia/core/shared/inversify';
import { EditorManager, EditorWidget } from '@theia/editor/lib/browser';
import { TerminalService } from '@theia/terminal/lib/browser/base/terminal-service';
import { TerminalWidget } from '@theia/terminal/lib/browser/base/terminal-widget';

import { PrahariCommands, PrahariService } from '../common/prahari-protocol';

export const RunFileCommand: Command = {
    id: PrahariCommands.RUN_FILE,
    category: 'Run',
    label: 'Run File',
    iconClass: codicon('play')
};

export const StopRunCommand: Command = {
    id: PrahariCommands.STOP_RUN,
    category: 'Run',
    label: 'Stop Running File',
    iconClass: codicon('debug-stop')
};

/** The Run menu, as `@theia/debug` names it; written out to keep this extension's dependencies small. */
const RUN_MENU = [...MAIN_MENU_BAR, '6_debug', '0_prahari_run'];

/** A toolbar passes the widget it belongs to; the palette and keybindings pass nothing. */
export function editorFor(editorManager: EditorManager, widget?: unknown): EditorWidget | undefined {
    return widget instanceof EditorWidget ? widget : widget instanceof Widget ? undefined : editorManager.currentEditor;
}

@injectable()
export class PrahariRunContribution implements CommandContribution, MenuContribution, KeybindingContribution {
    @inject(PrahariService) protected readonly prahari: PrahariService;
    @inject(EditorManager) protected readonly editorManager: EditorManager;
    @inject(TerminalService) protected readonly terminals: TerminalService;
    @inject(OpenerService) protected readonly openers: OpenerService;
    @inject(CommandRegistry) protected readonly commands: CommandRegistry;
    @inject(MessageService) protected readonly messages: MessageService;

    protected runTerminal: TerminalWidget | undefined;
    /** Fires when the Run terminal appears or goes away, so the Stop button follows it. */
    protected readonly onDidChangeRunningEmitter = new Emitter<void>();
    readonly onDidChangeRunning = this.onDidChangeRunningEmitter.event;

    registerCommands(registry: CommandRegistry): void {
        registry.registerCommand(RunFileCommand, {
            execute: (widget?: unknown) => this.run(editorFor(this.editorManager, widget)),
            isVisible: (widget?: unknown) => widget === undefined || widget instanceof EditorWidget,
            isEnabled: (widget?: unknown) => !!editorFor(this.editorManager, widget)
        });
        registry.registerCommand(StopRunCommand, {
            execute: () => this.stop(),
            isVisible: (widget?: unknown) => this.hasRunTerminal() && (widget === undefined || widget instanceof EditorWidget),
            isEnabled: () => this.hasRunTerminal()
        });
    }

    registerMenus(menus: MenuModelRegistry): void {
        menus.registerMenuAction(RUN_MENU, { commandId: RunFileCommand.id, label: 'Run File', order: '0' });
        menus.registerMenuAction(RUN_MENU, { commandId: StopRunCommand.id, label: 'Stop Running File', order: '1' });
    }

    registerKeybindings(keybindings: KeybindingRegistry): void {
        // Code Runner's binding, the one VS Code users already know for "run this file".
        keybindings.registerKeybinding({ command: RunFileCommand.id, keybinding: 'ctrlcmd+alt+n' });
        keybindings.registerKeybinding({ command: StopRunCommand.id, keybinding: 'ctrlcmd+alt+m' });
    }

    protected hasRunTerminal(): boolean {
        return !!this.runTerminal && !this.runTerminal.isDisposed;
    }

    async run(widget: EditorWidget | undefined): Promise<void> {
        if (!widget) {
            this.messages.info('Open a file, then press Run.');
            return;
        }
        const uri = widget.editor.uri;
        if (uri.scheme !== 'file') {
            this.messages.info(`Save ${uri.path.base} to a folder first — a file has to exist on disk to run.`);
            return;
        }
        if (widget.saveable.dirty) {
            await widget.saveable.save();
        }

        const plan = await this.prahari.planRun(uri.toString());
        switch (plan.kind) {
            case 'terminal':
                return this.runInTerminal(uri, plan.shellPath!, plan.shellArgs!);
            case 'preview':
                return this.preview(uri);
            case 'markdown':
                return this.previewMarkdown(uri);
            case 'external': {
                const result = await this.prahari.openExternally(uri.toString());
                if (result.error) {
                    this.messages.warn(`Could not open ${uri.path.base} with the system: ${result.error}`);
                } else {
                    this.messages.info(`${uri.path.base} is not a program Prahari can execute, so it was opened with ${plan.runner}.`);
                }
                return;
            }
            case 'info':
                this.messages.info(plan.message);
                return;
            case 'unavailable':
                this.messages.warn(plan.message);
                return;
        }
    }

    protected async runInTerminal(uri: URI, shellPath: string, shellArgs: string[]): Promise<void> {
        if (this.hasRunTerminal()) {
            // One Run terminal, as in VS Code: a new run replaces the previous one.
            this.runTerminal!.dispose();
        }
        const terminal = await this.terminals.newTerminal({
            title: `Run: ${uri.path.base}`,
            iconClass: codicon('play'),
            shellPath,
            shellArgs,
            cwd: uri.parent.toString(),
            destroyTermOnClose: true,
            useServerTitle: false
        });
        this.runTerminal = terminal;
        const forget = () => {
            if (this.runTerminal === terminal) {
                this.runTerminal = undefined;
                this.onDidChangeRunningEmitter.fire();
            }
        };
        terminal.onTerminalDidClose(forget);
        terminal.disposed.connect(forget);
        this.onDidChangeRunningEmitter.fire();
        await terminal.start();
        await this.terminals.open(terminal, { mode: 'activate' });
    }

    protected async preview(uri: URI): Promise<void> {
        try {
            const opener = await this.openers.getOpener(uri, { openFor: 'preview' });
            await opener.open(uri, { openFor: 'preview', mode: 'activate', widgetOptions: { mode: 'split-right' } } as object);
        } catch (error) {
            this.messages.warn(`Could not preview ${uri.path.base}: ${error}`);
        }
    }

    protected async previewMarkdown(uri: URI): Promise<void> {
        // The built-in VS Code Markdown extension renders the preview; it acts on the active editor.
        for (const id of ['markdown.showPreviewToSide', 'markdown.showPreview']) {
            if (this.commands.getCommand(id)) {
                await this.commands.executeCommand(id);
                return;
            }
        }
        this.messages.info(`${uri.path.base} is Markdown. Run \`npm run download:plugins\` to add the Markdown preview.`);
    }

    protected stop(): void {
        if (this.hasRunTerminal()) {
            this.runTerminal!.sendText('\x03');
        }
    }
}
