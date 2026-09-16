/**
 * The buttons: Prahari AI's view, the editor's title-bar actions, and the
 * actions at the top right of the window.
 *
 * Each action exists in three places a VS Code user looks for it — the editor
 * tab bar (Run, Stop, Audit, Ask AI), the window's title bar (Run, Audit,
 * Prahari AI) and the command palette with a keybinding — and every one of
 * them executes the same registered command, so they cannot behave differently.
 */

import {
    AbstractViewContribution,
    codicon,
    FrontendApplication,
    FrontendApplicationContribution,
    KeybindingRegistry
} from '@theia/core/lib/browser';
import { TabBarToolbarContribution, TabBarToolbarRegistry } from '@theia/core/lib/browser/shell/tab-bar-toolbar';
import { Command, CommandRegistry, CommandService, MenuModelRegistry } from '@theia/core/lib/common';
import { inject, injectable } from '@theia/core/shared/inversify';
import { EditorManager, EditorWidget, EDITOR_CONTEXT_MENU } from '@theia/editor/lib/browser';

import { CHAT_WIDGET_ID, PrahariCommands } from '../common/prahari-protocol';
import { PrahariChatWidget } from './chat-widget';
import { editorFor, PrahariRunContribution, RunFileCommand, StopRunCommand } from './run-contribution';

export const OpenChatCommand: Command = {
    id: PrahariCommands.OPEN_CHAT,
    category: PrahariCommands.CATEGORY,
    label: 'Open Prahari AI',
    iconClass: codicon('sparkle')
};

export const AskAboutSelectionCommand: Command = {
    id: PrahariCommands.ASK_ABOUT_SELECTION,
    category: PrahariCommands.CATEGORY,
    label: 'Ask Prahari AI',
    iconClass: codicon('sparkle')
};

/** Languages the compiler audits. */
export function isAuditable(widget: EditorWidget | undefined): boolean {
    return !!widget && /\.(c|h)$/i.test(widget.editor.uri.path.base);
}

@injectable()
export class PrahariChatContribution
    extends AbstractViewContribution<PrahariChatWidget>
    implements FrontendApplicationContribution, TabBarToolbarContribution
{
    @inject(EditorManager) protected readonly editorManager: EditorManager;
    @inject(CommandService) protected readonly commandService: CommandService;
    @inject(PrahariRunContribution) protected readonly runs: PrahariRunContribution;

    constructor() {
        super({
            widgetId: CHAT_WIDGET_ID,
            widgetName: PrahariChatWidget.LABEL,
            // The right side panel — VS Code's secondary side bar, where its chat lives.
            defaultWidgetOptions: { area: 'right', rank: 100 }
            // No toggleCommandId: the generic "Toggle … View" command has no
            // icon, and the toolbar and palette should say Prahari AI.
        });
    }

    /**
     * Keep Prahari AI's tab on the right-hand side bar in every layout, including
     * one restored from before the panel existed, without opening it uninvited.
     */
    async onDidInitializeLayout(app: FrontendApplication): Promise<void> {
        if (!this.shell.getWidgets('right').some(widget => widget.id === CHAT_WIDGET_ID)) {
            await this.openView({ activate: false, reveal: false });
        }
        this.addTitleBarActions(app);
    }

    override registerCommands(registry: CommandRegistry): void {
        super.registerCommands(registry);
        registry.registerCommand(OpenChatCommand, {
            execute: () => this.toggleChat(),
            isVisible: (widget?: unknown) => widget === undefined || widget instanceof EditorWidget
        });
        registry.registerCommand(AskAboutSelectionCommand, {
            execute: async () => {
                const editor = this.editorManager.currentEditor?.editor;
                const selected = editor ? editor.document.getText(editor.selection).trim() : '';
                const widget = await this.openView({ activate: true, reveal: true });
                widget.ask(selected ? 'Explain the selected code and point out any problems in it.' : 'Explain what this file does.', false);
            }
        });
    }

    /** Open Prahari AI and focus its input; if it is already active, close the side bar. */
    protected async toggleChat(): Promise<void> {
        const widget = this.tryGetWidget();
        if (widget && widget.isVisible && this.shell.activeWidget === widget) {
            await this.closeView();
            return;
        }
        await this.openView({ activate: true, reveal: true });
    }

    override registerKeybindings(keybindings: KeybindingRegistry): void {
        super.registerKeybindings(keybindings);
        keybindings.registerKeybinding({ command: OpenChatCommand.id, keybinding: 'ctrlcmd+alt+i' });
    }

    override registerMenus(menus: MenuModelRegistry): void {
        super.registerMenus(menus);
        menus.registerMenuAction(['menubar', '4_view', '1_prahari'], {
            commandId: OpenChatCommand.id,
            label: 'Prahari AI'
        });
        menus.registerMenuAction([...EDITOR_CONTEXT_MENU, '0_prahari'], {
            commandId: AskAboutSelectionCommand.id,
            label: 'Ask Prahari AI',
            order: '0'
        });
        menus.registerMenuAction([...EDITOR_CONTEXT_MENU, '0_prahari'], {
            commandId: RunFileCommand.id,
            label: 'Run File',
            order: '1'
        });
        menus.registerMenuAction([...EDITOR_CONTEXT_MENU, '0_prahari'], {
            commandId: PrahariCommands.AUDIT,
            label: 'Prahari: Audit Current File',
            order: '2'
        });
    }

    registerToolbarItems(toolbar: TabBarToolbarRegistry): void {
        toolbar.registerItem({
            id: 'prahari.toolbar.run',
            command: RunFileCommand.id,
            tooltip: 'Run File (Ctrl+Alt+N)',
            priority: 0
        });
        toolbar.registerItem({
            id: 'prahari.toolbar.stop',
            command: StopRunCommand.id,
            tooltip: 'Stop Running File (Ctrl+Alt+M)',
            priority: 1,
            onDidChange: this.runs.onDidChangeRunning
        });
        toolbar.registerItem({
            id: 'prahari.toolbar.audit',
            command: PrahariCommands.AUDIT,
            tooltip: 'Prahari: Audit Current File (Ctrl+Alt+A)',
            priority: 2,
            isVisible: widget => widget instanceof EditorWidget && isAuditable(widget)
        });
        toolbar.registerItem({
            id: 'prahari.toolbar.ask',
            command: OpenChatCommand.id,
            tooltip: 'Open Prahari AI (Ctrl+Alt+I)',
            priority: 3,
            isVisible: widget => widget instanceof EditorWidget
        });
    }

    /**
     * Run, Audit and Prahari AI at the top right of the window.
     *
     * Theia's title bar has no contribution point for buttons, so they are added
     * to its top panel the way Theia adds its own window controls, and placed
     * immediately to their left on the desktop.
     */
    protected addTitleBarActions(app: FrontendApplication): void {
        const panel = app.shell.topPanel.node;
        if (panel.querySelector('#prahari-title-actions')) {
            return;
        }
        const bar = document.createElement('div');
        bar.id = 'prahari-title-actions';
        const actions: { id: string; icon: string; label?: string; title: string; command: string; enabled?: () => boolean }[] = [
            { id: 'prahari-title-run', icon: 'play', title: 'Run File (Ctrl+Alt+N)', command: RunFileCommand.id, enabled: () => !!editorFor(this.editorManager) },
            { id: 'prahari-title-audit', icon: 'shield', label: 'Audit', title: 'Prahari: Audit Current File (Ctrl+Alt+A)', command: PrahariCommands.AUDIT, enabled: () => isAuditable(this.editorManager.currentEditor) },
            { id: 'prahari-title-ai', icon: 'sparkle', label: 'Prahari AI', title: 'Toggle Prahari AI (Ctrl+Alt+I)', command: OpenChatCommand.id }
        ];
        const buttons: [HTMLButtonElement, (() => boolean) | undefined][] = [];
        for (const action of actions) {
            const button = document.createElement('button');
            button.id = action.id;
            button.className = 'prahari-title-action';
            button.title = action.title;
            const icon = document.createElement('span');
            icon.className = codicon(action.icon);
            button.appendChild(icon);
            if (action.label) {
                const text = document.createElement('span');
                text.textContent = action.label;
                button.appendChild(text);
            }
            button.addEventListener('click', () => void this.commandService.executeCommand(action.command));
            bar.appendChild(button);
            buttons.push([button, action.enabled]);
        }
        const refresh = () => {
            for (const [button, enabled] of buttons) {
                button.classList.toggle('prahari-disabled', !!enabled && !enabled());
            }
        };
        this.editorManager.onCurrentEditorChanged(refresh);
        refresh();

        const controls = panel.querySelector('#window-controls');
        if (controls) {
            bar.classList.add('prahari-beside-window-controls');
            panel.insertBefore(bar, controls);
        } else {
            panel.appendChild(bar);
        }
    }
}
