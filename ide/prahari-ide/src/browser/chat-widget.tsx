/**
 * Prahari AI: the chat panel on the right of the window.
 *
 * It sees what the developer sees — the active editor's text (unsaved edits
 * included), its selection and, for C, the compiler's findings, which the
 * backend adds — so a question such as "why is line 19 dangerous?" needs no
 * copying and pasting. Answers render as Markdown; every code block can be
 * copied or inserted at the cursor.
 *
 * Requests go to the configured free model through the same gateway as
 * adjudication. The key never reaches this process.
 */

import { codicon, Message, ReactWidget } from '@theia/core/lib/browser';
import { CoreMarkdownRenderer, MarkdownRenderer } from '@theia/core/lib/browser/markdown-rendering/markdown-renderer';
import { MarkdownStringImpl } from '@theia/core/lib/common/markdown-rendering/markdown-string';
import { MessageService } from '@theia/core/lib/common';
import { EditorManager, TextEditor } from '@theia/editor/lib/browser';
import { inject, injectable, postConstruct } from '@theia/core/shared/inversify';
import * as React from '@theia/core/shared/react';

import { CHAT_WIDGET_ID, PrahariChatTurn, PrahariService } from '../common/prahari-protocol';

interface Message_ extends PrahariChatTurn {
    model?: string;
    error?: boolean;
}

const SUGGESTIONS = [
    { label: 'Explain this file', prompt: 'Explain what this file does, section by section.' },
    { label: 'Find bugs', prompt: 'Find bugs and security problems in this file. Cite line numbers.' },
    { label: 'Fix the findings', prompt: 'Explain each Prahari finding in this file and show the corrected code.' },
    { label: 'Write tests', prompt: 'Write unit tests for the functions in this file.' }
];

@injectable()
export class PrahariChatWidget extends ReactWidget {
    static readonly ID = CHAT_WIDGET_ID;
    static readonly LABEL = 'Prahari AI';

    @inject(PrahariService) protected readonly prahari: PrahariService;
    @inject(EditorManager) protected readonly editorManager: EditorManager;
    // The markdown-it renderer, not Monaco's rebinding of MarkdownRenderer:
    // Monaco's fills code blocks asynchronously and leaves them empty without a
    // code-block callback, which is most of what an assistant replies with.
    @inject(CoreMarkdownRenderer) protected readonly markdown: MarkdownRenderer;
    @inject(MessageService) protected readonly messageService: MessageService;

    protected messages: Message_[] = [];
    protected draft = '';
    protected busy = false;
    protected includeFile = true;
    protected input: HTMLTextAreaElement | null = null;
    protected transcript: HTMLDivElement | null = null;

    @postConstruct()
    protected init(): void {
        this.id = PrahariChatWidget.ID;
        this.title.label = PrahariChatWidget.LABEL;
        this.title.caption = 'Prahari AI — ask about the open file';
        this.title.iconClass = codicon('sparkle');
        this.title.closable = true;
        this.addClass('prahari-chat');
        this.update();
    }

    protected override onActivateRequest(message: Message): void {
        super.onActivateRequest(message);
        (this.input ?? this.node).focus();
    }

    /** Put a question in the box (and optionally send it), e.g. from "Ask Prahari AI about selection". */
    ask(prompt: string, send = false): void {
        this.draft = prompt;
        this.update();
        if (send) {
            void this.send();
        } else {
            this.input?.focus();
        }
    }

    protected currentEditor(): TextEditor | undefined {
        return this.editorManager.currentEditor?.editor;
    }

    protected async send(): Promise<void> {
        const question = this.draft.trim();
        if (!question || this.busy) {
            return;
        }
        const history = this.messages.filter(m => !m.error).map(({ role, content }) => ({ role, content }));
        this.messages.push({ role: 'user', content: question });
        this.draft = '';
        this.busy = true;
        this.update();

        const editor = this.includeFile ? this.currentEditor() : undefined;
        const selection = editor ? editor.document.getText(editor.selection) : '';
        const reply = await this.prahari.chat({
            question,
            history,
            uri: editor?.uri.toString(),
            language: editor?.document.languageId,
            text: editor?.document.getText(),
            selection
        });

        if (reply.error) {
            this.messages.push({ role: 'assistant', content: this.explainError(reply.error), error: true, model: reply.model });
        } else {
            this.messages.push({ role: 'assistant', content: reply.reply, model: reply.model });
        }
        this.busy = false;
        this.update();
    }

    protected explainError(error: string): string {
        if (/API key|no model is configured/i.test(error)) {
            return (
                '**Prahari AI is not configured.** Add a free OpenRouter key to the project `.env` ' +
                '(`OPENROUTER_API_KEY=...`) and restart the IDE. Everything else — Run, Audit, the findings panel — works without it.'
            );
        }
        return `**The model could not answer:** ${error}`;
    }

    protected clear(): void {
        this.messages = [];
        this.update();
    }

    protected override onUpdateRequest(message: Message): void {
        super.onUpdateRequest(message);
        requestAnimationFrame(() => this.scrollToEnd());
    }

    protected scrollToEnd(): void {
        if (this.transcript) {
            this.transcript.scrollTop = this.transcript.scrollHeight;
        }
    }

    // -- rendering ------------------------------------------------------------

    protected render(): React.ReactNode {
        const editor = this.currentEditor();
        const fileName = editor?.uri.path.base;
        return (
            <div className='prahari-chat-panel'>
                <div className='prahari-chat-header'>
                    <span className={codicon('sparkle')} />
                    <span className='prahari-chat-title'>Prahari AI</span>
                    <span className='prahari-chat-spacer' />
                    <button
                        className={`prahari-chat-icon ${codicon('clear-all')}`}
                        title='New conversation'
                        onClick={() => this.clear()}
                        disabled={this.busy || this.messages.length === 0}
                    />
                </div>

                <div className='prahari-chat-transcript' ref={element => { this.transcript = element; }}>
                    {this.messages.length === 0 ? this.renderWelcome() : this.messages.map((m, i) => this.renderMessage(m, i))}
                    {this.busy && (
                        <div className='prahari-chat-message assistant prahari-chat-thinking'>
                            <span className={`${codicon('loading')} theia-animation-spin`} /> Thinking…
                        </div>
                    )}
                </div>

                <div className='prahari-chat-composer'>
                    <label className='prahari-chat-context' title='Send the active editor, its selection and its Prahari findings with the question'>
                        <input
                            type='checkbox'
                            checked={this.includeFile}
                            onChange={event => {
                                this.includeFile = event.currentTarget.checked;
                                this.update();
                            }}
                        />
                        <span className={codicon('file-code')} />
                        {this.includeFile ? (fileName ? `Context: ${fileName}` : 'No file open') : 'No file context'}
                    </label>
                    <div className='prahari-chat-input-row'>
                        <textarea
                            ref={element => { this.input = element; }}
                            className='theia-input prahari-chat-input'
                            placeholder='Ask Prahari AI… (Enter to send, Shift+Enter for a new line)'
                            rows={3}
                            value={this.draft}
                            onChange={event => {
                                this.draft = event.currentTarget.value;
                                this.update();
                            }}
                            onKeyDown={event => {
                                if (event.key === 'Enter' && !event.shiftKey) {
                                    event.preventDefault();
                                    void this.send();
                                }
                            }}
                        />
                        <button
                            className={`theia-button prahari-chat-send ${codicon('send')}`}
                            title='Send'
                            disabled={this.busy || !this.draft.trim()}
                            onClick={() => void this.send()}
                        />
                    </div>
                </div>
            </div>
        );
    }

    protected renderWelcome(): React.ReactNode {
        return (
            <div className='prahari-chat-welcome'>
                <div className={`prahari-chat-welcome-icon ${codicon('sparkle')}`} />
                <h3>Ask Prahari AI</h3>
                <p>Questions are answered with the open file, your selection and the compiler’s findings as context, using a free model.</p>
                <div className='prahari-chat-suggestions'>
                    {SUGGESTIONS.map(s => (
                        <button key={s.label} className='prahari-chat-suggestion' onClick={() => this.ask(s.prompt, true)}>
                            {s.label}
                        </button>
                    ))}
                </div>
            </div>
        );
    }

    protected renderMessage(message: Message_, index: number): React.ReactNode {
        return (
            <div key={index} className={`prahari-chat-message ${message.role}${message.error ? ' error' : ''}`}>
                <div className='prahari-chat-author'>
                    <span className={codicon(message.role === 'user' ? 'account' : 'sparkle')} />
                    {message.role === 'user' ? 'You' : 'Prahari AI'}
                    {message.model && <span className='prahari-chat-model'>{message.model}</span>}
                </div>
                {message.role === 'user' ? (
                    <div className='prahari-chat-text'>{message.content}</div>
                ) : (
                    <MarkdownView source={message.content} renderer={this.markdown} onInsert={code => this.insert(code)} onRendered={() => this.scrollToEnd()} />
                )}
            </div>
        );
    }

    protected insert(code: string): void {
        const editor = this.currentEditor();
        if (!editor) {
            this.messageService.info('Prahari AI: open a file to insert code into.');
            return;
        }
        editor.executeEdits([{ range: editor.selection, newText: code }]);
        editor.focus();
    }
}

/** Markdown rendered once per message, with Copy and Insert on every code block. */
function MarkdownView(props: { source: string; renderer: MarkdownRenderer; onInsert: (code: string) => void; onRendered: () => void }): React.ReactElement {
    const host = React.useRef<HTMLDivElement>(null);
    React.useEffect(() => {
        const element = host.current;
        if (!element) {
            return;
        }
        const result = props.renderer.render(new MarkdownStringImpl(props.source), undefined, undefined);
        element.replaceChildren(result.element);
        for (const pre of Array.from(element.querySelectorAll('pre'))) {
            const code = pre.textContent ?? '';
            const bar = document.createElement('div');
            bar.className = 'prahari-chat-code-actions';
            for (const [label, icon, action] of [
                ['Copy', 'copy', () => void navigator.clipboard.writeText(code)],
                ['Insert at cursor', 'insert', () => props.onInsert(code.replace(/\n$/, ''))]
            ] as const) {
                const button = document.createElement('button');
                button.className = `prahari-chat-icon ${codicon(icon)}`;
                button.title = label;
                button.onclick = action;
                bar.appendChild(button);
            }
            pre.classList.add('prahari-chat-code');
            pre.prepend(bar);
        }
        // The reply is taller now than when the transcript last scrolled.
        props.onRendered();
        return () => result.dispose();
    }, [props.source]);
    return <div className='prahari-chat-text prahari-chat-markdown' ref={host} />;
}
