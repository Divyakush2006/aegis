/**
 * The Welcome page, with Prahari's own actions in place of Theia AI's banner.
 *
 * `@theia/plugin-ext` brings in `@theia/ai-core`, and the stock Welcome page
 * reacts to its presence with a banner inviting the user to configure Theia AI
 * and warning that it "might incur costs". Prahari IDE's assistant is Prahari
 * AI, on free models only, so that banner describes a different product. This
 * replaces it with a section for what this IDE actually offers: Run, Audit and
 * Prahari AI.
 */

import { codicon } from '@theia/core/lib/browser';
import { CommandService } from '@theia/core/lib/common';
import { inject, injectable } from '@theia/core/shared/inversify';
import * as React from '@theia/core/shared/react';
import { GettingStartedWidget } from '@theia/getting-started/lib/browser/getting-started-widget';

import { PrahariCommands } from '../common/prahari-protocol';

@injectable()
export class PrahariWelcomeWidget extends GettingStartedWidget {
    @inject(CommandService) protected readonly prahariCommands: CommandService;

    protected override async doInit(): Promise<void> {
        await super.doInit();
        this.aiIsIncluded = false;
        this.update();
    }

    protected override renderStart(): React.ReactNode {
        const action = (label: string, icon: string, command: string, detail: string) => (
            <div className='gs-action-container'>
                <a
                    role='button'
                    tabIndex={0}
                    className='prahari-welcome-action'
                    onClick={() => void this.prahariCommands.executeCommand(command)}
                    onKeyDown={event => {
                        if (event.key === 'Enter') {
                            void this.prahariCommands.executeCommand(command);
                        }
                    }}
                >
                    <i className={codicon(icon)} /> {label}
                </a>
                <span className='prahari-welcome-detail'> — {detail}</span>
            </div>
        );
        return (
            <>
                <div className='gs-section prahari-welcome'>
                    <h3 className='gs-section-header'>
                        <i className={codicon('shield')} />
                        Prahari
                    </h3>
                    {action('Run File', 'play', PrahariCommands.RUN_FILE, 'any language, Ctrl+Alt+N')}
                    {action('Audit Current File', 'shield', PrahariCommands.AUDIT, 'dataflow security analysis of C, Ctrl+Alt+A')}
                    {action('Open Prahari AI', 'sparkle', PrahariCommands.OPEN_CHAT, 'ask about the open file, free models, Ctrl+Alt+I')}
                </div>
                {super.renderStart()}
            </>
        );
    }
}
