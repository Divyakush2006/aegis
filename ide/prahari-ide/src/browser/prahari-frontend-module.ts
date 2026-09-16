/**
 * Frontend dependency injection.
 *
 * Binds the findings widget, the view contribution, and the RPC proxy that
 * reaches the backend service running in Theia's Node process.
 */

import { bindViewContribution, FrontendApplicationContribution, WidgetFactory } from '@theia/core/lib/browser';
import {
    RemoteConnectionProvider,
    ServiceConnectionProvider
} from '@theia/core/lib/browser/messaging/service-connection-provider';
import { ContainerModule } from '@theia/core/shared/inversify';

import { CHAT_WIDGET_ID, PRAHARI_SERVICE_PATH, PrahariService, FINDINGS_WIDGET_ID } from '../common/prahari-protocol';
import { PrahariViewContribution } from './prahari-contribution';
import { PrahariCLanguageContribution } from './c-language';
import { PrahariFindingsWidget } from './findings-widget';
import { PrahariChatWidget } from './chat-widget';
import { PrahariWelcomeWidget } from './welcome-widget';
import { GettingStartedWidget } from '@theia/getting-started/lib/browser/getting-started-widget';
import { PrahariRunContribution } from './run-contribution';
import { PrahariChatContribution } from './toolbar-contribution';
import { CommandContribution, MenuContribution } from '@theia/core/lib/common';
import { KeybindingContribution } from '@theia/core/lib/browser';
import { TabBarToolbarContribution } from '@theia/core/lib/browser/shell/tab-bar-toolbar';

import '../../src/browser/style/index.css';
// The application logo, in the slot Theia leaves at the far left of the menu
// bar. Generated with the icons by scripts/make-app-icon.py.
import '../../src/browser/style/logo.css';
import '../../src/browser/style/chat.css';

export default new ContainerModule((bind, _unbind, _isBound, rebind) => {
    // C highlighting and editing behaviour; see c-language.ts for why the IDE
    // registers the language itself.
    bind(PrahariCLanguageContribution).toSelf().inSingletonScope();
    bind(FrontendApplicationContribution).toService(PrahariCLanguageContribution);

    bind(PrahariFindingsWidget).toSelf();
    bind(WidgetFactory)
        .toDynamicValue(context => ({
            id: FINDINGS_WIDGET_ID,
            createWidget: () => context.container.get<PrahariFindingsWidget>(PrahariFindingsWidget)
        }))
        .inSingletonScope();

    bindViewContribution(bind, PrahariViewContribution);
    bind(FrontendApplicationContribution).toService(PrahariViewContribution);

    // Run and Stop for every file type; see node/run-planner.ts for how each runs.
    bind(PrahariRunContribution).toSelf().inSingletonScope();
    bind(CommandContribution).toService(PrahariRunContribution);
    bind(MenuContribution).toService(PrahariRunContribution);
    bind(KeybindingContribution).toService(PrahariRunContribution);

    // Prahari AI: the chat panel, and the editor and title-bar buttons.
    bind(PrahariChatWidget).toSelf();
    bind(WidgetFactory)
        .toDynamicValue(context => ({
            id: CHAT_WIDGET_ID,
            createWidget: () => context.container.get<PrahariChatWidget>(PrahariChatWidget)
        }))
        .inSingletonScope();
    bindViewContribution(bind, PrahariChatContribution);
    bind(FrontendApplicationContribution).toService(PrahariChatContribution);
    bind(TabBarToolbarContribution).toService(PrahariChatContribution);

    // The Welcome page offers Run, Audit and Prahari AI instead of Theia AI's banner.
    bind(PrahariWelcomeWidget).toSelf();
    rebind(GettingStartedWidget).toService(PrahariWelcomeWidget);

    bind(PrahariService)
        .toDynamicValue(context => {
            const provider = context.container.get<ServiceConnectionProvider>(RemoteConnectionProvider);
            // The client is registered by the view contribution on start, so the
            // proxy is created without one here.
            return provider.createProxy<PrahariService>(PRAHARI_SERVICE_PATH);
        })
        .inSingletonScope();
});
