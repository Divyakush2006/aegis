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

import { PRAHARI_SERVICE_PATH, PrahariService, FINDINGS_WIDGET_ID } from '../common/prahari-protocol';
import { PrahariViewContribution } from './prahari-contribution';
import { PrahariCLanguageContribution } from './c-language';
import { PrahariFindingsWidget } from './findings-widget';

import '../../src/browser/style/index.css';

export default new ContainerModule(bind => {
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

    bind(PrahariService)
        .toDynamicValue(context => {
            const provider = context.container.get<ServiceConnectionProvider>(RemoteConnectionProvider);
            // The client is registered by the view contribution on start, so the
            // proxy is created without one here.
            return provider.createProxy<PrahariService>(PRAHARI_SERVICE_PATH);
        })
        .inSingletonScope();
});
