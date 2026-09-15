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

import { AEGIS_SERVICE_PATH, AegisService, FINDINGS_WIDGET_ID } from '../common/aegis-protocol';
import { AegisViewContribution } from './aegis-contribution';
import { AegisCLanguageContribution } from './c-language';
import { AegisFindingsWidget } from './findings-widget';

import '../../src/browser/style/index.css';

export default new ContainerModule(bind => {
    // C highlighting and editing behaviour; see c-language.ts for why the IDE
    // registers the language itself.
    bind(AegisCLanguageContribution).toSelf().inSingletonScope();
    bind(FrontendApplicationContribution).toService(AegisCLanguageContribution);

    bind(AegisFindingsWidget).toSelf();
    bind(WidgetFactory)
        .toDynamicValue(context => ({
            id: FINDINGS_WIDGET_ID,
            createWidget: () => context.container.get<AegisFindingsWidget>(AegisFindingsWidget)
        }))
        .inSingletonScope();

    bindViewContribution(bind, AegisViewContribution);
    bind(FrontendApplicationContribution).toService(AegisViewContribution);

    bind(AegisService)
        .toDynamicValue(context => {
            const provider = context.container.get<ServiceConnectionProvider>(RemoteConnectionProvider);
            // The client is registered by the view contribution on start, so the
            // proxy is created without one here.
            return provider.createProxy<AegisService>(AEGIS_SERVICE_PATH);
        })
        .inSingletonScope();
});
