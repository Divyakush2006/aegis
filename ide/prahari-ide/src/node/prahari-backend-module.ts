/**
 * Backend dependency injection: exposes the Prahari service over Theia's RPC.
 */

import { ConnectionHandler, RpcConnectionHandler } from '@theia/core/lib/common/messaging';
import { ContainerModule } from '@theia/core/shared/inversify';

import { PRAHARI_SERVICE_PATH, PrahariClient, PrahariService } from '../common/prahari-protocol';
import { PrahariServerImpl } from './prahari-server';

export default new ContainerModule(bind => {
    bind(PrahariServerImpl).toSelf().inSingletonScope();
    bind(PrahariService).toService(PrahariServerImpl);

    bind(ConnectionHandler)
        .toDynamicValue(
            context =>
                new RpcConnectionHandler<PrahariClient>(PRAHARI_SERVICE_PATH, client => {
                    const server = context.container.get<PrahariServerImpl>(PrahariServerImpl);
                    server.setClient(client);
                    // One Python process per connected frontend; dropping the
                    // client must not leave an orphaned child process behind.
                    client.onDidCloseConnection?.(() => server.setClient(undefined));
                    return server;
                })
        )
        .inSingletonScope();
});
