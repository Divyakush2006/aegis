/**
 * Backend dependency injection: exposes the Aegis service over Theia's RPC.
 */

import { ConnectionHandler, RpcConnectionHandler } from '@theia/core/lib/common/messaging';
import { ContainerModule } from '@theia/core/shared/inversify';

import { AEGIS_SERVICE_PATH, AegisClient, AegisService } from '../common/aegis-protocol';
import { AegisServerImpl } from './aegis-server';

export default new ContainerModule(bind => {
    bind(AegisServerImpl).toSelf().inSingletonScope();
    bind(AegisService).toService(AegisServerImpl);

    bind(ConnectionHandler)
        .toDynamicValue(
            context =>
                new RpcConnectionHandler<AegisClient>(AEGIS_SERVICE_PATH, client => {
                    const server = context.container.get<AegisServerImpl>(AegisServerImpl);
                    server.setClient(client);
                    // One Python process per connected frontend; dropping the
                    // client must not leave an orphaned child process behind.
                    client.onDidCloseConnection?.(() => server.setClient(undefined));
                    return server;
                })
        )
        .inSingletonScope();
});
