/**
 * Backend service: drives the Prahari language server from Theia's Node process.
 *
 * The Python compiler runs as a child process speaking LSP over stdio, exactly
 * as it would for any other editor. The IDE gains nothing from a private
 * protocol, and using the standard one means the same server already works in
 * Neovim or Emacs — the editor is a client of the compiler, not a host for it.
 *
 * The server is started lazily on first use and restarted if it dies, so a
 * crash in analysis degrades the IDE rather than breaking it.
 */

import { ILogger } from '@theia/core/lib/common/logger';
import { inject, injectable, postConstruct } from '@theia/core/shared/inversify';
import { ChildProcess, spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import {
    createMessageConnection,
    MessageConnection,
    StreamMessageReader,
    StreamMessageWriter
} from 'vscode-jsonrpc/node';

import {
    PrahariAiStatus,
    PrahariAuditResult,
    PrahariClient,
    PrahariExplanation,
    PrahariService
} from '../common/prahari-protocol';

/** Notifications the Python server pushes; mirrored in `server/lsp_server.py`. */
const FINDINGS_NOTIFICATION = 'prahari/findings';
const STATUS_NOTIFICATION = 'prahari/status';

/** Which interpreter runs the compiler; overridable for a virtualenv. */
const PYTHON = process.env.PRAHARI_PYTHON || 'python';

/**
 * Locate the `compiler/` directory.
 *
 * A fixed path relative to `__dirname` depends on where the code happens to
 * run from. esbuild moves this code into `browser-app/lib/backend/`, and the
 * old `../../../../compiler` resolves correctly there only because that
 * directory sits exactly four levels below the project root -- a coincidence
 * any change to the build layout would break silently. So the root is searched
 * for, upward from this file and from the working directory, by the one thing
 * that identifies it: the Python package itself.
 */
export function findCompilerRoot(
    explicit: string | undefined = process.env.PRAHARI_COMPILER_ROOT,
    starts: string[] = [__dirname, process.cwd()]
): string {
    if (explicit) {
        return path.resolve(explicit);
    }
    for (const start of starts) {
        let directory = path.resolve(start);
        while (true) {
            const candidate = path.join(directory, 'compiler');
            if (fs.existsSync(path.join(candidate, 'src', 'prahari', '__init__.py'))) {
                return candidate;
            }
            const parent = path.dirname(directory);
            if (parent === directory) {
                break;
            }
            directory = parent;
        }
    }
    // The source-tree layout, as a last resort; the spawn error will name it.
    return path.resolve(__dirname, '../../../../compiler');
}

const COMPILER_ROOT = findCompilerRoot();

@injectable()
export class PrahariServerImpl implements PrahariService {
    @inject(ILogger) protected readonly logger: ILogger;

    protected client: PrahariClient | undefined;
    protected process: ChildProcess | undefined;
    protected connection: MessageConnection | undefined;
    protected starting: Promise<MessageConnection> | undefined;

    @postConstruct()
    protected init(): void {
        // Started lazily: an IDE window that never audits should never pay for
        // a Python process.
    }

    setClient(client: PrahariClient | undefined): void {
        this.client = client;
    }

    async isReady(): Promise<boolean> {
        try {
            await this.ensureConnection();
            return true;
        } catch {
            return false;
        }
    }

    // -- process lifecycle --------------------------------------------------

    protected async ensureConnection(): Promise<MessageConnection> {
        if (this.connection) {
            return this.connection;
        }
        if (!this.starting) {
            this.starting = this.start().finally(() => {
                this.starting = undefined;
            });
        }
        return this.starting;
    }

    protected async start(): Promise<MessageConnection> {
        this.logger.info(`Starting the Prahari language server: ${PYTHON} in ${COMPILER_ROOT}`);
        const child = spawn(PYTHON, ['-m', 'prahari.server.lsp_server'], {
            cwd: COMPILER_ROOT,
            env: {
                ...process.env,
                PYTHONPATH: path.join(COMPILER_ROOT, 'src'),
                PYTHONIOENCODING: 'utf-8',
                PYTHONUNBUFFERED: '1'
            },
            stdio: ['pipe', 'pipe', 'pipe']
        });

        child.stderr?.on('data', data => this.logger.debug(`[prahari] ${data}`));
        child.on('exit', code => {
            this.logger.warn(`Prahari language server exited with code ${code}`);
            this.connection = undefined;
            this.process = undefined;
        });
        child.on('error', error => {
            this.logger.error(`Failed to start the Prahari language server: ${error}`);
            this.connection = undefined;
            this.process = undefined;
        });

        // `@types/node` has drifted from the stream interfaces vscode-jsonrpc 8
        // was typed against (an async-iterator signature changed). The objects
        // are structurally correct at runtime, so this reconciles the types
        // narrowly rather than widening the whole call to `any`.
        const connection = createMessageConnection(
            new StreamMessageReader(child.stdout! as unknown as NodeJS.ReadableStream),
            new StreamMessageWriter(child.stdin! as unknown as NodeJS.WritableStream)
        );

        connection.onNotification(FINDINGS_NOTIFICATION, (result: PrahariAuditResult) =>
            this.client?.onFindings(result)
        );
        connection.onNotification(STATUS_NOTIFICATION, status => this.client?.onStatus(status));
        // The compiler publishes diagnostics too; the findings panel is the
        // richer surface, so these are logged rather than duplicated.
        connection.onNotification('textDocument/publishDiagnostics', () => undefined);
        connection.onRequest('window/workDoneProgress/create', () => null);

        connection.listen();

        await connection.sendRequest('initialize', {
            processId: process.pid,
            rootUri: null,
            capabilities: {
                workspace: { executeCommand: { dynamicRegistration: false } },
                textDocument: {
                    publishDiagnostics: { relatedInformation: true },
                    completion: { completionItem: { snippetSupport: false } },
                    hover: { contentFormat: ['markdown', 'plaintext'] }
                }
            }
        });
        await connection.sendNotification('initialized', {});

        this.process = child;
        this.connection = connection;
        this.logger.info('Prahari language server ready');
        return connection;
    }

    // -- operations ---------------------------------------------------------

    protected async execute<T>(command: string, args: unknown[], fallback: T): Promise<T> {
        try {
            const connection = await this.ensureConnection();
            const result = await connection.sendRequest<T>('workspace/executeCommand', {
                command,
                arguments: args
            });
            return result ?? fallback;
        } catch (error) {
            this.logger.error(`Prahari command ${command} failed: ${error}`);
            return fallback;
        }
    }

    async audit(uri: string): Promise<PrahariAuditResult> {
        return this.execute<PrahariAuditResult>('prahari.audit', [uri], {
            uri,
            revision: '',
            stats: {},
            findings: [],
            exclusions: [],
            error: 'the Prahari language server is unavailable'
        });
    }

    async explain(uri: string, functionName: string): Promise<PrahariExplanation> {
        return this.execute<PrahariExplanation>('prahari.explain', [uri, functionName], {
            function: functionName,
            blocks: 0,
            instructions: 0,
            parameters: [],
            returnType: '',
            callees: [],
            taintSummary: '',
            error: 'the Prahari language server is unavailable'
        });
    }

    async adjudicate(uri: string): Promise<PrahariAuditResult> {
        return this.execute<PrahariAuditResult>('prahari.adjudicate', [uri], {
            uri,
            revision: '',
            stats: {},
            findings: [],
            exclusions: [],
            error: 'the Prahari language server is unavailable'
        });
    }

    async aiStatus(): Promise<PrahariAiStatus> {
        return this.execute<PrahariAiStatus>('prahari.aiStatus', [], {
            configured: false,
            error: 'the Prahari language server is unavailable'
        });
    }

    async buildLlvm(uri: string): Promise<{ uri: string; llvm?: string; error?: string }> {
        return this.execute('prahari.build', [uri], {
            uri,
            error: 'the Prahari language server is unavailable'
        });
    }

    dispose(): void {
        this.connection?.dispose();
        this.process?.kill();
        this.connection = undefined;
        this.process = undefined;
    }
}
