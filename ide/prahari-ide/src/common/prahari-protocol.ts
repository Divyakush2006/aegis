/**
 * The contract between the Prahari IDE frontend and its backend service.
 *
 * This file is the whole TypeScript/Python boundary. The frontend knows about
 * findings and path steps; it knows nothing about lattices, SSA or taint
 * specifications. Freezing this interface early is what keeps a two-language
 * project from bleeding compiler concepts into the UI layer.
 */

/** JSON-RPC path the backend service is served on. */
export const PRAHARI_SERVICE_PATH = '/services/prahari';

export const PrahariService = Symbol('PrahariService');
export const PrahariClient = Symbol('PrahariClient');

/** A source position, as the compiler reports it (1-based line and column). */
export interface PrahariLocation {
    uri: string;
    line: number;
    column: number;
}

/**
 * One hop on a dataflow path.
 *
 * `SOURCE` is where untrusted data enters, `SINK` where it becomes dangerous,
 * and `PROPAGATE` every step between. Rendering the whole chain — rather than
 * only the sink — is what makes a finding reviewable instead of merely alarming.
 */
export interface PrahariStep extends PrahariLocation {
    kind: 'SOURCE' | 'PROPAGATE' | 'SINK';
    value: string;
    snippet: string;
    explanation: string;
}

export interface PrahariGuard {
    condition: string;
    line: number;
}

export interface PrahariFinding {
    ruleId: string;
    cwe: string;
    title: string;
    message: string;
    severity: 'error' | 'warning' | 'note';
    function: string;
    missingControl: string;
    remediation: string;
    fingerprint: string;
    confidence?: number;
    /**
     * Which component last judged this finding: `none` before adjudication,
     * `null` for the deterministic gateway, a model id when a model reviewed
     * it, or `unavailable` when adjudication was attempted and failed. The
     * finding itself is the compiler's either way.
     */
    adjudicator: string;
    /** A model's verdict, or `null`/undefined when none was sought. */
    exploitable?: boolean | null;
    /** The reasoning behind `exploitable`, quoted verbatim from the verdict. */
    reason?: string;
    sink: PrahariLocation;
    guards: PrahariGuard[];
    steps: PrahariStep[];
}

export interface PrahariExclusion {
    construct: string;
    file: string;
    line: number;
    detail: string;
}

export interface PrahariAuditResult {
    uri: string;
    revision: string;
    stats: Record<string, number>;
    findings: PrahariFinding[];
    exclusions: PrahariExclusion[];
    /** Present only on a result that went through the adjudication pass. */
    adjudication?: PrahariAdjudication | null;
    error?: string;
}

/** What the adjudication pass did, for the panel header and for a report. */
export interface PrahariAdjudication {
    model: string;
    enabled?: boolean;
    candidates: number;
    adjudicated: number;
    dismissed: number;
    demoted: number;
    errors: number;
    cache_hits: number;
    input_tokens: number;
    output_tokens: number;
    mean_context_reduction: number;
    elapsed_seconds: number;
    /** Which use case resolved the model: the IDE always asks as `interactive`. */
    role?: string;
    /**
     * Why no model reviewed the findings, when none did: no key, a non-free
     * model refused by free-only mode, or an endpoint gated to other apps.
     */
    reason?: string;
    error?: string;
}

/**
 * Adjudication configuration as the backend sees it.
 *
 * `keyFingerprint` is a digest, never the key: an IDE that can display a
 * credential is an IDE that leaks one in a screen share.
 */
export interface PrahariAiStatus {
    provider?: string;
    model?: string;
    configured: boolean;
    key_fingerprint?: string;
    base_url?: string;
    cache?: string;
    error?: string;
}

export interface PrahariExplanation {
    function: string;
    blocks: number;
    instructions: number;
    parameters: string[];
    returnType: string;
    callees: string[];
    taintSummary: string;
    error?: string;
}

export interface PrahariStatus {
    state: 'running' | 'done' | 'failed';
    uri: string;
    findings?: number;
    /** Set while a long phase is in flight, so the panel can name it. */
    phase?: string;
}

/** One program invocation in a run: compile, then execute, for instance. */
export interface PrahariRunStep {
    program: string;
    args: string[];
}

/**
 * What pressing Run does for a file. Every file gets one of these — there is
 * no "cannot run" error, only an action or an explanation of what to install.
 */
export type PrahariRunPlan =
    | {
          kind: 'terminal';
          /** Human-readable toolchain, e.g. `C (gcc)`. */
          runner: string;
          cwd: string;
          steps: PrahariRunStep[];
          /** Toolchain directories put first on PATH, so built programs find their runtime. */
          pathPrefix: string[];
          /** Filled in by the backend: the platform shell wrapping the steps. */
          shellPath?: string;
          shellArgs?: string[];
      }
    | { kind: 'preview'; runner: string }
    | { kind: 'markdown'; runner: string }
    | { kind: 'external'; runner: string }
    | { kind: 'info'; message: string }
    | { kind: 'unavailable'; message: string };

export interface PrahariChatTurn {
    role: 'user' | 'assistant';
    content: string;
}

export interface PrahariChatRequest {
    question: string;
    history: PrahariChatTurn[];
    /** The active editor, when there is one; the file's text is sent as shown, unsaved edits included. */
    uri?: string;
    language?: string;
    text?: string;
    selection?: string;
}

export interface PrahariChatReply {
    reply: string;
    model: string;
    error?: string;
}

/** Backend operations, each one a compiler phase the user can invoke. */
export interface PrahariService {
    /** Run the full pipeline: taint, heap state machine, detectors. */
    audit(uri: string): Promise<PrahariAuditResult>;
    /** Describe a function from its CFG and interprocedural summary. */
    explain(uri: string, functionName: string): Promise<PrahariExplanation>;
    /** Generate LLVM IR for the document. */
    buildLlvm(uri: string): Promise<{ uri: string; llvm?: string; error?: string }>;
    /**
     * Audit, then review each finding through the configured model.
     *
     * Deliberately not folded into `audit`: an audit is local and free, while
     * this costs a round trip per finding. With no key configured it returns
     * the audit unchanged.
     */
    adjudicate(uri: string): Promise<PrahariAuditResult>;
    /** Whether adjudication is configured, for the status bar and the panel. */
    aiStatus(): Promise<PrahariAiStatus>;
    /** Ask Prahari AI a question about the open file, on the free interactive model. */
    chat(request: PrahariChatRequest): Promise<PrahariChatReply>;
    /** Decide how the Run button runs a file. Has no side effects. */
    planRun(uri: string): Promise<PrahariRunPlan>;
    /** Open a file in the application the operating system associates with it. */
    openExternally(uri: string): Promise<{ error?: string }>;
    /** True once the Python language server has completed initialisation. */
    isReady(): Promise<boolean>;
    dispose(): void;
    setClient(client: PrahariClient | undefined): void;
}

/** Notifications pushed from the backend while an audit is in flight. */
export interface PrahariClient {
    onStatus(status: PrahariStatus): void;
    onFindings(result: PrahariAuditResult): void;
}

export namespace PrahariCommands {
    export const CATEGORY = 'Prahari';
    export const AUDIT = 'prahari.audit';
    export const AUDIT_WORKSPACE = 'prahari.auditWorkspace';
    export const SHOW_FINDINGS = 'prahari.showFindings';
    export const EXPLAIN = 'prahari.explainFunction';
    export const BUILD_LLVM = 'prahari.buildLlvm';
    export const ADJUDICATE = 'prahari.adjudicateFindings';
    export const AI_STATUS = 'prahari.aiStatus';
    export const RUN_FILE = 'prahari.runFile';
    export const STOP_RUN = 'prahari.stopRun';
    export const OPEN_CHAT = 'prahari.openChat';
    export const ASK_ABOUT_SELECTION = 'prahari.askAboutSelection';
}

export const FINDINGS_WIDGET_ID = 'prahari.findings';
export const CHAT_WIDGET_ID = 'prahari.chat';
