/**
 * The contract between the Aegis IDE frontend and its backend service.
 *
 * This file is the whole TypeScript/Python boundary. The frontend knows about
 * findings and path steps; it knows nothing about lattices, SSA or taint
 * specifications. Freezing this interface early is what keeps a two-language
 * project from bleeding compiler concepts into the UI layer.
 */

/** JSON-RPC path the backend service is served on. */
export const AEGIS_SERVICE_PATH = '/services/aegis';

export const AegisService = Symbol('AegisService');
export const AegisClient = Symbol('AegisClient');

/** A source position, as the compiler reports it (1-based line and column). */
export interface AegisLocation {
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
export interface AegisStep extends AegisLocation {
    kind: 'SOURCE' | 'PROPAGATE' | 'SINK';
    value: string;
    snippet: string;
    explanation: string;
}

export interface AegisGuard {
    condition: string;
    line: number;
}

export interface AegisFinding {
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
    sink: AegisLocation;
    guards: AegisGuard[];
    steps: AegisStep[];
}

export interface AegisExclusion {
    construct: string;
    file: string;
    line: number;
    detail: string;
}

export interface AegisAuditResult {
    uri: string;
    revision: string;
    stats: Record<string, number>;
    findings: AegisFinding[];
    exclusions: AegisExclusion[];
    /** Present only on a result that went through the adjudication pass. */
    adjudication?: AegisAdjudication | null;
    error?: string;
}

/** What the adjudication pass did, for the panel header and for a report. */
export interface AegisAdjudication {
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
export interface AegisAiStatus {
    provider?: string;
    model?: string;
    configured: boolean;
    key_fingerprint?: string;
    base_url?: string;
    cache?: string;
    error?: string;
}

export interface AegisExplanation {
    function: string;
    blocks: number;
    instructions: number;
    parameters: string[];
    returnType: string;
    callees: string[];
    taintSummary: string;
    error?: string;
}

export interface AegisStatus {
    state: 'running' | 'done' | 'failed';
    uri: string;
    findings?: number;
    /** Set while a long phase is in flight, so the panel can name it. */
    phase?: string;
}

/** Backend operations, each one a compiler phase the user can invoke. */
export interface AegisService {
    /** Run the full pipeline: taint, heap state machine, detectors. */
    audit(uri: string): Promise<AegisAuditResult>;
    /** Describe a function from its CFG and interprocedural summary. */
    explain(uri: string, functionName: string): Promise<AegisExplanation>;
    /** Generate LLVM IR for the document. */
    buildLlvm(uri: string): Promise<{ uri: string; llvm?: string; error?: string }>;
    /**
     * Audit, then review each finding through the configured model.
     *
     * Deliberately not folded into `audit`: an audit is local and free, while
     * this costs a round trip per finding. With no key configured it returns
     * the audit unchanged.
     */
    adjudicate(uri: string): Promise<AegisAuditResult>;
    /** Whether adjudication is configured, for the status bar and the panel. */
    aiStatus(): Promise<AegisAiStatus>;
    /** True once the Python language server has completed initialisation. */
    isReady(): Promise<boolean>;
    dispose(): void;
    setClient(client: AegisClient | undefined): void;
}

/** Notifications pushed from the backend while an audit is in flight. */
export interface AegisClient {
    onStatus(status: AegisStatus): void;
    onFindings(result: AegisAuditResult): void;
}

export namespace AegisCommands {
    export const CATEGORY = 'Aegis';
    export const AUDIT = 'aegis.audit';
    export const AUDIT_WORKSPACE = 'aegis.auditWorkspace';
    export const SHOW_FINDINGS = 'aegis.showFindings';
    export const EXPLAIN = 'aegis.explainFunction';
    export const BUILD_LLVM = 'aegis.buildLlvm';
    export const ADJUDICATE = 'aegis.adjudicateFindings';
    export const AI_STATUS = 'aegis.aiStatus';
}

export const FINDINGS_WIDGET_ID = 'aegis.findings';
