/**
 * The findings panel: a security result rendered as the dataflow path that
 * produced it.
 *
 * This is the surface that distinguishes Aegis from a linter. A linter says
 * "line 40 calls system()". This panel shows where the value came from, every
 * function it crossed, what the compiler's summary said about each hop, and
 * which guards already stand on the path — so the reviewer can judge the claim
 * instead of trusting it. Every row navigates to its source location.
 */

import { codicon, Message, ReactWidget } from '@theia/core/lib/browser';
import { EditorManager } from '@theia/editor/lib/browser';
import { inject, injectable, postConstruct } from '@theia/core/shared/inversify';
import * as React from '@theia/core/shared/react';
import URI from '@theia/core/lib/common/uri';

import {
    AegisAdjudication,
    AegisAuditResult,
    AegisFinding,
    AegisStep,
    FINDINGS_WIDGET_ID
} from '../common/aegis-protocol';

const SEVERITY_ICON: Record<string, string> = {
    error: 'error',
    warning: 'warning',
    note: 'info'
};

const STEP_GLYPH: Record<AegisStep['kind'], string> = {
    SOURCE: '●',
    PROPAGATE: '○',
    SINK: '●'
};

@injectable()
export class AegisFindingsWidget extends ReactWidget {
    static readonly ID = FINDINGS_WIDGET_ID;
    static readonly LABEL = 'Aegis Findings';

    @inject(EditorManager) protected readonly editorManager: EditorManager;

    protected result: AegisAuditResult | undefined;
    protected status: 'idle' | 'running' | 'failed' = 'idle';
    protected runningLabel = 'Running the compiler pipeline…';
    protected expanded = new Set<string>();

    @postConstruct()
    protected init(): void {
        this.id = AegisFindingsWidget.ID;
        this.title.label = AegisFindingsWidget.LABEL;
        this.title.caption = AegisFindingsWidget.LABEL;
        this.title.iconClass = codicon('shield');
        this.title.closable = true;
        this.addClass('aegis-findings');
        this.update();
    }

    protected override onActivateRequest(message: Message): void {
        super.onActivateRequest(message);
        this.node.focus();
    }

    // -- state --------------------------------------------------------------

    setRunning(label?: string): void {
        this.status = 'running';
        this.runningLabel = label ?? 'Running the compiler pipeline…';
        this.update();
    }

    setResult(result: AegisAuditResult): void {
        this.result = result;
        this.status = result.error ? 'failed' : 'idle';
        // Open the first finding so the panel is never an empty-looking list.
        if (result.findings.length > 0) {
            this.expanded = new Set([result.findings[0].fingerprint]);
        }
        this.update();
    }

    protected toggle(fingerprint: string): void {
        if (this.expanded.has(fingerprint)) {
            this.expanded.delete(fingerprint);
        } else {
            this.expanded.add(fingerprint);
        }
        this.update();
    }

    protected async reveal(uri: string, line: number, column: number): Promise<void> {
        const widget = await this.editorManager.open(new URI(uri), {
            mode: 'reveal',
            selection: {
                start: { line: Math.max(line - 1, 0), character: Math.max(column - 1, 0) },
                end: { line: Math.max(line - 1, 0), character: Math.max(column - 1, 0) }
            }
        });
        widget.editor.focus();
    }

    // -- rendering ----------------------------------------------------------

    protected render(): React.ReactNode {
        return (
            <div className="aegis-panel">
                {this.renderHeader()}
                {this.renderBody()}
            </div>
        );
    }

    protected renderHeader(): React.ReactNode {
        const findings = this.result?.findings ?? [];
        const counts = findings.reduce<Record<string, number>>((acc, finding) => {
            acc[finding.cwe] = (acc[finding.cwe] ?? 0) + 1;
            return acc;
        }, {});
        const breakdown = Object.keys(counts)
            .sort()
            .map(cwe => `${cwe} ×${counts[cwe]}`)
            .join('  ');

        return (
            <div className="aegis-header">
                <span className="aegis-header-title">
                    {/* "0 findings" before any audit would read as "this file is
                        clean"; say plainly that nothing has been checked yet. */}
                    {this.status === 'running'
                        ? 'Auditing…'
                        : this.result
                          ? `${findings.length} finding${findings.length === 1 ? '' : 's'}`
                          : 'Not audited yet'}
                </span>
                {breakdown && <span className="aegis-header-breakdown">{breakdown}</span>}
                {this.renderAdjudicationSummary(this.result?.adjudication)}
                {this.result?.revision && (
                    <span className="aegis-header-revision">rev {this.result.revision}</span>
                )}
            </div>
        );
    }

    /**
     * One line describing the review pass, shown only when one ran.
     *
     * It reports the model by name and what it changed. A reviewer needs to
     * know a second opinion was involved and whose it was; a panel that hides
     * that is asking to be trusted rather than read.
     */
    protected renderAdjudicationSummary(summary: AegisAdjudication | null | undefined): React.ReactNode {
        if (!summary) {
            return undefined;
        }
        if (summary.enabled === false) {
            // No key is the normal, silent state. A refusal is not: it means the
            // user configured review and did not get it.
            return summary.reason && !/API key/.test(summary.reason) ? (
                <span className="aegis-header-adjudication failed" title={summary.reason}>
                    AI review unavailable — static verdicts retained
                </span>
            ) : undefined;
        }
        if (summary.error || (summary.errors > 0 && summary.adjudicated === 0)) {
            return (
                <span className="aegis-header-adjudication failed" title={summary.error}>
                    review unavailable — static verdicts retained
                </span>
            );
        }
        const role = summary.role ? ' (' + summary.role + ')' : '';
        const parts = [`${summary.adjudicated} reviewed by ${summary.model}${role}`];
        if (summary.dismissed) {
            parts.push(`${summary.dismissed} dismissed`);
        }
        if (summary.demoted) {
            parts.push(`${summary.demoted} demoted`);
        }
        if (summary.cache_hits) {
            parts.push(`${summary.cache_hits} cached`);
        }
        return <span className="aegis-header-adjudication">{parts.join(' · ')}</span>;
    }

    protected renderBody(): React.ReactNode {
        if (this.status === 'running') {
            return <div className="aegis-empty">{this.runningLabel}</div>;
        }
        if (this.result?.error) {
            return <div className="aegis-empty aegis-error">{this.result.error}</div>;
        }
        if (!this.result) {
            return (
                <div className="aegis-empty">
                    Run <strong>Aegis: Audit Current File</strong> to analyse the open document.
                </div>
            );
        }
        if (this.result.findings.length === 0) {
            return <div className="aegis-empty aegis-clean">No security findings.</div>;
        }
        return (
            <div className="aegis-list">
                {this.result.findings.map(finding => this.renderFinding(finding))}
                {this.renderExclusions()}
            </div>
        );
    }

    protected renderFinding(finding: AegisFinding): React.ReactNode {
        const open = this.expanded.has(finding.fingerprint);
        return (
            <div key={finding.fingerprint} className={`aegis-finding severity-${finding.severity}`}>
                <div
                    className="aegis-finding-head"
                    onClick={() => this.toggle(finding.fingerprint)}
                    role="button"
                    tabIndex={0}
                >
                    <span className={codicon(open ? 'chevron-down' : 'chevron-right')} />
                    <span className={`${codicon(SEVERITY_ICON[finding.severity] ?? 'info')} aegis-sev`} />
                    <span className="aegis-finding-title">{finding.title}</span>
                    {this.renderVerdictBadge(finding)}
                    <span className="aegis-finding-where">
                        {finding.function || ''}:{finding.sink.line}
                    </span>
                </div>
                {open && (
                    <div className="aegis-finding-body">
                        <p className="aegis-message">{finding.message}</p>
                        <div className="aegis-trace">
                            {finding.steps.map((step, index) => this.renderStep(step, index, finding.steps.length))}
                        </div>
                        {this.renderMeta('GUARDS ON PATH',
                            finding.guards.length
                                ? finding.guards.map(g => `${g.condition} (line ${g.line})`).join(', ')
                                : 'none')}
                        {this.renderMeta('MISSING CONTROL', finding.missingControl)}
                        {this.renderMeta('SUGGESTED FIX', finding.remediation)}
                        {this.renderAdjudication(finding)}
                    </div>
                )}
            </div>
        );
    }

    protected renderStep(step: AegisStep, index: number, total: number): React.ReactNode {
        return (
            <div key={`${step.uri}:${step.line}:${index}`} className="aegis-step-group">
                <div
                    className={`aegis-step kind-${step.kind.toLowerCase()}`}
                    onClick={() => this.reveal(step.uri, step.line, step.column)}
                    role="button"
                    tabIndex={0}
                    title={`${step.uri}:${step.line}`}
                >
                    <span className="aegis-step-glyph">{STEP_GLYPH[step.kind]}</span>
                    <span className="aegis-step-kind">{step.kind}</span>
                    <span className="aegis-step-line">{step.line}</span>
                    <code className="aegis-step-snippet">{step.snippet || step.value}</code>
                </div>
                <div className="aegis-step-why">{step.explanation}</div>
                {index < total - 1 && <div className="aegis-step-arrow">▼</div>}
            </div>
        );
    }

    /**
     * A one-word verdict next to the title, shown only once a model has ruled.
     *
     * A dismissal is styled as de-emphasis rather than removal. The compiler
     * still found the path; a reviewer who disagrees with the dismissal needs
     * to be able to see it and say so.
     */
    protected renderVerdictBadge(finding: AegisFinding): React.ReactNode {
        if (finding.adjudicator === 'unavailable') {
            return <span className="aegis-verdict unavailable">unreviewed</span>;
        }
        if (finding.exploitable === undefined || finding.exploitable === null) {
            return undefined;
        }
        return finding.exploitable ? (
            <span className="aegis-verdict exploitable">exploitable</span>
        ) : (
            <span className="aegis-verdict dismissed">dismissed</span>
        );
    }

    protected renderAdjudication(finding: AegisFinding): React.ReactNode {
        const reviewed = finding.exploitable !== undefined && finding.exploitable !== null;
        if (!reviewed && finding.adjudicator !== 'unavailable') {
            return undefined;
        }
        const confidence =
            finding.confidence !== undefined && finding.confidence !== null
                ? ` · confidence ${finding.confidence.toFixed(2)}`
                : '';
        return (
            <div className="aegis-meta aegis-adjudication">
                <span className="aegis-meta-label">AI REVIEW</span>
                <span className="aegis-meta-value">
                    <em>{finding.adjudicator}</em>
                    {confidence}
                    {finding.reason ? ` — ${finding.reason}` : ''}
                </span>
            </div>
        );
    }

    protected renderMeta(label: string, value: string): React.ReactNode {
        if (!value) {
            return undefined;
        }
        return (
            <div className="aegis-meta">
                <span className="aegis-meta-label">{label}</span>
                <span className="aegis-meta-value">{value}</span>
            </div>
        );
    }

    protected renderExclusions(): React.ReactNode {
        const exclusions = this.result?.exclusions ?? [];
        if (exclusions.length === 0) {
            return undefined;
        }
        const grouped = exclusions.reduce<Record<string, number>>((acc, exclusion) => {
            acc[exclusion.construct] = (acc[exclusion.construct] ?? 0) + 1;
            return acc;
        }, {});
        return (
            <div className="aegis-exclusions">
                <div className="aegis-exclusions-title">
                    Excluded from analysis ({exclusions.length})
                </div>
                {Object.keys(grouped)
                    .sort()
                    .map(construct => (
                        <div key={construct} className="aegis-exclusion">
                            {construct}: {grouped[construct]}
                        </div>
                    ))}
            </div>
        );
    }
}
