/**
 * The findings panel: a security result rendered as the dataflow path that
 * produced it.
 *
 * This is the surface that distinguishes Prahari from a linter. A linter says
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
    PrahariAdjudication,
    PrahariAuditResult,
    PrahariFinding,
    PrahariStep,
    FINDINGS_WIDGET_ID
} from '../common/prahari-protocol';

const SEVERITY_ICON: Record<string, string> = {
    error: 'error',
    warning: 'warning',
    note: 'info'
};

const STEP_GLYPH: Record<PrahariStep['kind'], string> = {
    SOURCE: '●',
    PROPAGATE: '○',
    SINK: '●'
};

@injectable()
export class PrahariFindingsWidget extends ReactWidget {
    static readonly ID = FINDINGS_WIDGET_ID;
    static readonly LABEL = 'Prahari Findings';

    @inject(EditorManager) protected readonly editorManager: EditorManager;

    protected result: PrahariAuditResult | undefined;
    protected status: 'idle' | 'running' | 'failed' = 'idle';
    protected runningLabel = 'Running the compiler pipeline…';
    protected expanded = new Set<string>();

    @postConstruct()
    protected init(): void {
        this.id = PrahariFindingsWidget.ID;
        this.title.label = PrahariFindingsWidget.LABEL;
        this.title.caption = PrahariFindingsWidget.LABEL;
        this.title.iconClass = codicon('shield');
        this.title.closable = true;
        this.addClass('prahari-findings');
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

    setResult(result: PrahariAuditResult): void {
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
            <div className="prahari-panel">
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
            <div className="prahari-header">
                <span className="prahari-header-title">
                    {/* "0 findings" before any audit would read as "this file is
                        clean"; say plainly that nothing has been checked yet. */}
                    {this.status === 'running'
                        ? 'Auditing…'
                        : this.result
                          ? `${findings.length} finding${findings.length === 1 ? '' : 's'}`
                          : 'Not audited yet'}
                </span>
                {breakdown && <span className="prahari-header-breakdown">{breakdown}</span>}
                {this.renderAdjudicationSummary(this.result?.adjudication)}
                {this.result?.revision && (
                    <span className="prahari-header-revision">rev {this.result.revision}</span>
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
    protected renderAdjudicationSummary(summary: PrahariAdjudication | null | undefined): React.ReactNode {
        if (!summary) {
            return undefined;
        }
        if (summary.enabled === false) {
            // No key is the normal, silent state. A refusal is not: it means the
            // user configured review and did not get it.
            return summary.reason && !/API key/.test(summary.reason) ? (
                <span className="prahari-header-adjudication failed" title={summary.reason}>
                    AI review unavailable — static verdicts retained
                </span>
            ) : undefined;
        }
        if (summary.error || (summary.errors > 0 && summary.adjudicated === 0)) {
            return (
                <span className="prahari-header-adjudication failed" title={summary.error}>
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
        return <span className="prahari-header-adjudication">{parts.join(' · ')}</span>;
    }

    protected renderBody(): React.ReactNode {
        if (this.status === 'running') {
            return <div className="prahari-empty">{this.runningLabel}</div>;
        }
        if (this.result?.error) {
            return <div className="prahari-empty prahari-error">{this.result.error}</div>;
        }
        if (!this.result) {
            return (
                <div className="prahari-empty">
                    Run <strong>Prahari: Audit Current File</strong> to analyse the open document.
                </div>
            );
        }
        if (this.result.findings.length === 0) {
            return <div className="prahari-empty prahari-clean">No security findings.</div>;
        }
        return (
            <div className="prahari-list">
                {this.result.findings.map(finding => this.renderFinding(finding))}
                {this.renderExclusions()}
            </div>
        );
    }

    protected renderFinding(finding: PrahariFinding): React.ReactNode {
        const open = this.expanded.has(finding.fingerprint);
        return (
            <div key={finding.fingerprint} className={`prahari-finding severity-${finding.severity}`}>
                <div
                    className="prahari-finding-head"
                    onClick={() => this.toggle(finding.fingerprint)}
                    role="button"
                    tabIndex={0}
                >
                    <span className={codicon(open ? 'chevron-down' : 'chevron-right')} />
                    <span className={`${codicon(SEVERITY_ICON[finding.severity] ?? 'info')} prahari-sev`} />
                    <span className="prahari-finding-title">{finding.title}</span>
                    {this.renderVerdictBadge(finding)}
                    <span className="prahari-finding-where">
                        {finding.function || ''}:{finding.sink.line}
                    </span>
                </div>
                {open && (
                    <div className="prahari-finding-body">
                        <p className="prahari-message">{finding.message}</p>
                        <div className="prahari-trace">
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

    protected renderStep(step: PrahariStep, index: number, total: number): React.ReactNode {
        return (
            <div key={`${step.uri}:${step.line}:${index}`} className="prahari-step-group">
                <div
                    className={`prahari-step kind-${step.kind.toLowerCase()}`}
                    onClick={() => this.reveal(step.uri, step.line, step.column)}
                    role="button"
                    tabIndex={0}
                    title={`${step.uri}:${step.line}`}
                >
                    <span className="prahari-step-glyph">{STEP_GLYPH[step.kind]}</span>
                    <span className="prahari-step-kind">{step.kind}</span>
                    <span className="prahari-step-line">{step.line}</span>
                    <code className="prahari-step-snippet">{step.snippet || step.value}</code>
                </div>
                <div className="prahari-step-why">{step.explanation}</div>
                {index < total - 1 && <div className="prahari-step-arrow">▼</div>}
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
    protected renderVerdictBadge(finding: PrahariFinding): React.ReactNode {
        if (finding.adjudicator === 'unavailable') {
            return <span className="prahari-verdict unavailable">unreviewed</span>;
        }
        if (finding.exploitable === undefined || finding.exploitable === null) {
            return undefined;
        }
        return finding.exploitable ? (
            <span className="prahari-verdict exploitable">exploitable</span>
        ) : (
            <span className="prahari-verdict dismissed">dismissed</span>
        );
    }

    protected renderAdjudication(finding: PrahariFinding): React.ReactNode {
        const reviewed = finding.exploitable !== undefined && finding.exploitable !== null;
        if (!reviewed && finding.adjudicator !== 'unavailable') {
            return undefined;
        }
        const confidence =
            finding.confidence !== undefined && finding.confidence !== null
                ? ` · confidence ${finding.confidence.toFixed(2)}`
                : '';
        return (
            <div className="prahari-meta prahari-adjudication">
                <span className="prahari-meta-label">AI REVIEW</span>
                <span className="prahari-meta-value">
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
            <div className="prahari-meta">
                <span className="prahari-meta-label">{label}</span>
                <span className="prahari-meta-value">{value}</span>
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
            <div className="prahari-exclusions">
                <div className="prahari-exclusions-title">
                    Excluded from analysis ({exclusions.length})
                </div>
                {Object.keys(grouped)
                    .sort()
                    .map(construct => (
                        <div key={construct} className="prahari-exclusion">
                            {construct}: {grouped[construct]}
                        </div>
                    ))}
            </div>
        );
    }
}
