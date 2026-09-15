"""SARIF 2.1.0 output.

SARIF is the OASIS interchange format that CodeQL, Semgrep, Snyk and GitHub
code scanning all speak. Emitting it is what lets Aegis results be consumed by
tooling nobody had to write: the SARIF Viewer extension renders the findings,
and ``github/codeql-action/upload-sarif`` turns them into pull-request
annotations.

The mapping that matters is ``codeFlows``/``threadFlows``: SARIF's model of a
multi-step dataflow trace is exactly the source -> propagation -> sink path the
taint analysis already produces, so no information is lost in translation.
"""
from __future__ import annotations

import json
from pathlib import Path, PurePosixPath

from ..diagnostics import Finding, Location, Severity
from ..index import SemanticIndex

SARIF_VERSION = "2.1.0"
SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "Aegis"
TOOL_URI = "https://github.com/Divyakush2006/aegis"

_KIND_IMPORTANCE = {"SOURCE": "essential", "SINK": "essential", "PROPAGATE": "important"}


def _uri(location: Location, base: Path | None) -> str:
    """Repository-relative, forward-slashed URI, as SARIF consumers expect."""
    path = Path(location.file)
    if base is not None:
        try:
            path = path.resolve().relative_to(base.resolve())
        except (ValueError, OSError):
            path = Path(location.file).name and path
    return str(PurePosixPath(*path.parts)) if path.parts else str(path)


def _physical(location: Location, base: Path | None) -> dict:
    return {
        "artifactLocation": {"uri": _uri(location, base), "uriBaseId": "%SRCROOT%"},
        "region": {"startLine": max(location.line, 1), "startColumn": max(location.column, 1)},
    }


def _level(severity: Severity) -> str:
    return severity.sarif_level


def build_rules(index: SemanticIndex, registry) -> tuple[list[dict], dict[str, int]]:
    """One SARIF rule per detector that actually produced a finding."""
    used = sorted({f.rule_id for f in index.findings})
    by_rule = {f.rule_id: f for f in index.findings}
    rules: list[dict] = []
    rule_index: dict[str, int] = {}

    for position, rule_id in enumerate(used):
        finding = by_rule[rule_id]
        detector = registry.get(finding.path.cwe)
        rule_index[rule_id] = position
        rules.append(
            {
                "id": rule_id,
                "name": (detector.name if detector else finding.title).replace(" ", ""),
                "shortDescription": {"text": detector.name if detector else finding.title},
                "fullDescription": {
                    "text": (detector.remediation if detector else finding.remediation)
                },
                "help": {
                    "text": finding.remediation or "",
                    "markdown": f"**Missing control:** {finding.missing_control}\n\n"
                    f"{finding.remediation}",
                },
                "helpUri": detector.help_uri if detector else "",
                "defaultConfiguration": {"level": _level(finding.severity)},
                "properties": {
                    "tags": ["security", "external/cwe", f"external/cwe/{finding.path.cwe.lower()}"],
                    "precision": detector.precision if detector else "medium",
                    "security-severity": _security_severity(finding.severity),
                },
            }
        )
    return rules, rule_index


def _security_severity(severity: Severity) -> str:
    """GitHub code scanning ranks by this numeric string, not by ``level``."""
    return {"error": "8.0", "warning": "5.0", "note": "2.0"}[severity.sarif_level]


def _code_flow(finding: Finding, base: Path | None) -> dict:
    locations = [
        {
            "location": {
                "physicalLocation": _physical(step.location, base),
                "message": {"text": f"{step.kind}: {step.explanation}"},
            },
            "importance": _KIND_IMPORTANCE.get(step.kind, "important"),
            "nestingLevel": 0,
        }
        for step in finding.path.steps
    ]
    return {"threadFlows": [{"locations": locations}]}


def build_result(finding: Finding, rule_index: dict[str, int], base: Path | None) -> dict:
    result = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index.get(finding.rule_id, 0),
        "level": _level(finding.severity),
        "message": {"text": finding.message},
        "locations": [{"physicalLocation": _physical(finding.path.sink, base)}],
        "relatedLocations": [
            {
                "id": 1,
                "physicalLocation": _physical(finding.path.source, base),
                "message": {"text": "untrusted data enters here"},
            }
        ],
        "partialFingerprints": {"aegisPathHash/v1": finding.path.fingerprint},
        "properties": {
            "cwe": finding.path.cwe,
            "function": finding.function,
            "missingControl": finding.missing_control,
            "adjudicator": finding.adjudicator,
            "guards": [f"{g.condition} at line {g.location.line}" for g in finding.path.guards],
        },
    }
    if len(finding.path.steps) > 1:
        result["codeFlows"] = [_code_flow(finding, base)]
    if finding.exploitable is not None:
        result["properties"]["exploitable"] = finding.exploitable
        result["properties"]["adjudicationReason"] = finding.reason
    if finding.path.confidence is not None:
        result["properties"]["confidence"] = finding.path.confidence
    return result


def to_sarif(index: SemanticIndex, registry, base: Path | None = None, version: str = "0.1.0") -> dict:
    """Render a Semantic Index as a SARIF 2.1.0 log."""
    rules, rule_index = build_rules(index, registry)
    results = [build_result(f, rule_index, base) for f in index.findings]

    notifications = [
        {
            "level": "note",
            "message": {
                "text": f"excluded {e.construct} at {e.file}:{e.line}"
                + (f" ({e.detail})" if e.detail else "")
            },
        }
        for e in index.exclusions
    ]

    return {
        "$schema": SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "semanticVersion": version,
                        "informationUri": TOOL_URI,
                        "rules": rules,
                    }
                },
                "originalUriBaseIds": (
                    {"%SRCROOT%": {"uri": base.resolve().as_uri() + "/"}} if base else {}
                ),
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": notifications,
                        "properties": {"revision": index.revision, **index.stats},
                    }
                ],
                "artifacts": [
                    {"location": {"uri": _uri(Location(f), base)}} for f in index.files
                ],
                "results": results,
                "properties": {
                    "revision": index.revision,
                    "unmodelledExternals": sorted(index.unmodelled_externals()),
                    "exclusions": [e.as_dict() for e in index.exclusions],
                },
            }
        ],
    }


def dumps(index: SemanticIndex, registry, base: Path | None = None) -> str:
    return json.dumps(to_sarif(index, registry, base), indent=2)
