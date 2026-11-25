"""Render an ``AuditReport`` to SARIF 2.1.0 for GitHub Code Scanning & CI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ouroboros.schemas.audit_report import AuditReport
from ouroboros.schemas.common import AtlasTechnique, OwaspRisk, Severity
from ouroboros.schemas.dynamic_finding import DynamicFinding
from ouroboros.schemas.static_finding import StaticFinding

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_SEVERITY_TO_LEVEL: dict[Severity, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

_SEVERITY_TO_SECURITY_SCORE: dict[Severity, str] = {
    "CRITICAL": "9.5",
    "HIGH": "8.0",
    "MEDIUM": "5.5",
    "LOW": "3.0",
}


def render_sarif(report: AuditReport) -> dict[str, Any]:
    """Convert ``report`` into a SARIF 2.1.0 document dict."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for sf in report.static_findings:
        rule_id = f"ouroboros/static/{sf.category}"
        rules.setdefault(
            rule_id,
            _build_rule(
                rule_id=rule_id,
                name=sf.category,
                short=f"Static weakness: {sf.category}",
                help_text=sf.recommendation,
                severity=sf.severity,
                atlas=sf.atlas,
                owasp=sf.owasp,
                cwe=sf.cwe,
            ),
        )
        results.append(_static_result(rule_id, sf))

    for df in report.dynamic_findings:
        rule_id = f"ouroboros/dynamic/{df.category}"
        rules.setdefault(
            rule_id,
            _build_rule(
                rule_id=rule_id,
                name=df.category,
                short=f"Dynamic finding: {df.category} ({df.family})",
                help_text=f"Harden system prompt / tool gates against {df.family} ({df.oracle}).",
                severity=df.severity,
                atlas=df.atlas,
                owasp=df.owasp,
                cwe=[],
            ),
        )
        results.append(_dynamic_result(rule_id, df))

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Ouroboros Red Team",
                        "version": report.tool_version,
                        "informationUri": "https://github.com/Nachitzu/ouroboros-redteam",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {
                    "target": report.repo.source,
                    "mode": report.mode,
                    "applied_action": report.applied_action,
                },
            }
        ],
    }


def write_sarif(report: AuditReport, out_dir: Path, stem: str) -> Path:
    """Write ``<stem>.sarif`` into ``out_dir`` and return its path."""
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{stem}.sarif"
    path.write_text(json.dumps(render_sarif(report), indent=2) + "\n", encoding="utf-8")
    return path


def _build_rule(
    *,
    rule_id: str,
    name: str,
    short: str,
    help_text: str,
    severity: Severity,
    atlas: list[AtlasTechnique],
    owasp: list[OwaspRisk],
    cwe: list[str],
) -> dict[str, Any]:
    tags = [
        "security",
        "llm",
        *(a.technique_id for a in atlas),
        *(o.risk_id for o in owasp),
        *cwe,
    ]
    return {
        "id": rule_id,
        "name": name,
        "shortDescription": {"text": short},
        "help": {"text": help_text},
        "defaultConfiguration": {"level": _SEVERITY_TO_LEVEL[severity]},
        "properties": {
            "tags": tags,
            "security-severity": _SEVERITY_TO_SECURITY_SCORE[severity],
        },
    }


def _static_result(rule_id: str, f: StaticFinding) -> dict[str, Any]:
    region: dict[str, int] = {"startLine": f.line} if f.line and f.line >= 1 else {"startLine": 1}
    return {
        "ruleId": rule_id,
        "level": _SEVERITY_TO_LEVEL[f.severity],
        "message": {"text": f"{f.explanation} Fix: {f.recommendation}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file_path},
                    "region": region,
                }
            }
        ],
        "properties": {
            "confidence": f.confidence,
            "enriched": f.enriched,
            "atlas": [a.technique_id for a in f.atlas],
            "owasp": [o.risk_id for o in f.owasp],
            "cwe": list(f.cwe),
        },
    }


def _dynamic_result(rule_id: str, f: DynamicFinding) -> dict[str, Any]:
    locations: list[dict[str, Any]] = []
    if f.prompt_ref:
        parts = f.prompt_ref.rsplit(":", 1)
        uri = parts[0]
        line = int(parts[1]) if len(parts) == 2 and parts[1].isdigit() else 1
        locations.append(
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": max(1, line)},
                }
            }
        )
    else:
        locations.append({"logicalLocations": [{"name": "system-prompt", "kind": "prompt"}]})
    return {
        "ruleId": rule_id,
        "level": _SEVERITY_TO_LEVEL[f.severity],
        "message": {
            "text": (
                f"[{f.confidence}] {f.payload_id} ({f.family}/{f.oracle}): {f.observed_behavior}"
            )
        },
        "locations": locations,
        "properties": {
            "confidence": f.confidence,
            "family": f.family,
            "oracle": f.oracle,
            "pack": f.pack,
            "payload_id": f.payload_id,
            "turns": f.turns,
            "mutation": f.mutation,
            "atlas": [a.technique_id for a in f.atlas],
            "owasp": [o.risk_id for o in f.owasp],
        },
    }
