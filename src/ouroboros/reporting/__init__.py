"""Rendering of an ``AuditReport`` into Markdown, JSON, SARIF 2.1.0, and diffs."""

from __future__ import annotations

from ouroboros.reporting.diff import ReportDiff, compare_reports, render_diff_markdown
from ouroboros.reporting.markdown import render_markdown, write_report
from ouroboros.reporting.sarif import render_sarif, write_sarif

__all__ = [
    "ReportDiff",
    "compare_reports",
    "render_diff_markdown",
    "render_markdown",
    "render_sarif",
    "write_report",
    "write_sarif",
]
