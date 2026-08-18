"""Local HTML reporting for the standalone two-file comparator only."""

from __future__ import annotations

from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any

import pandas as pd


def _table(frame: pd.DataFrame, empty_message: str = "No values to show.", limit: int | None = None) -> str:
    if frame is None or frame.empty:
        return f'<p class="empty">{escape(empty_message)}</p>'
    shown = frame.head(limit) if limit else frame
    return shown.to_html(index=False, border=0, classes="data-table", escape=True, float_format=lambda value: f"{value:.4g}")


def _section(title: str, content: str) -> str:
    return f"<section><h2>{escape(title)}</h2>{content}</section>"


def build_comparison_html(result: dict[str, Any]) -> str:
    """Return a self-contained offline comparison report."""
    a, b = result["file_a"], result["file_b"]
    rate = pd.DataFrame([result["alert_rate"]])
    periods = pd.DataFrame([
        {"file": a.label, "raw_events": a.raw_event_count, "cleaned_events": a.cleaned_event_count, "period_start": a.period_start, "period_end": a.period_end},
        {"file": b.label, "raw_events": b.raw_event_count, "cleaned_events": b.cleaned_event_count, "period_start": b.period_start, "period_end": b.period_end},
    ])
    interpretation = "".join(f"<li>{escape(item)}</li>" for item in result["interpretation"])
    baseline = "ON" if result["baseline_enabled"] else "OFF"
    css = """
body{font-family:Arial,sans-serif;background:#f6f5f0;color:#23211d;margin:0}.report{max-width:1180px;margin:auto;padding:24px}
header,section{background:white;border:1px solid #e5e2d9;border-radius:9px;padding:18px;margin-bottom:16px}h1,h2{margin-top:0}
.meta,.empty{color:#6b675f}.data-table{border-collapse:collapse;width:100%;font-size:13px}.data-table th,.data-table td{border-bottom:1px solid #e5e2d9;padding:8px;text-align:left}.data-table th{background:#faf9f5}
@media print{body{background:white}.report{padding:0}header,section{break-inside:avoid}}
"""
    sections = [
        "<!doctype html>", '<html lang="en"><head><meta charset="utf-8">', '<meta name="viewport" content="width=device-width,initial-scale=1">',
        "<title>Offline Firewall Log Comparison</title>", f"<style>{css}</style></head><body><main class=\"report\">",
        f"<header><h1>Offline Firewall Log Comparison</h1><p>{escape(a.label)} vs {escape(b.label)}</p><p class=\"meta\">Baseline: {baseline} for both files | Generated locally {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p></header>",
        _section("FILE A / FILE B", _table(periods)),
        _section("DATASET OVERVIEW", _table(result["overview"])),
        _section("NORMALIZED ALERT RATE", _table(rate)),
        _section("SECURITY INTERPRETATION — What became more suspicious?", f"<ul>{interpretation}</ul>"),
        _section("ALERT / DETECTION DIFFERENCES", _table(result["alert_types"], "No detector alerts appeared in either file.")),
        _section("INCIDENT RISK DIFFERENCES", _table(result["incident_metrics"])),
        _section("INCIDENT SEVERITY DIFFERENCES", _table(result["incident_severities"])),
        _section("NEW FINDINGS — Newly observed in File B", _table(result["new_observables"], "No new source IPs, destination IPs, or destination ports.", 100)),
        _section("DISAPPEARED OBSERVABLES", _table(result["removed_observables"], "No source IPs, destination IPs, or destination ports disappeared.", 100)),
        _section("TRAFFIC-VOLUME CHANGES", _table(result["traffic_metrics"])),
        _section("TOP ACTIVITY CHANGES", _table(result["activity_changes"], "No activity changes available.", 100)),
        "</main></body></html>",
    ]
    return "\n".join(sections)


def write_comparison_report(result: dict[str, Any], output_path: str | Path) -> Path:
    """Write one comparison-specific HTML report and return its path."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_comparison_html(result), encoding="utf-8")
    return path
