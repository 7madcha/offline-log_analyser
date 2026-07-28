"""Local report and template utilities."""

from __future__ import annotations

from datetime import datetime
from html import escape
from pathlib import Path
import textwrap

import pandas as pd

from src.utils import ensure_directory

CSV_SCHEMA_COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "action",
    "bytes_sent",
    "bytes_received",
    "label",
]

DASHBOARD_REPORT_CSS = """
body {
    background: #f8fafc;
    color: #111827;
    font-family: Arial, Helvetica, sans-serif;
    margin: 0;
}
.report {
    margin: 0 auto;
    max-width: 1180px;
    padding: 24px;
}
.simple-header,
.metric,
.section {
    background: #ffffff;
    border: 1px solid #e5e7eb;
    border-radius: 8px;
}
.simple-header {
    margin-bottom: 16px;
    padding: 16px;
}
.simple-header h1 {
    font-size: 26px;
    margin: 0 0 4px;
}
.simple-header p {
    color: #475569;
    margin: 0;
}
.metrics {
    display: grid;
    gap: 12px;
    grid-template-columns: repeat(4, 1fr);
    margin-bottom: 16px;
}
.metric {
    padding: 12px;
}
.metric span {
    color: #64748b;
    display: block;
    font-size: 13px;
    margin-bottom: 8px;
}
.metric strong {
    display: block;
    font-size: 26px;
}
.metric small {
    color: #64748b;
}
.section {
    margin-bottom: 16px;
    padding: 16px;
}
.section h2 {
    font-size: 18px;
    margin: 0 0 12px;
}
table {
    border-collapse: collapse;
    font-size: 13px;
    width: 100%;
}
th,
td {
    border-bottom: 1px solid #e5e7eb;
    padding: 8px;
    text-align: left;
    vertical-align: top;
}
th {
    background: #f8fafc;
    color: #334155;
}
.empty {
    color: #64748b;
    margin: 0;
}
@media print {
    body {
        background: #ffffff;
    }
    .report {
        max-width: none;
        padding: 0;
    }
    .section,
    .simple-header,
    .metric {
        break-inside: avoid;
    }
}
"""


def csv_schema_template() -> str:
    """Return a small CSV template users can download and fill locally."""
    example = [
        "2026-07-01 09:00:01",
        "10.0.0.15",
        "198.51.100.20",
        "51000",
        "443",
        "TCP",
        "ALLOW",
        "1200",
        "8500",
        "normal",
    ]
    return ",".join(CSV_SCHEMA_COLUMNS) + "\n" + ",".join(example) + "\n"


def build_html_report(
    logs: pd.DataFrame,
    alerts: pd.DataFrame,
    incidents: pd.DataFrame,
    cleaning_summary: dict[str, int] | None = None,
    source_label: str = "Local analysis results",
    top_sources: pd.DataFrame | None = None,
    top_ports: pd.DataFrame | None = None,
    top_dst_ips: pd.DataFrame | None = None,
) -> str:
    """Build a dashboard-style HTML report from local analysis results."""
    blocked = int((logs["action"] == "BLOCK").sum()) if "action" in logs else 0
    allowed = int((logs["action"] == "ALLOW").sum()) if "action" in logs else 0
    max_risk = int(incidents["risk_score"].max()) if not incidents.empty and "risk_score" in incidents else 0
    critical = int((incidents["severity"] == "Critical").sum()) if "severity" in incidents else 0

    cleaning = cleaning_summary or {}
    summary_rows = [
        ("Original rows", _format_count(cleaning.get("original_row_count", 0))),
        ("Final rows", _format_count(cleaning.get("final_row_count", len(logs)))),
        ("Duplicates removed", _format_count(cleaning.get("duplicate_rows_removed", 0))),
        ("Invalid timestamps", _format_count(cleaning.get("invalid_timestamps", 0))),
        ("Invalid IP addresses", _format_count(cleaning.get("invalid_ip_addresses", 0))),
        ("Invalid ports", _format_count(cleaning.get("invalid_ports", 0))),
    ]
    incident_columns = ["incident_id", "src_ip", "start_time", "end_time", "risk_score", "severity", "alert_types", "alert_count"]
    alert_columns = ["timestamp", "src_ip", "alert_type", "severity", "event_count", "score_contribution"]
    incident_rows = incidents.sort_values("risk_score", ascending=False).head(10) if "risk_score" in incidents else incidents.head(10)

    source_columns = ["src_ip", "total_events", "allowed_events", "blocked_events", "blocked_ratio", "bytes_sent_total", "bytes_received_total", "unique_dst_ips", "unique_dst_ports", "alert_count"]
    port_columns = ["dst_port", "service_name", "total_events", "unique_source_ips", "allowed_events", "blocked_events", "blocked_ratio", "bytes_sent_total", "bytes_received_total"]
    dst_ip_columns = ["dst_ip", "total_events", "unique_source_ips", "allowed_events", "blocked_events", "blocked_ratio", "bytes_sent_total", "bytes_received_total"]

    sections = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>Offline Log Forensic Analyzer Report</title>",
        f"<style>{DASHBOARD_REPORT_CSS}</style>",
        "</head>",
        "<body>",
        '<main class="report">',
        '<section class="simple-header">',
        "<h1>Offline Log Forensic Analyzer</h1>",
        f"<p>{escape(source_label)} - Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        "</section>",
        '<section class="metrics">',
        _metric_card("Events", _format_count(len(logs)), f"Allowed: {_format_count(allowed)} | Blocked: {_format_count(blocked)}"),
        _metric_card("Alerts", _format_count(len(alerts))),
        _metric_card("Incidents", _format_count(len(incidents)), f"Critical: {_format_count(critical)}"),
        _metric_card("Highest risk", str(max_risk)),
        "</section>",
        _section("Cleaning summary", _key_value_table(summary_rows)),
        _section("Top incidents", _dataframe_table(incident_rows, incident_columns, "No incidents to show.")),
        _section("Recent alerts", _dataframe_table(alerts.head(10), alert_columns, "No alerts to show.")),
    ]
    if top_sources is not None:
        sections.append(_section("Top Active Source IPs", _dataframe_table(top_sources, source_columns, "No source IP data available.")))
    if top_ports is not None:
        sections.append(_section("Most Frequently Used Destination Ports", _dataframe_table(top_ports, port_columns, "No destination port data available.")))
    if top_dst_ips is not None:
        sections.append(_section("Top Destination IPs", _dataframe_table(top_dst_ips, dst_ip_columns, "No destination IP data available.")))
    sections += ["</main>", "</body>", "</html>"]
    return "\n".join(sections)


def build_report_lines(
    logs: pd.DataFrame,
    alerts: pd.DataFrame,
    incidents: pd.DataFrame,
    cleaning_summary: dict[str, int] | None = None,
    top_sources: pd.DataFrame | None = None,
    top_ports: pd.DataFrame | None = None,
    top_dst_ips: pd.DataFrame | None = None,
) -> list[str]:
    """Build a plain-text incident report from local analysis results."""
    lines = [
        "Offline Log Forensic Analyzer - Incident Report",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "Scope: local CSV analysis only. No network scanning, external API calls, or company resource access.",
        "",
        "Summary",
        f"- Log events: {len(logs):,}",
        f"- Alerts: {len(alerts):,}",
        f"- Incidents: {len(incidents):,}",
    ]
    if not incidents.empty:
        lines.append(f"- Highest risk score: {int(incidents['risk_score'].max())}")
        severity_counts = incidents["severity"].value_counts().to_dict()
        severity_text = ", ".join(f"{name}: {severity_counts.get(name, 0)}" for name in ["Low", "Medium", "High", "Critical"])
        lines.append(f"- Incident severity: {severity_text}")
    if cleaning_summary:
        lines.extend([
            "",
            "Cleaning Summary",
            f"- Original rows: {cleaning_summary.get('original_row_count', 0):,}",
            f"- Final rows: {cleaning_summary.get('final_row_count', 0):,}",
            f"- Duplicates removed: {cleaning_summary.get('duplicate_rows_removed', 0):,}",
            f"- Invalid timestamps: {cleaning_summary.get('invalid_timestamps', 0):,}",
            f"- Invalid IP addresses: {cleaning_summary.get('invalid_ip_addresses', 0):,}",
            f"- Invalid ports: {cleaning_summary.get('invalid_ports', 0):,}",
        ])

    lines.extend(["", "Top Incidents"])
    if incidents.empty:
        lines.append("No incidents were created for the selected data.")
    else:
        ordered = incidents.sort_values("risk_score", ascending=False).head(5)
        for _, incident in ordered.iterrows():
            lines.extend([
                "",
                f"{incident['incident_id']} - {incident['severity']} - Risk {int(incident['risk_score'])}/100",
                f"Source IP: {incident['src_ip']}",
                f"Window: {incident['start_time']} to {incident['end_time']}",
                f"Alert types: {incident['alert_types']}",
                f"Affected destinations: {incident['affected_destinations']}",
                f"Affected ports: {incident['affected_ports']}",
                "Explanation:",
            ])
            lines.extend(_wrap_text(str(incident["explanation"])))
            lines.append("Risk score breakdown:")
            lines.extend(_wrap_text(str(incident["score_breakdown"]).replace(" | ", "; ")))
            lines.append("Recommendations:")
            for recommendation in _split_pipe_values(incident["recommendations"]):
                lines.extend(_wrap_text(f"- {recommendation}"))

    if top_sources is not None:
        lines.extend(["", "Top Active Source IPs"])
        src_cols = ["src_ip", "total_events", "blocked_events", "blocked_ratio", "bytes_sent_total", "bytes_received_total", "unique_dst_ips", "unique_dst_ports"]
        lines.extend(_format_text_table(top_sources, src_cols))

    if top_ports is not None:
        lines.extend(["", "Most Frequently Used Destination Ports"])
        port_cols = ["dst_port", "service_name", "total_events", "blocked_ratio", "bytes_sent_total", "bytes_received_total"]
        lines.extend(_format_text_table(top_ports, port_cols))

    if top_dst_ips is not None:
        lines.extend(["", "Top 10 Destination IPs"])
        dst_cols = ["dst_ip", "total_events", "unique_source_ips", "blocked_events", "blocked_ratio", "bytes_sent_total", "bytes_received_total"]
        lines.extend(_format_text_table(top_dst_ips, dst_cols))

    return lines


def build_pdf_report(
    logs: pd.DataFrame,
    alerts: pd.DataFrame,
    incidents: pd.DataFrame,
    cleaning_summary: dict[str, int] | None = None,
    top_sources: pd.DataFrame | None = None,
    top_ports: pd.DataFrame | None = None,
    top_dst_ips: pd.DataFrame | None = None,
) -> bytes:
    """Create a dependency-free PDF report from local analysis results."""
    return _pdf_from_lines(build_report_lines(logs, alerts, incidents, cleaning_summary, top_sources, top_ports, top_dst_ips))


def build_visual_pdf_report(
    logs: pd.DataFrame,
    alerts: pd.DataFrame,
    incidents: pd.DataFrame,
    cleaning_summary: dict[str, int] | None = None,
    source_label: str = "Local analysis results",
    top_sources: pd.DataFrame | None = None,
    top_ports: pd.DataFrame | None = None,
    top_dst_ips: pd.DataFrame | None = None,
) -> bytes:
    """Create a dashboard-style PDF report by rendering HTML in Chromium."""
    html = build_html_report(logs, alerts, incidents, cleaning_summary, source_label, top_sources, top_ports, top_dst_ips)
    return _html_to_pdf_bytes(html)


def export_pdf_report(
    logs: pd.DataFrame,
    alerts: pd.DataFrame,
    incidents: pd.DataFrame,
    path: str | Path = "outputs/reports/incident_report.pdf",
    cleaning_summary: dict[str, int] | None = None,
) -> Path:
    """Write a local PDF incident report and return its path."""
    output = Path(path)
    ensure_directory(output.parent)
    output.write_bytes(build_pdf_report(logs, alerts, incidents, cleaning_summary))
    return output


def export_visual_pdf_report(
    logs: pd.DataFrame,
    alerts: pd.DataFrame,
    incidents: pd.DataFrame,
    path: str | Path = "outputs/reports/incident_report_visual.pdf",
    cleaning_summary: dict[str, int] | None = None,
    source_label: str = "Local analysis results",
) -> Path:
    """Write a dashboard-style Chromium-rendered PDF report and return its path."""
    output = Path(path)
    ensure_directory(output.parent)
    output.write_bytes(build_visual_pdf_report(logs, alerts, incidents, cleaning_summary, source_label))
    return output


def export_html_report(
    logs: pd.DataFrame,
    alerts: pd.DataFrame,
    incidents: pd.DataFrame,
    path: str | Path = "outputs/reports/incident_report.html",
    cleaning_summary: dict[str, int] | None = None,
    source_label: str = "Local analysis results",
) -> Path:
    """Write a dashboard-style HTML report and return its path."""
    output = Path(path)
    ensure_directory(output.parent)
    output.write_text(build_html_report(logs, alerts, incidents, cleaning_summary, source_label), encoding="utf-8")
    return output


def _split_pipe_values(value: object) -> list[str]:
    if pd.isna(value):
        return []
    return [item.strip() for item in str(value).split(" | ") if item.strip()]


def _metric_card(label: str, value: str, detail: str = "") -> str:
    detail_html = f"<small>{escape(detail)}</small>" if detail else ""
    return f'<article class="metric"><span>{escape(label)}</span><strong>{escape(value)}</strong>{detail_html}</article>'


def _section(title: str, body: str) -> str:
    return f'<section class="section"><h2>{escape(title)}</h2>{body}</section>'


def _key_value_table(rows: list[tuple[str, str]]) -> str:
    body = "".join(f"<tr><th>{escape(label)}</th><td>{escape(value)}</td></tr>" for label, value in rows)
    return f"<table><tbody>{body}</tbody></table>"


def _dataframe_table(df: pd.DataFrame, columns: list[str], empty_message: str) -> str:
    available = [column for column in columns if column in df]
    if df.empty or not available:
        return f'<p class="empty">{escape(empty_message)}</p>'
    header = "".join(f"<th>{escape(column.replace('_', ' ').title())}</th>" for column in available)
    rows = []
    for _, row in df[available].iterrows():
        cells = "".join(f"<td>{escape(_format_cell(row[column]))}</td>" for column in available)
        rows.append(f"<tr>{cells}</tr>")
    return f"<table><thead><tr>{header}</tr></thead><tbody>{''.join(rows)}</tbody></table>"


def _format_count(value: object) -> str:
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return "0"


def _format_cell(value: object) -> str:
    if pd.isna(value):
        return ""
    if isinstance(value, pd.Timestamp):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _html_to_pdf_bytes(html: str) -> bytes:
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError(_playwright_install_message()) from exc

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            try:
                page = browser.new_page(viewport={"width": 1180, "height": 1600})
                page.set_content(html, wait_until="networkidle")
                return page.pdf(
                    format="A4",
                    print_background=True,
                    margin={"top": "14mm", "right": "12mm", "bottom": "14mm", "left": "12mm"},
                )
            finally:
                browser.close()
    except PlaywrightError as exc:
        raise RuntimeError(_playwright_install_message()) from exc


def _playwright_install_message() -> str:
    return (
        "Visual PDF export requires Playwright and a Chromium browser. "
        "Install them with: pip install playwright && python -m playwright install chromium"
    )


def _format_text_table(df: pd.DataFrame, columns: list[str], max_rows: int = 10) -> list[str]:
    """Render a DataFrame as fixed-width plain-text table rows for the text-only PDF."""
    available = [col for col in columns if col in df.columns]
    if df.empty or not available:
        return ["  No data available."]
    subset = df[available].head(max_rows).copy()
    # Format values for display
    for col in subset.columns:
        if col == "blocked_ratio":
            subset[col] = subset[col].apply(lambda v: f"{v:.1%}" if pd.notna(v) else "0.0%")
        elif "bytes" in col:
            subset[col] = subset[col].apply(lambda v: f"{int(v):,}" if pd.notna(v) else "0")
        else:
            subset[col] = subset[col].apply(
                lambda v: str(int(v)) if isinstance(v, float) and v == int(v) else str(v) if pd.notna(v) else ""
            )
    headers = {col: col.replace("_", " ").title() for col in subset.columns}
    widths = {col: max(len(headers[col]), subset[col].astype(str).str.len().max()) for col in subset.columns}
    header_line = "  ".join(headers[col].ljust(widths[col]) for col in subset.columns)
    sep_line = "  ".join("-" * widths[col] for col in subset.columns)
    lines = [header_line, sep_line]
    for _, row in subset.iterrows():
        lines.append("  ".join(str(row[col]).ljust(widths[col]) for col in subset.columns))
    return lines


def _wrap_text(text: str, width: int = 92) -> list[str]:
    wrapped: list[str] = []
    for line in str(text).splitlines() or [""]:
        wrapped.extend(textwrap.wrap(line, width=width) or [""])
    return wrapped


def _pdf_from_lines(lines: list[str]) -> bytes:
    page_line_limit = 48
    pages = [lines[index : index + page_line_limit] for index in range(0, len(lines), page_line_limit)] or [[""]]
    objects: dict[int, bytes] = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        3: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    }
    page_ids: list[int] = []
    for index, page_lines in enumerate(pages):
        page_id = 4 + index * 2
        content_id = page_id + 1
        page_ids.append(page_id)
        stream = _page_stream(page_lines)
        objects[content_id] = b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream"
        objects[page_id] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>"
        ).encode("ascii")
    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    objects[2] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode("ascii")

    output = bytearray(b"%PDF-1.4\n")
    offsets: dict[int, int] = {}
    for obj_id in sorted(objects):
        offsets[obj_id] = len(output)
        output.extend(f"{obj_id} 0 obj\n".encode("ascii"))
        output.extend(objects[obj_id])
        output.extend(b"\nendobj\n")
    xref_start = len(output)
    max_id = max(objects)
    output.extend(f"xref\n0 {max_id + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for obj_id in range(1, max_id + 1):
        output.extend(f"{offsets[obj_id]:010d} 00000 n \n".encode("ascii"))
    output.extend(
        f"trailer\n<< /Size {max_id + 1} /Root 1 0 R >>\nstartxref\n{xref_start}\n%%EOF\n".encode("ascii")
    )
    return bytes(output)


def _page_stream(lines: list[str]) -> bytes:
    commands = ["BT", "/F1 10 Tf", "50 760 Td", "14 TL"]
    for line in lines:
        commands.append(f"({_pdf_escape(line)}) Tj")
        commands.append("T*")
    commands.append("ET")
    return "\n".join(commands).encode("latin-1", errors="replace")


def _pdf_escape(value: object) -> str:
    safe = str(value).encode("latin-1", errors="replace").decode("latin-1")
    return safe.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
