"""Local report and template utilities."""

from __future__ import annotations

from datetime import datetime
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


def build_report_lines(
    logs: pd.DataFrame,
    alerts: pd.DataFrame,
    incidents: pd.DataFrame,
    cleaning_summary: dict[str, int] | None = None,
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
        return lines

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
    return lines


def build_pdf_report(
    logs: pd.DataFrame,
    alerts: pd.DataFrame,
    incidents: pd.DataFrame,
    cleaning_summary: dict[str, int] | None = None,
) -> bytes:
    """Create a dependency-free PDF report from local analysis results."""
    return _pdf_from_lines(build_report_lines(logs, alerts, incidents, cleaning_summary))


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


def _split_pipe_values(value: object) -> list[str]:
    if pd.isna(value):
        return []
    return [item.strip() for item in str(value).split(" | ") if item.strip()]


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
