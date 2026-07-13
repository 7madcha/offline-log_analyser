"""Tests for local report utilities."""

from __future__ import annotations

import pandas as pd

from src.reporting import build_pdf_report, csv_schema_template


def test_csv_schema_template_contains_required_columns():
    template = csv_schema_template()
    header = template.splitlines()[0].split(",")
    assert header == [
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


def test_build_pdf_report_returns_pdf_bytes():
    logs = pd.DataFrame({"timestamp": [], "action": []})
    alerts = pd.DataFrame()
    incidents = pd.DataFrame()
    pdf = build_pdf_report(logs, alerts, incidents, {"original_row_count": 0, "final_row_count": 0})
    assert pdf.startswith(b"%PDF-1.4")
    assert b"%%EOF" in pdf
