"""Tests for local report utilities."""

from __future__ import annotations

import pandas as pd

from src.reporting import build_html_report, build_pdf_report, csv_schema_template, export_html_report


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


def test_build_html_report_contains_dashboard_sections():
    logs = pd.DataFrame({"timestamp": [pd.Timestamp("2026-07-01 09:00:00")], "action": ["BLOCK"]})
    alerts = pd.DataFrame(
        {
            "timestamp": [pd.Timestamp("2026-07-01 09:00:00")],
            "src_ip": ["10.0.0.1"],
            "alert_type": ["Port scan"],
            "severity": ["High"],
            "event_count": [20],
            "score_contribution": [25],
        }
    )
    incidents = pd.DataFrame(
        {
            "incident_id": ["INC-001"],
            "src_ip": ["10.0.0.1"],
            "start_time": [pd.Timestamp("2026-07-01 09:00:00")],
            "end_time": [pd.Timestamp("2026-07-01 09:05:00")],
            "risk_score": [80],
            "severity": ["Critical"],
            "alert_types": ["Port scan"],
            "alert_count": [1],
        }
    )

    html = build_html_report(
        logs,
        alerts,
        incidents,
        {"original_row_count": 2, "final_row_count": 1},
        source_label="<local>",
    )

    assert html.startswith("<!doctype html>")
    assert "Offline Log Forensic Analyzer" in html
    assert "Top incidents" in html
    assert "Recent alerts" in html
    assert "INC-001" in html
    assert "&lt;local&gt;" in html


def test_export_html_report_writes_file(tmp_path):
    output = tmp_path / "incident_report.html"
    path = export_html_report(pd.DataFrame({"action": []}), pd.DataFrame(), pd.DataFrame(), output)

    assert path == output
    assert output.read_text(encoding="utf-8").startswith("<!doctype html>")


def test_build_visual_pdf_report_mocked():
    from unittest.mock import patch
    from src.reporting import build_visual_pdf_report
    logs = pd.DataFrame({"timestamp": [], "action": []})
    alerts = pd.DataFrame()
    incidents = pd.DataFrame()

    with patch("src.reporting._html_to_pdf_bytes") as mock_convert:
        mock_convert.return_value = b"%PDF-mock"
        pdf = build_visual_pdf_report(logs, alerts, incidents)
        assert pdf == b"%PDF-mock"
        mock_convert.assert_called_once()


def test_html_to_pdf_bytes_mocked():
    from unittest.mock import MagicMock, patch
    import src.reporting as reporting

    # The shared-browser cache is module-level state (kept alive across calls
    # on purpose, to avoid relaunching Chromium per PDF export) — reset it
    # around this test so it doesn't leak a mock browser into other tests.
    reporting._PLAYWRIGHT_CTX = None
    reporting._PLAYWRIGHT_BROWSER = None
    try:
        with patch("playwright.sync_api.sync_playwright") as mock_sync:
            mock_playwright = MagicMock()
            mock_browser = MagicMock()
            mock_page = MagicMock()

            mock_sync.return_value.start.return_value = mock_playwright
            mock_playwright.chromium.launch.return_value = mock_browser
            mock_browser.new_page.return_value = mock_page
            mock_browser.is_connected.return_value = True
            mock_page.pdf.return_value = b"%PDF-mock-bytes"

            pdf = reporting._html_to_pdf_bytes("<html></html>")
            assert pdf == b"%PDF-mock-bytes"
            mock_page.set_content.assert_called_once_with("<html></html>", wait_until="networkidle")
            mock_page.pdf.assert_called_once()
    finally:
        reporting._PLAYWRIGHT_BROWSER = None
        reporting._PLAYWRIGHT_CTX = None


def test_build_visual_pdf_report_real():
    from src.reporting import build_visual_pdf_report
    logs = pd.DataFrame({"timestamp": [pd.Timestamp("2026-07-01 09:00:00")], "action": ["BLOCK"]})
    alerts = pd.DataFrame()
    incidents = pd.DataFrame()
    try:
        pdf_bytes = build_visual_pdf_report(logs, alerts, incidents, {"original_row_count": 1, "final_row_count": 1})
        assert pdf_bytes.startswith(b"%PDF-")
    except Exception as exc:
        assert "Playwright" in str(exc) or "playwright" in str(exc)

