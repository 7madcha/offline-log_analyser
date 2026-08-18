"""Tests for the isolated standalone two-file comparator."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from src.comparison import _alert_type_comparison, _metric_row, _observable_comparison, _severity_comparison, _traffic_metrics, alerts_per_1000, compare_files, DatasetAnalysis
from src.comparison_reporting import build_comparison_html, write_comparison_report


def _write_logs(path: Path, rows: list[dict]) -> Path:
    pd.DataFrame(rows).to_csv(path, index=False)
    return path


def test_two_valid_different_sized_files_are_analyzed_independently(tmp_path, event_factory):
    start = pd.Timestamp("2026-08-01 10:00:00")
    file_a = _write_logs(tmp_path / "a.csv", [event_factory(start)])
    file_b = _write_logs(tmp_path / "b.csv", [event_factory(start), event_factory(start + pd.Timedelta(minutes=1), src_ip="10.0.0.2")])

    result = compare_files(file_a, file_b)

    assert result["file_a"].raw_event_count == 1
    assert result["file_b"].raw_event_count == 2
    assert result["file_a"].logs is not result["file_b"].logs
    cleaned = result["overview"].set_index("metric").loc["Cleaned events"]
    assert cleaned["difference"] == 1


@pytest.mark.parametrize("missing_side", ["a", "b"])
def test_missing_input_is_clear(tmp_path, event_factory, missing_side):
    valid = _write_logs(tmp_path / "valid.csv", [event_factory(pd.Timestamp("2026-08-01"))])
    missing = tmp_path / "missing.csv"
    with pytest.raises(FileNotFoundError, match="does not exist"):
        compare_files(missing, valid) if missing_side == "a" else compare_files(valid, missing)


def test_empty_invalid_and_unsupported_inputs_fail_without_comparison(tmp_path, event_factory):
    valid = _write_logs(tmp_path / "valid.csv", [event_factory(pd.Timestamp("2026-08-01"))])
    empty = tmp_path / "empty.csv"
    empty.touch()
    unsupported = tmp_path / "logs.txt"
    unsupported.write_text("not a supported log", encoding="utf-8")
    invalid = tmp_path / "invalid.csv"
    invalid.write_text('"unterminated', encoding="utf-8")
    with pytest.raises(ValueError, match="empty"):
        compare_files(valid, empty)
    with pytest.raises(ValueError, match="unsupported"):
        compare_files(valid, unsupported)
    with pytest.raises(ValueError):
        compare_files(valid, invalid)


def test_same_supported_type_is_required(tmp_path, event_factory):
    row = event_factory(pd.Timestamp("2026-08-01"))
    csv_path = _write_logs(tmp_path / "a.csv", [row])
    json_path = tmp_path / "b.json"
    pd.DataFrame([row]).to_json(json_path, orient="records", date_format="iso")
    with pytest.raises(ValueError, match="same supported file type"):
        compare_files(csv_path, json_path)


def test_percentage_change_is_safe_for_zero_baseline():
    assert _metric_row("Alerts", 0, 4)["percentage_change"] is None
    assert _metric_row("Alerts", 2, 4)["percentage_change"] == 100
    assert alerts_per_1000(4, 0) == 0
    assert alerts_per_1000(4, 2000) == 2


def _analysis(name: str, alerts: pd.DataFrame, incidents: pd.DataFrame) -> DatasetAnalysis:
    return DatasetAnalysis(Path(name), 10, pd.DataFrame(index=range(10)), alerts, incidents, pd.DataFrame(), {}, None, None)


def test_alert_types_and_incident_severities_use_existing_names():
    a = _analysis("a.csv", pd.DataFrame({"alert_type": ["Port scan"]}), pd.DataFrame({"severity": ["Medium"], "risk_score": [30], "alert_types": ["Port scan"]}))
    b = _analysis("b.csv", pd.DataFrame({"alert_type": ["Port scan", "Port scan", "Host scan"]}), pd.DataFrame({"severity": ["High", "Critical"], "risk_score": [70, 90], "alert_types": ["Port scan", "Host scan"]}))

    alerts = _alert_type_comparison(a, b).set_index("alert_type")
    severities = _severity_comparison(a, b).set_index("severity")

    assert alerts.loc["Host scan", "status"] == "newly appearing"
    assert alerts.loc["Port scan", "difference"] == 1
    assert severities.loc["High", "difference"] == 1
    assert severities.loc["Critical", "difference"] == 1


def test_new_source_destination_and_port_are_ranked_with_security_context():
    columns = ["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "action", "bytes_sent", "bytes_received"]
    logs_a = pd.DataFrame([[pd.Timestamp("2026-08-01"), "10.0.0.1", "192.0.2.1", 443, "TCP", "ALLOW", 100, 20]], columns=columns)
    logs_b = pd.DataFrame([[pd.Timestamp("2026-08-02"), "10.0.0.9", "198.51.100.9", 22, "TCP", "BLOCK", 900, 30]], columns=columns)
    alerts_b = pd.DataFrame({"src_ip": ["10.0.0.9"], "affected_destinations": ["198.51.100.9"], "affected_ports": ["22"]})
    incidents_b = pd.DataFrame({"src_ip": ["10.0.0.9"], "risk_score": [80]})
    a = DatasetAnalysis(Path("a.csv"), 1, logs_a, pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), {}, None, None)
    b = DatasetAnalysis(Path("b.csv"), 1, logs_b, alerts_b, incidents_b, pd.DataFrame(), {}, None, None)

    new, removed = _observable_comparison(a, b)

    assert {"source_ip", "destination_ip", "destination_port"} == set(new["category"])
    assert new.iloc[0]["value"] == "10.0.0.9"
    assert new.iloc[0]["highest_incident_risk"] == 80
    assert set(removed["status"]) == {"disappeared"}


def test_traffic_metrics_use_supported_normalized_fields():
    logs_a = pd.DataFrame({"action": ["ALLOW", "BLOCK"], "bytes_sent": [10, 20], "bytes_received": [5, 5]})
    logs_b = pd.DataFrame({"action": ["BLOCK", "BLOCK"], "bytes_sent": [100, 200], "bytes_received": [10, 20]})
    a = DatasetAnalysis(Path("a.csv"), 2, logs_a, pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), {}, None, None)
    b = DatasetAnalysis(Path("b.csv"), 2, logs_b, pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), {}, None, None)
    metrics = _traffic_metrics(a, b).set_index("metric")
    assert metrics.loc["Blocked events", "difference"] == 1
    assert metrics.loc["Block ratio", "file_b"] == 1
    assert metrics.loc["Bytes sent", "difference"] == 270


def test_local_comparison_report_contains_both_files_and_security_sections(tmp_path, event_factory):
    start = pd.Timestamp("2026-08-01 10:00:00")
    file_a = _write_logs(tmp_path / "first.csv", [event_factory(start, action="ALLOW")])
    file_b = _write_logs(tmp_path / "second.csv", [event_factory(start, src_ip="10.0.0.9", dst_port=3389, action="BLOCK")])
    result = compare_files(file_a, file_b)

    html = build_comparison_html(result)
    output = write_comparison_report(result, tmp_path / "reports" / "comparison.html")

    assert "first.csv" in html and "second.csv" in html
    assert "What became more suspicious?" in html
    assert "NEW FINDINGS" in html
    assert output.read_text(encoding="utf-8") == html
