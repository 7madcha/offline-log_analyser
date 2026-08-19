"""Dashboard integration tests for the optional CUSTOM detector path."""

from __future__ import annotations

import base64
import json

import pandas as pd
import pytest

import app
from src.analysis_settings import AnalysisMode, SettingsValidationError


def _csv_upload(frame: pd.DataFrame) -> str:
    encoded = base64.b64encode(frame.to_csv(index=False).encode("utf-8")).decode("ascii")
    return f"data:text/csv;base64,{encoded}"


def _custom_run(contents: str, *, comparison_value=None, port_threshold=5, baseline_value=None):
    return app.run_analysis(
        1,
        "upload",
        "Normal",
        100,
        contents,
        "custom.csv",
        comparison_value or [],
        None,
        None,
        baseline_value or [],
        0,
        ["on"],
        50,
        1,
        "22, 23, 3389",
        port_threshold,
        5,
        30,
        5,
        0.99,
        10_000_000,
        0,
        5,
    )


def test_custom_controls_are_hidden_until_enabled():
    assert app.toggle_custom_settings_controls([])["display"] == "none"
    assert app.toggle_custom_settings_controls(["on"])["display"] == "block"


def test_dashboard_values_build_valid_settings_and_reject_bad_ports():
    settings = app.custom_settings_from_dashboard(10, 2, "22, 3389", 8, 4, 12, 6, 0.95, 5_000_000, 22, 6)
    assert settings.port_scan_unique_ports == 8
    assert settings.brute_force_destination_ports == (22, 3389)

    with pytest.raises(SettingsValidationError, match="only whole numbers"):
        app.custom_settings_from_dashboard(10, 2, "22, ssh", 8, 4, 12, 6, 0.95, 5_000_000, 22, 6)


def test_custom_dashboard_analysis_uses_inputs_and_overrides_baseline(config, event_factory):
    app._reset_analysis_state()
    base = pd.Timestamp("2026-08-10 12:00:00")
    events = pd.DataFrame([event_factory(base + pd.Timedelta(seconds=i), dst_port=1000 + i) for i in range(5)])

    response = _custom_run(_csv_upload(events), baseline_value=["on"])

    assert response[0] == 1
    assert response[1] == ""
    assert app._STATE["analysis_mode"] == AnalysisMode.CUSTOM.value
    assert app._STATE["baselining_enabled"] is False
    assert app._STATE["custom_settings"]["port_scan"]["unique_ports"] == 5
    assert app._STATE["alerts"]["alert_type"].tolist() == ["Port scan"]
    evidence = json.loads(app._STATE["alerts"].iloc[0]["evidence"])
    assert evidence["threshold_source"] == "custom_settings"
    assert evidence["effective_threshold"] == 5


def test_invalid_custom_dashboard_value_is_shown_without_running(event_factory):
    base = pd.Timestamp("2026-08-10 12:00:00")
    events = pd.DataFrame([event_factory(base, dst_port=1000)])

    response = _custom_run(_csv_upload(events), port_threshold=0)

    assert response[0] is app.no_update
    assert "greater than zero" in response[1].children


def test_custom_and_comparison_combination_is_rejected(event_factory):
    base = pd.Timestamp("2026-08-10 12:00:00")
    events = pd.DataFrame([event_factory(base, dst_port=1000)])

    response = _custom_run(_csv_upload(events), comparison_value=["on"])

    assert response[0] is app.no_update
    assert "single-file analysis only" in response[1].children


def test_dash_layout_registers_all_custom_controls():
    response = app.app.server.test_client().get("/_dash-layout")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    for component_id in (
        "custom-settings-toggle",
        "custom-brute-attempts",
        "custom-brute-window",
        "custom-brute-ports",
        "custom-port-threshold",
        "custom-port-window",
        "custom-host-threshold",
        "custom-host-window",
        "custom-transfer-percentile",
        "custom-transfer-bytes",
        "custom-offhours-start",
        "custom-offhours-end",
    ):
        assert component_id in body

