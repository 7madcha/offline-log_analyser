"""Tests for the isolated custom detector runner."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace

import pandas as pd
import pytest

from src.analysis_settings import AnalysisSettings, SettingsValidationError
from src.correlator import correlate_alerts
from src.custom_detector_runner import run_custom_detectors
from src.detectors import ALERT_COLUMNS, run_all_detectors


def _port_scan_events(event_factory, count: int = 20) -> pd.DataFrame:
    base = pd.Timestamp("2026-08-10 12:00:00")
    return pd.DataFrame([event_factory(base + pd.Timedelta(seconds=i), dst_port=1000 + i) for i in range(count)])


def test_runner_returns_compatible_auditable_alerts(config, event_factory):
    settings = replace(AnalysisSettings.from_config(config), port_scan_unique_ports=5)
    alerts = run_custom_detectors(_port_scan_events(event_factory, 5), settings, config)

    assert list(alerts.columns) == ALERT_COLUMNS
    assert alerts["alert_id"].tolist() == ["ALT-000001"]
    assert alerts.attrs["analysis_mode"] == "CUSTOM"
    assert alerts.attrs["analysis_settings"] == settings.to_dict()
    incidents = correlate_alerts(alerts, config)
    assert len(incidents) == 1
    assert incidents.iloc[0]["alert_types"] == "Port scan"


def test_runner_skips_only_detectors_missing_required_columns(config, event_factory):
    events = _port_scan_events(event_factory, 5).drop(columns=["action", "bytes_sent"])
    settings = replace(AnalysisSettings.from_config(config), port_scan_unique_ports=5)
    alerts = run_custom_detectors(events, settings, config, set(events.columns))

    assert set(alerts.attrs["skipped_detectors"]) == {
        "Repeated blocked connections",
        "Large outbound transfer",
        "Suspicious off-hours activity",
    }
    assert alerts["alert_type"].tolist() == ["Port scan"]


def test_runner_rejects_unvalidated_settings_instead_of_falling_back(config, event_factory):
    with pytest.raises(SettingsValidationError, match="validated AnalysisSettings"):
        run_custom_detectors(_port_scan_events(event_factory), {"port_scan_unique_ports": 5}, config)  # type: ignore[arg-type]


def test_empty_input_returns_compatible_auditable_result(config):
    empty = pd.DataFrame(columns=config["required_columns"])
    empty["timestamp"] = pd.to_datetime(empty["timestamp"])
    settings = AnalysisSettings.from_config(config)

    result = run_custom_detectors(empty, settings, config)

    assert result.empty
    assert list(result.columns) == ALERT_COLUMNS
    assert result.attrs["analysis_mode"] == "CUSTOM"
    assert result.attrs["analysis_settings"] == settings.to_dict()


def test_runner_does_not_mutate_events_settings_or_scoring_config(config, event_factory):
    events = _port_scan_events(event_factory, 5)
    original_events = events.copy(deep=True)
    original_config = deepcopy(config)
    settings = replace(AnalysisSettings.from_config(config), port_scan_unique_ports=5)
    original_settings = settings.to_dict()

    run_custom_detectors(events, settings, config)

    pd.testing.assert_frame_equal(events, original_events)
    assert config == original_config
    assert settings.to_dict() == original_settings


def test_same_settings_object_can_be_applied_independently_to_two_files(config, event_factory):
    settings = replace(AnalysisSettings.from_config(config), port_scan_unique_ports=5)
    file_a = _port_scan_events(event_factory, 4)
    file_b = _port_scan_events(event_factory, 5)

    assert run_custom_detectors(file_a, settings, config).empty
    assert run_custom_detectors(file_b, settings, config)["alert_type"].tolist() == ["Port scan"]


def test_equivalent_settings_produce_same_detector_types_as_standard_runner(config, event_factory):
    events = _port_scan_events(event_factory, 20)

    standard = run_all_detectors(events, config)
    custom = run_custom_detectors(events, AnalysisSettings.from_config(config), config)

    assert standard["alert_type"].tolist() == custom["alert_type"].tolist() == ["Port scan"]
