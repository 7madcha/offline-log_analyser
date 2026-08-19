"""Tests for the isolated custom analysis settings model."""

from __future__ import annotations

import json

import pytest

from src.analysis_settings import AnalysisMode, AnalysisSettings, SettingsValidationError, effective_analysis_mode


def _values() -> dict:
    return {
        "brute_force_blocked_attempts": 50,
        "brute_force_window_minutes": 1,
        "brute_force_destination_ports": [22, 23, 3389],
        "port_scan_unique_ports": 20,
        "port_scan_window_minutes": 5,
        "host_scan_unique_destinations": 30,
        "host_scan_window_minutes": 5,
        "large_transfer_percentile": 0.99,
        "large_transfer_minimum_bytes": 10_000_000,
        "off_hours_start_hour": 0,
        "off_hours_end_hour": 5,
    }


def test_valid_configuration_is_accepted_and_serializable(config):
    settings = AnalysisSettings.from_mapping(_values())
    equivalent = AnalysisSettings.from_config(config)

    assert settings == equivalent
    assert settings.brute_force_destination_ports == (22, 23, 3389)
    assert json.loads(json.dumps(settings.to_dict()))["analysis_mode"] == "CUSTOM"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("brute_force_blocked_attempts", -1),
        ("port_scan_unique_ports", 0),
        ("large_transfer_minimum_bytes", -10),
    ],
)
def test_negative_or_zero_threshold_is_rejected(field, value):
    values = _values()
    values[field] = value
    with pytest.raises(SettingsValidationError, match="greater than zero"):
        AnalysisSettings.from_mapping(values)


def test_invalid_time_window_is_rejected():
    values = _values()
    values["host_scan_window_minutes"] = 0
    with pytest.raises(SettingsValidationError, match="greater than zero"):
        AnalysisSettings.from_mapping(values)


@pytest.mark.parametrize(("field", "value"), [("off_hours_start_hour", -1), ("off_hours_end_hour", 25)])
def test_invalid_hour_is_rejected(field, value):
    values = _values()
    values[field] = value
    with pytest.raises(SettingsValidationError, match="between"):
        AnalysisSettings.from_mapping(values)


def test_missing_required_setting_is_rejected():
    values = _values()
    del values["port_scan_unique_ports"]
    with pytest.raises(SettingsValidationError, match="Missing required.*port_scan_unique_ports"):
        AnalysisSettings.from_mapping(values)


def test_non_string_setting_name_is_rejected():
    values = _values()
    values[123] = 5
    with pytest.raises(SettingsValidationError, match="names must be strings"):
        AnalysisSettings.from_mapping(values)


@pytest.mark.parametrize(("field", "value"), [("brute_force_blocked_attempts", "50"), ("large_transfer_percentile", "0.99")])
def test_incorrect_type_is_rejected(field, value):
    values = _values()
    values[field] = value
    with pytest.raises(SettingsValidationError):
        AnalysisSettings.from_mapping(values)


def test_mode_precedence_and_default_state():
    assert effective_analysis_mode() is AnalysisMode.STANDARD
    assert effective_analysis_mode(baseline_enabled=True) is AnalysisMode.BASELINE
    assert effective_analysis_mode(custom_settings_enabled=True) is AnalysisMode.CUSTOM
    assert effective_analysis_mode(custom_settings_enabled=True, baseline_enabled=True) is AnalysisMode.CUSTOM
