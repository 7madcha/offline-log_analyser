"""Behavior tests for isolated configurable detectors."""

from __future__ import annotations

from dataclasses import replace

import pandas as pd
from pandas.testing import assert_frame_equal

from src.analysis_settings import AnalysisSettings
from src.custom_detectors import (
    detect_custom_host_scan,
    detect_custom_large_outbound_transfer,
    detect_custom_off_hours_activity,
    detect_custom_port_scan,
    detect_custom_repeated_blocked_connections,
)
from src.detectors import ALERT_COLUMNS, detect_host_scan, detect_large_outbound_transfer, detect_off_hours_activity, detect_port_scan, detect_repeated_blocked_connections


def test_custom_blocked_threshold_controls_result_and_boundary(config, event_factory):
    base = pd.Timestamp("2026-08-10 09:00:00")
    events = pd.DataFrame([event_factory(base + pd.Timedelta(seconds=i)) for i in range(5)])
    settings = replace(AnalysisSettings.from_config(config), brute_force_blocked_attempts=5)

    at_boundary = detect_custom_repeated_blocked_connections(events, settings, config)
    above_activity = detect_custom_repeated_blocked_connections(events, replace(settings, brute_force_blocked_attempts=6), config)

    assert len(at_boundary) == 1
    assert at_boundary.iloc[0]["event_count"] == 5
    assert above_activity.empty
    assert list(at_boundary.columns) == ALERT_COLUMNS
    assert '"threshold_source": "custom_settings"' in at_boundary.iloc[0]["evidence"]


def test_custom_blocked_window_is_used(config, event_factory):
    base = pd.Timestamp("2026-08-10 09:00:00")
    events = pd.DataFrame([event_factory(base + pd.Timedelta(seconds=i * 40)) for i in range(4)])
    settings = replace(AnalysisSettings.from_config(config), brute_force_blocked_attempts=4, brute_force_window_minutes=1)

    assert detect_custom_repeated_blocked_connections(events, settings, config).empty
    assert len(detect_custom_repeated_blocked_connections(events, replace(settings, brute_force_window_minutes=3), config)) == 1


def test_equivalent_blocked_settings_match_standard_finding_without_mutating_it(config, event_factory):
    base = pd.Timestamp("2026-08-10 09:00:00")
    events = pd.DataFrame([event_factory(base + pd.Timedelta(seconds=i)) for i in range(50)])
    original_before = detect_repeated_blocked_connections(events, config)
    custom = detect_custom_repeated_blocked_connections(events, AnalysisSettings.from_config(config), config)
    original_after = detect_repeated_blocked_connections(events, config)

    assert len(custom) == len(original_before) == 1
    assert custom.iloc[0][["alert_type", "event_count", "first_seen", "last_seen"]].to_dict() == original_before.iloc[0][["alert_type", "event_count", "first_seen", "last_seen"]].to_dict()
    assert_frame_equal(original_before, original_after)


def test_custom_port_scan_threshold_controls_result_and_boundary(config, event_factory):
    base = pd.Timestamp("2026-08-10 10:00:00")
    events = pd.DataFrame([event_factory(base + pd.Timedelta(seconds=i), dst_port=1000 + i) for i in range(5)])
    settings = replace(AnalysisSettings.from_config(config), port_scan_unique_ports=5)

    assert len(detect_custom_port_scan(events, settings, config)) == 1
    assert detect_custom_port_scan(events, replace(settings, port_scan_unique_ports=6), config).empty


def test_custom_port_scan_window_is_used(config, event_factory):
    base = pd.Timestamp("2026-08-10 10:00:00")
    events = pd.DataFrame([event_factory(base + pd.Timedelta(seconds=i * 40), dst_port=1000 + i) for i in range(4)])
    settings = replace(AnalysisSettings.from_config(config), port_scan_unique_ports=4, port_scan_window_minutes=1)

    assert detect_custom_port_scan(events, settings, config).empty
    assert len(detect_custom_port_scan(events, replace(settings, port_scan_window_minutes=3), config)) == 1


def test_equivalent_port_scan_settings_match_standard_finding(config, event_factory):
    base = pd.Timestamp("2026-08-10 10:00:00")
    events = pd.DataFrame([event_factory(base + pd.Timedelta(seconds=i), dst_port=1000 + i) for i in range(20)])

    standard = detect_port_scan(events, config)
    custom = detect_custom_port_scan(events, AnalysisSettings.from_config(config), config)

    assert custom.iloc[0][["alert_type", "event_count", "first_seen", "last_seen"]].to_dict() == standard.iloc[0][["alert_type", "event_count", "first_seen", "last_seen"]].to_dict()


def test_custom_host_scan_threshold_controls_result_and_boundary(config, event_factory):
    base = pd.Timestamp("2026-08-10 11:00:00")
    events = pd.DataFrame([event_factory(base + pd.Timedelta(seconds=i), dst_ip=f"192.0.2.{i + 1}") for i in range(5)])
    settings = replace(AnalysisSettings.from_config(config), host_scan_unique_destinations=5)

    assert len(detect_custom_host_scan(events, settings, config)) == 1
    assert detect_custom_host_scan(events, replace(settings, host_scan_unique_destinations=6), config).empty


def test_custom_host_scan_window_is_used(config, event_factory):
    base = pd.Timestamp("2026-08-10 11:00:00")
    events = pd.DataFrame([event_factory(base + pd.Timedelta(seconds=i * 40), dst_ip=f"192.0.2.{i + 1}") for i in range(4)])
    settings = replace(AnalysisSettings.from_config(config), host_scan_unique_destinations=4, host_scan_window_minutes=1)

    assert detect_custom_host_scan(events, settings, config).empty
    assert len(detect_custom_host_scan(events, replace(settings, host_scan_window_minutes=3), config)) == 1


def test_equivalent_host_scan_settings_match_standard_finding(config, event_factory):
    base = pd.Timestamp("2026-08-10 11:00:00")
    events = pd.DataFrame([event_factory(base + pd.Timedelta(seconds=i), dst_ip=f"192.0.2.{i + 1}") for i in range(30)])

    standard = detect_host_scan(events, config)
    custom = detect_custom_host_scan(events, AnalysisSettings.from_config(config), config)

    assert custom.iloc[0][["alert_type", "event_count", "first_seen", "last_seen"]].to_dict() == standard.iloc[0][["alert_type", "event_count", "first_seen", "last_seen"]].to_dict()


def test_custom_large_transfer_threshold_controls_result_and_boundary(config, event_factory):
    base = pd.Timestamp("2026-08-10 12:00:00")
    events = pd.DataFrame([event_factory(base + pd.Timedelta(seconds=i), bytes_sent=value) for i, value in enumerate([100, 200, 300])])
    settings = replace(AnalysisSettings.from_config(config), large_transfer_percentile=1.0, large_transfer_minimum_bytes=300)

    at_boundary = detect_custom_large_outbound_transfer(events, settings, config)
    above_activity = detect_custom_large_outbound_transfer(events, replace(settings, large_transfer_minimum_bytes=301), config)

    assert len(at_boundary) == 1
    assert at_boundary.iloc[0]["event_count"] == 1
    assert above_activity.empty


def test_custom_large_transfer_percentile_is_used(config, event_factory):
    base = pd.Timestamp("2026-08-10 12:00:00")
    events = pd.DataFrame([event_factory(base + pd.Timedelta(seconds=i), bytes_sent=value) for i, value in enumerate([100, 200, 300])])
    settings = replace(AnalysisSettings.from_config(config), large_transfer_percentile=1.0, large_transfer_minimum_bytes=1)

    assert len(detect_custom_large_outbound_transfer(events, settings, config)) == 1
    assert len(detect_custom_large_outbound_transfer(events, replace(settings, large_transfer_percentile=0.5), config)) == 2


def test_equivalent_large_transfer_settings_match_standard_finding(config, event_factory):
    base = pd.Timestamp("2026-08-10 12:00:00")
    events = pd.DataFrame([
        event_factory(base, bytes_sent=100),
        event_factory(base + pd.Timedelta(seconds=1), bytes_sent=10_000_000),
    ])

    standard = detect_large_outbound_transfer(events, config)
    custom = detect_custom_large_outbound_transfer(events, AnalysisSettings.from_config(config), config)

    assert custom.iloc[0][["alert_type", "event_count", "first_seen", "last_seen"]].to_dict() == standard.iloc[0][["alert_type", "event_count", "first_seen", "last_seen"]].to_dict()


def test_custom_off_hours_range_controls_result(config, event_factory):
    event = pd.DataFrame([event_factory(pd.Timestamp("2026-08-10 02:00:00"), action="BLOCK")])
    settings = AnalysisSettings.from_config(config)

    assert len(detect_custom_off_hours_activity(event, settings, config)) == 1
    assert detect_custom_off_hours_activity(event, replace(settings, off_hours_start_hour=3), config).empty


def test_custom_off_hours_boundary_is_start_inclusive_end_exclusive(config, event_factory):
    events = pd.DataFrame([
        event_factory(pd.Timestamp("2026-08-10 00:00:00"), src_ip="10.0.0.1", action="BLOCK"),
        event_factory(pd.Timestamp("2026-08-10 05:00:00"), src_ip="10.0.0.2", action="BLOCK"),
    ])

    alerts = detect_custom_off_hours_activity(events, AnalysisSettings.from_config(config), config)

    assert set(alerts["src_ip"]) == {"10.0.0.1"}


def test_custom_off_hours_wraparound_range(config, event_factory):
    events = pd.DataFrame([
        event_factory(pd.Timestamp("2026-08-10 23:00:00"), src_ip="10.0.0.1", action="BLOCK"),
        event_factory(pd.Timestamp("2026-08-10 12:00:00"), src_ip="10.0.0.2", action="BLOCK"),
    ])
    settings = replace(AnalysisSettings.from_config(config), off_hours_start_hour=22, off_hours_end_hour=5)

    alerts = detect_custom_off_hours_activity(events, settings, config)

    assert set(alerts["src_ip"]) == {"10.0.0.1"}


def test_equivalent_off_hours_settings_match_standard_finding(config, event_factory):
    event = pd.DataFrame([event_factory(pd.Timestamp("2026-08-10 02:00:00"), action="BLOCK")])

    standard = detect_off_hours_activity(event, config)
    custom = detect_custom_off_hours_activity(event, AnalysisSettings.from_config(config), config)

    assert custom.iloc[0][["alert_type", "event_count", "first_seen", "last_seen"]].to_dict() == standard.iloc[0][["alert_type", "event_count", "first_seen", "last_seen"]].to_dict()
