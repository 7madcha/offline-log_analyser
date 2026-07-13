"""Tests for suspicious activity detectors."""

from __future__ import annotations

import pandas as pd

from src.detectors import detect_host_scan, detect_port_scan, detect_repeated_blocked_connections


def test_brute_force_49_blocked_events_no_alert(config, event_factory):
    base = pd.Timestamp("2026-07-01 09:00:00")
    df = pd.DataFrame([event_factory(base + pd.Timedelta(seconds=i)) for i in range(49)])
    alerts = detect_repeated_blocked_connections(df, config)
    assert alerts.empty


def test_brute_force_50_blocked_events_triggers(config, event_factory):
    base = pd.Timestamp("2026-07-01 09:00:00")
    df = pd.DataFrame([event_factory(base + pd.Timedelta(seconds=i)) for i in range(50)])
    alerts = detect_repeated_blocked_connections(df, config)
    assert len(alerts) == 1
    assert alerts["alert_type"].iloc[0] == "Repeated blocked connections"


def test_brute_force_events_outside_window_no_alert(config, event_factory):
    base = pd.Timestamp("2026-07-01 09:00:00")
    df = pd.DataFrame([event_factory(base + pd.Timedelta(seconds=i * 2)) for i in range(50)])
    alerts = detect_repeated_blocked_connections(df, config)
    assert alerts.empty


def test_port_scan_19_unique_ports_no_alert(config, event_factory):
    base = pd.Timestamp("2026-07-01 09:00:00")
    df = pd.DataFrame([event_factory(base + pd.Timedelta(seconds=i), dst_port=1000 + i) for i in range(19)])
    alerts = detect_port_scan(df, config)
    assert alerts.empty


def test_port_scan_20_unique_ports_triggers(config, event_factory):
    base = pd.Timestamp("2026-07-01 09:00:00")
    df = pd.DataFrame([event_factory(base + pd.Timedelta(seconds=i), dst_port=1000 + i) for i in range(20)])
    alerts = detect_port_scan(df, config)
    assert len(alerts) == 1
    assert alerts["alert_type"].iloc[0] == "Port scan"


def test_host_scan_29_destinations_no_alert(config, event_factory):
    base = pd.Timestamp("2026-07-01 09:00:00")
    df = pd.DataFrame([event_factory(base + pd.Timedelta(seconds=i), dst_ip=f"192.0.2.{i + 1}") for i in range(29)])
    alerts = detect_host_scan(df, config)
    assert alerts.empty


def test_host_scan_30_destinations_triggers(config, event_factory):
    base = pd.Timestamp("2026-07-01 09:00:00")
    df = pd.DataFrame([event_factory(base + pd.Timedelta(seconds=i), dst_ip=f"192.0.2.{i + 1}") for i in range(30)])
    alerts = detect_host_scan(df, config)
    assert len(alerts) == 1
    assert alerts["alert_type"].iloc[0] == "Host scan"
