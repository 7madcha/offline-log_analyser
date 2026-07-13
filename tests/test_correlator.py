"""Tests for alert correlation."""

from __future__ import annotations

import pandas as pd

from src.correlator import correlate_alerts


def _alert(alert_type: str, src_ip: str, timestamp: str, index: int) -> dict:
    return {
        "alert_id": f"ALT-{index:06d}",
        "timestamp": pd.Timestamp(timestamp),
        "src_ip": src_ip,
        "dst_ip": "192.0.2.1",
        "alert_type": alert_type,
        "severity": "Low",
        "event_count": 1,
        "window_minutes": 5,
        "evidence": "{}",
        "score_contribution": 20,
        "first_seen": pd.Timestamp(timestamp),
        "last_seen": pd.Timestamp(timestamp),
        "affected_destinations": "192.0.2.1",
        "affected_ports": "22",
    }


def test_same_ip_in_window_grouped(config):
    alerts = pd.DataFrame(
        [
            _alert("Port scan", "10.0.0.1", "2026-07-01 09:00:00", 1),
            _alert("Host scan", "10.0.0.1", "2026-07-01 09:10:00", 2),
        ]
    )
    incidents = correlate_alerts(alerts, config)
    assert len(incidents) == 1
    assert incidents["alert_count"].iloc[0] == 2


def test_same_ip_outside_window_separate(config):
    alerts = pd.DataFrame(
        [
            _alert("Port scan", "10.0.0.1", "2026-07-01 09:00:00", 1),
            _alert("Host scan", "10.0.0.1", "2026-07-01 09:20:00", 2),
        ]
    )
    incidents = correlate_alerts(alerts, config)
    assert len(incidents) == 2


def test_different_ips_not_grouped(config):
    alerts = pd.DataFrame(
        [
            _alert("Port scan", "10.0.0.1", "2026-07-01 09:00:00", 1),
            _alert("Host scan", "10.0.0.2", "2026-07-01 09:01:00", 2),
        ]
    )
    incidents = correlate_alerts(alerts, config)
    assert len(incidents) == 2
