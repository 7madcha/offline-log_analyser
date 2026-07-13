"""Shared test fixtures."""

from __future__ import annotations

import pandas as pd
import pytest


@pytest.fixture
def config() -> dict:
    return {
        "required_columns": [
            "timestamp",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
            "action",
            "bytes_sent",
            "bytes_received",
        ],
        "brute_force": {
            "blocked_attempts": 50,
            "window_minutes": 1,
            "destination_ports": [22, 23, 3389],
            "score": 30,
        },
        "port_scan": {"unique_ports": 20, "window_minutes": 5, "score": 25},
        "host_scan": {"unique_destinations": 30, "window_minutes": 5, "score": 20},
        "large_transfer": {"percentile": 0.99, "minimum_bytes": 10000000, "score": 20},
        "off_hours": {"start_hour": 0, "end_hour": 5, "score": 10},
        "correlation": {"window_minutes": 15, "multiple_alert_bonus": 15},
        "severity": {"low_max": 29, "medium_max": 59, "high_max": 79, "critical_max": 100},
    }


def make_event(
    timestamp: pd.Timestamp,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "192.0.2.1",
    src_port: int = 50000,
    dst_port: int = 22,
    protocol: str = "TCP",
    action: str = "BLOCK",
    bytes_sent: int = 100,
    bytes_received: int = 0,
) -> dict:
    return {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "action": action,
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
    }


@pytest.fixture
def event_factory():
    return make_event
