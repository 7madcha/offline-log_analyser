"""Tests for log cleaning."""

from __future__ import annotations

import pandas as pd

from src.cleaner import clean_logs


def _base_row(**overrides):
    row = {
        "timestamp": "2026-07-01 09:00:00",
        "src_ip": "10.0.0.1",
        "dst_ip": "192.0.2.1",
        "src_port": "50000",
        "dst_port": "443",
        "protocol": "tcp",
        "action": "ACCEPT",
        "bytes_sent": "1000",
        "bytes_received": "2000",
        "label": "normal",
    }
    row.update(overrides)
    return row


def test_cleaner_invalid_timestamp():
    df = pd.DataFrame([_base_row(timestamp="bad"), _base_row()])
    cleaned, summary = clean_logs(df)
    assert len(cleaned) == 1
    assert summary["invalid_timestamps"] == 1


def test_cleaner_invalid_ip():
    df = pd.DataFrame([_base_row(src_ip="999.1.1.1"), _base_row()])
    cleaned, summary = clean_logs(df)
    assert len(cleaned) == 1
    assert summary["invalid_ip_addresses"] == 1


def test_cleaner_invalid_port():
    df = pd.DataFrame([_base_row(dst_port="70000"), _base_row()])
    cleaned, summary = clean_logs(df)
    assert len(cleaned) == 1
    assert summary["invalid_ports"] == 1


def test_cleaner_duplicate_removal():
    row = _base_row()
    cleaned, summary = clean_logs(pd.DataFrame([row, row]))
    assert len(cleaned) == 1
    assert summary["duplicate_rows_removed"] == 1


def test_cleaner_action_normalization():
    cleaned, _ = clean_logs(pd.DataFrame([_base_row(action="deny")]))
    assert cleaned["action"].iloc[0] == "BLOCK"
    assert cleaned["protocol"].iloc[0] == "TCP"
