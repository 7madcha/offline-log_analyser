"""Tests for alternate log schemas and partial-data behavior."""

from __future__ import annotations

import pandas as pd
import pytest

from src.cleaner import clean_logs
from src.detectors import run_all_detectors
from src.schema_mapper import map_log_schema


def test_mapper_renames_common_alternate_columns(config):
    source = pd.DataFrame(
        [{
            "event_time": "2026-07-01T09:00:00",
            "source_address": "10.0.0.1",
            "destination_address": "192.0.2.1",
            "source_port": 50000,
            "destination_port": 443,
            "transport_protocol": "tcp",
            "verdict": "deny",
            "bytes_out": 100,
            "bytes_in": 50,
        }]
    )

    mapped = map_log_schema(source, config)
    cleaned, _ = clean_logs(mapped.logs, set(mapped.mapped_columns))

    assert set(mapped.mapped_columns) == set(config["required_columns"])
    assert cleaned.iloc[0]["src_ip"] == "10.0.0.1"
    assert cleaned.iloc[0]["action"] == "BLOCK"


def test_mapper_accepts_palo_alto_export_headers(config):
    source = pd.DataFrame(
        [{
            "Generated Time": "2026/07/26 09:25:27",
            "Source address": "10.0.247.175",
            "Destination address": "137.94.75.68",
            "Source Port": 4458,
            "Destination Port": 80,
            "Protocol": "tcp",
            "Action": "allow",
            "Bytes Sent": 48565,
            "Bytes Received": 178005,
        }]
    )

    mapped = map_log_schema(source, config)
    cleaned, _ = clean_logs(mapped.logs, set(mapped.mapped_columns))

    assert len(cleaned) == 1
    assert mapped.mapped_columns["timestamp"] == "Generated Time"
    assert mapped.mapped_columns["src_ip"] == "Source address"


def test_mapper_requires_timestamp_and_source_ip(config):
    with pytest.raises(ValueError, match="required log fields"):
        map_log_schema(pd.DataFrame([{"event_time": "2026-07-01 09:00:00"}]), config)


def test_partial_logs_keep_supported_features_and_report_skips(config):
    source = pd.DataFrame(
        [{"timestamp": "2026-07-01 09:00:00", "src_ip": "10.0.0.1", "action": "ALLOW"}]
    )
    mapped = map_log_schema(source, config)
    cleaned, _ = clean_logs(mapped.logs, set(mapped.mapped_columns))
    alerts = run_all_detectors(cleaned, config, set(mapped.mapped_columns))

    assert len(cleaned) == 1
    assert alerts.empty
    assert "Port scan" in alerts.attrs["skipped_detectors"]
    assert "Large outbound transfer" in alerts.attrs["skipped_detectors"]
