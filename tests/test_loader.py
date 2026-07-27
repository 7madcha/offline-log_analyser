"""Tests for CSV loading."""

from __future__ import annotations

import pytest

from src.loader import load_logs


def test_load_valid_csv(tmp_path):
    path = tmp_path / "valid.csv"
    path.write_text("timestamp,src_ip\n2026-07-01 00:00:00,10.0.0.1\n", encoding="utf-8")
    df = load_logs(path)
    assert len(df) == 1
    assert list(df.columns) == ["timestamp", "src_ip"]


def test_load_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_logs(tmp_path / "missing.csv")


def test_load_empty_file(tmp_path):
    path = tmp_path / "empty.csv"
    path.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="empty"):
        load_logs(path)


def test_load_invalid_csv(tmp_path):
    path = tmp_path / "invalid.csv"
    path.write_text('timestamp,src_ip\n"2026-07-01,10.0.0.1\n', encoding="utf-8")
    with pytest.raises(ValueError):
        load_logs(path)


def test_load_json_logs(tmp_path):
    path = tmp_path / "logs.json"
    path.write_text('[{"event_time":"2026-07-01 00:00:00","source_ip":"10.0.0.1"}]', encoding="utf-8")
    df = load_logs(path)
    assert len(df) == 1
    assert "source_ip" in df.columns
