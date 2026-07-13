"""Tests for synthetic log profiles."""

from __future__ import annotations

import pytest

from src.generate_logs import generate_firewall_logs


def test_generate_logs_normal_profile_has_requested_rows():
    df = generate_firewall_logs(rows=25, seed=1, profile="normal")
    assert len(df) == 25
    assert set(df["label"]) == {"normal"}


def test_generate_logs_attack_heavy_adds_scenarios():
    df = generate_firewall_logs(rows=25, seed=1, profile="attack-heavy")
    assert len(df) > 25
    assert "combined_incident" in set(df["label"])


def test_generate_logs_rejects_unknown_profile():
    with pytest.raises(ValueError):
        generate_firewall_logs(rows=1, profile="unknown")
