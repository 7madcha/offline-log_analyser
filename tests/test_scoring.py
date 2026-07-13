"""Tests for explainable risk scoring."""

from __future__ import annotations

from src.scoring import calculate_incident_score, score_to_severity


def test_one_alert_type_score(config):
    score, breakdown = calculate_incident_score(["Port scan"], config)
    assert score == 25
    assert "Port scan: +25" in breakdown


def test_multiple_alert_types_bonus(config):
    score, breakdown = calculate_incident_score(["Port scan", "Host scan"], config)
    assert score == 60
    assert "Multiple alert types bonus: +15" in breakdown


def test_score_never_exceeds_100(config):
    score, _ = calculate_incident_score(
        [
            "Repeated blocked connections",
            "Port scan",
            "Host scan",
            "Large outbound transfer",
            "Suspicious off-hours activity",
        ],
        config,
    )
    assert score == 100


def test_correct_severity(config):
    assert score_to_severity(10, config) == "Low"
    assert score_to_severity(30, config) == "Medium"
    assert score_to_severity(60, config) == "High"
    assert score_to_severity(80, config) == "Critical"
