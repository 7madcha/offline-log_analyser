"""Explainable incident risk scoring."""

from __future__ import annotations


ALERT_SCORE_KEYS = {
    "Repeated blocked connections": "brute_force",
    "Port scan": "port_scan",
    "Host scan": "host_scan",
    "Large outbound transfer": "large_transfer",
    "Suspicious off-hours activity": "off_hours",
}


def score_for_alert_type(alert_type: str, config: dict) -> int:
    """Return configured score contribution for an alert type."""
    key = ALERT_SCORE_KEYS.get(alert_type)
    if not key:
        return 0
    return int(config.get(key, {}).get("score", 0))


def calculate_incident_score(alert_types: list[str] | set[str], config: dict) -> tuple[int, list[str]]:
    """Calculate a capped score and human-readable score breakdown."""
    unique_types = sorted(set(alert_types))
    score = 0
    breakdown: list[str] = []
    for alert_type in unique_types:
        contribution = score_for_alert_type(alert_type, config)
        if contribution:
            score += contribution
            breakdown.append(f"{alert_type}: +{contribution}")

    if len(unique_types) > 1:
        bonus = int(config.get("correlation", {}).get("multiple_alert_bonus", 0))
        score += bonus
        breakdown.append(f"Multiple alert types bonus: +{bonus}")

    final_score = min(score, 100)
    breakdown.append(f"Final score: {final_score}")
    return final_score, breakdown




def score_to_severity(score: int, config: dict) -> str:
    """Map numeric score to severity using configured thresholds."""
    severity = config.get("severity", {})
    if score <= int(severity.get("low_max", 29)):
        return "Low"
    if score <= int(severity.get("medium_max", 59)):
        return "Medium"
    if score <= int(severity.get("high_max", 79)):
        return "High"
    return "Critical"
