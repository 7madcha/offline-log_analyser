"""Advisory recommendations for investigation."""

from __future__ import annotations

RECOMMENDATION_MAP = {
    "Repeated blocked connections": [
        "Review authentication logs.",
        "Check whether a successful login occurred after the failures.",
        "Confirm whether the source is an authorized system.",
        "Review the targeted account or service.",
    ],
    "Port scan": [
        "Check whether the source is an authorized scanner.",
        "Identify the ports contacted.",
        "Inspect other activity from the same host.",
        "Verify whether the scan was planned.",
    ],
    "Host scan": [
        "Investigate why the source contacted many systems.",
        "Confirm whether it is an administrative or inventory tool.",
        "Inspect endpoint activity.",
    ],
    "Large outbound transfer": [
        "Verify the destination.",
        "Check whether the traffic corresponds to backup or update activity.",
        "Review the source system.",
        "Identify the transferred data when authorized.",
    ],
    "Suspicious off-hours activity": [
        "Confirm whether the activity was expected during the observed time.",
        "Review related blocked connections or unusual ports.",
        "Compare the source behavior with normal business-hours activity.",
    ],
}


def recommendations_for_alert_types(alert_types: list[str] | set[str]) -> str:
    """Return advisory recommendations for the provided alert types."""
    recommendations: list[str] = []
    for alert_type in sorted(set(alert_types)):
        recommendations.extend(RECOMMENDATION_MAP.get(alert_type, []))
    unique = list(dict.fromkeys(recommendations))
    return " | ".join(unique)
