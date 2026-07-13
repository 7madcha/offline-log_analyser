"""Alert-to-incident correlation."""

from __future__ import annotations

from typing import Any

import pandas as pd

from src.explanations import build_incident_explanation
from src.recommendations import recommendations_for_alert_types
from src.scoring import calculate_incident_score, score_to_severity
from src.utils import safe_join

INCIDENT_COLUMNS = [
    "incident_id",
    "src_ip",
    "start_time",
    "end_time",
    "alert_count",
    "alert_types",
    "affected_destinations",
    "affected_ports",
    "event_count",
    "risk_score",
    "severity",
    "score_breakdown",
    "explanation",
    "recommendations",
]


def _empty_incidents() -> pd.DataFrame:
    return pd.DataFrame(columns=INCIDENT_COLUMNS)


def _split_values(values: pd.Series) -> list[str]:
    collected: list[str] = []
    for value in values.dropna().astype(str):
        collected.extend([part.strip() for part in value.split(",") if part.strip()])
    return collected


def _incident_from_group(index: int, src_ip: str, group: pd.DataFrame, config: dict) -> dict[str, Any]:
    alert_types = sorted(group["alert_type"].astype(str).unique().tolist())
    risk_score, breakdown = calculate_incident_score(alert_types, config)
    incident = {
        "incident_id": f"INC-{index:06d}",
        "src_ip": src_ip,
        "start_time": group["first_seen"].min(),
        "end_time": group["last_seen"].max(),
        "alert_count": int(len(group)),
        "alert_types": ", ".join(alert_types),
        "affected_destinations": safe_join(_split_values(group["affected_destinations"])),
        "affected_ports": safe_join(_split_values(group["affected_ports"])),
        "event_count": int(group["event_count"].sum()),
        "risk_score": int(risk_score),
        "severity": score_to_severity(risk_score, config),
        "score_breakdown": " | ".join(breakdown),
        "recommendations": recommendations_for_alert_types(alert_types),
    }
    incident["explanation"] = build_incident_explanation(incident)
    return incident


def correlate_alerts(alerts: pd.DataFrame, config: dict) -> pd.DataFrame:
    """Group alerts from the same source within the configured time window."""
    if alerts.empty:
        return _empty_incidents()

    working = alerts.copy()
    for column in ("timestamp", "first_seen", "last_seen"):
        working[column] = pd.to_datetime(working[column], errors="coerce")
    working = working.sort_values(["src_ip", "timestamp"]).reset_index(drop=True)

    window = pd.Timedelta(minutes=int(config.get("correlation", {}).get("window_minutes", 15)))
    incidents: list[dict[str, Any]] = []
    incident_index = 1
    for src_ip, group in working.groupby("src_ip", sort=True):
        current_rows: list[pd.Series] = []
        current_start: pd.Timestamp | None = None
        for _, row in group.iterrows():
            row_time = row["timestamp"]
            if current_start is None:
                current_rows = [row]
                current_start = row_time
                continue
            if row_time <= current_start + window:
                current_rows.append(row)
            else:
                incident_group = pd.DataFrame(current_rows)
                incidents.append(_incident_from_group(incident_index, src_ip, incident_group, config))
                incident_index += 1
                current_rows = [row]
                current_start = row_time
        if current_rows:
            incident_group = pd.DataFrame(current_rows)
            incidents.append(_incident_from_group(incident_index, src_ip, incident_group, config))
            incident_index += 1

    if not incidents:
        return _empty_incidents()
    return pd.DataFrame(incidents, columns=INCIDENT_COLUMNS).sort_values("start_time").reset_index(drop=True)
