"""Configurable detectors used only by the isolated CUSTOM analysis path."""

from __future__ import annotations

import json
from typing import Any

import pandas as pd

from src.analysis_settings import AnalysisSettings
from src.detectors import ALERT_COLUMNS
from src.scoring import score_for_alert_type, score_to_severity


def _empty_alerts() -> pd.DataFrame:
    return pd.DataFrame(columns=ALERT_COLUMNS)


def _custom_alert(
    *,
    timestamp: pd.Timestamp,
    src_ip: str,
    dst_ip: str,
    alert_type: str,
    event_count: int,
    window_minutes: int,
    evidence: dict[str, Any],
    scoring_config: dict,
    first_seen: pd.Timestamp,
    last_seen: pd.Timestamp,
    destinations: list[str],
    ports: list[int],
) -> dict[str, Any]:
    """Build the existing downstream-compatible alert schema."""
    score = score_for_alert_type(alert_type, scoring_config)
    return {
        "alert_id": "",
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "alert_type": alert_type,
        "severity": score_to_severity(score, scoring_config),
        "event_count": int(event_count),
        "window_minutes": int(window_minutes),
        "evidence": json.dumps(evidence, sort_keys=True),
        "score_contribution": int(score),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "affected_destinations": ", ".join(sorted(set(map(str, destinations)))),
        "affected_ports": ", ".join(str(port) for port in sorted(set(map(int, ports)))),
    }


def _first_unique_value_window(
    group: pd.DataFrame,
    value_column: str,
    threshold: int,
    window_minutes: int,
) -> pd.DataFrame | None:
    """Return the first source-local window reaching a custom unique count."""
    ordered = group.sort_values("timestamp").reset_index(drop=True)
    times = ordered["timestamp"].tolist()
    values = ordered[value_column].astype(str).tolist()
    counts: dict[str, int] = {}
    left = 0
    window = pd.Timedelta(minutes=window_minutes)
    for right, value in enumerate(values):
        counts[value] = counts.get(value, 0) + 1
        while times[right] - times[left] > window:
            left_value = values[left]
            counts[left_value] -= 1
            if counts[left_value] == 0:
                del counts[left_value]
            left += 1
        if len(counts) >= threshold:
            return ordered.iloc[left : right + 1].copy()
    return None


def detect_custom_repeated_blocked_connections(
    df: pd.DataFrame,
    settings: AnalysisSettings,
    scoring_config: dict,
) -> pd.DataFrame:
    """Detect repeated blocked connections using explicit custom values."""
    threshold = settings.brute_force_blocked_attempts
    window = settings.brute_force_window_minutes
    target_ports = set(settings.brute_force_destination_ports)
    blocked = df[(df["action"] == "BLOCK") & (df["dst_port"].isin(target_ports))].copy()
    if blocked.empty:
        return _empty_alerts()

    alerts: list[dict[str, Any]] = []
    for src_ip, group in blocked.sort_values("timestamp").groupby("src_ip"):
        if len(group) < threshold:
            continue
        indexed = group.set_index("timestamp").sort_index()
        counts = indexed["dst_port"].rolling(f"{window}min").count()
        if counts.max() < threshold:
            continue
        end_time = counts[counts >= threshold].index[0]
        start_time = end_time - pd.Timedelta(minutes=window)
        window_df = group[(group["timestamp"] > start_time) & (group["timestamp"] <= end_time)]
        alerts.append(
            _custom_alert(
                timestamp=end_time,
                src_ip=str(src_ip),
                dst_ip="multiple" if window_df["dst_ip"].nunique() > 1 else str(window_df["dst_ip"].iloc[0]),
                alert_type="Repeated blocked connections",
                event_count=len(window_df),
                window_minutes=window,
                evidence={
                    "blocked_connections": int(len(window_df)),
                    "target_ports": sorted(window_df["dst_port"].unique().astype(int).tolist()),
                    "interpretation": "Possible brute-force or automated connection attempts",
                    "threshold_source": "custom_settings",
                    "effective_threshold": threshold,
                    "observed_value": int(len(window_df)),
                },
                scoring_config=scoring_config,
                first_seen=window_df["timestamp"].min(),
                last_seen=window_df["timestamp"].max(),
                destinations=window_df["dst_ip"].astype(str).tolist(),
                ports=window_df["dst_port"].astype(int).tolist(),
            )
        )
    return pd.DataFrame(alerts, columns=ALERT_COLUMNS) if alerts else _empty_alerts()


def detect_custom_port_scan(
    df: pd.DataFrame,
    settings: AnalysisSettings,
    scoring_config: dict,
) -> pd.DataFrame:
    """Detect a source contacting a custom number of ports in a custom window."""
    threshold = settings.port_scan_unique_ports
    window = settings.port_scan_window_minutes
    alerts: list[dict[str, Any]] = []
    for src_ip, group in df.sort_values("timestamp").groupby("src_ip"):
        window_df = _first_unique_value_window(group, "dst_port", threshold, window)
        if window_df is None:
            continue
        unique_ports = sorted(window_df["dst_port"].unique().astype(int).tolist())
        alerts.append(
            _custom_alert(
                timestamp=window_df["timestamp"].max(),
                src_ip=str(src_ip),
                dst_ip="multiple" if window_df["dst_ip"].nunique() > 1 else str(window_df["dst_ip"].iloc[0]),
                alert_type="Port scan",
                event_count=len(window_df),
                window_minutes=window,
                evidence={
                    "unique_destination_ports": len(unique_ports),
                    "ports_sample": unique_ports[:50],
                    "threshold_source": "custom_settings",
                    "effective_threshold": threshold,
                    "observed_value": len(unique_ports),
                },
                scoring_config=scoring_config,
                first_seen=window_df["timestamp"].min(),
                last_seen=window_df["timestamp"].max(),
                destinations=window_df["dst_ip"].astype(str).tolist(),
                ports=unique_ports,
            )
        )
    return pd.DataFrame(alerts, columns=ALERT_COLUMNS) if alerts else _empty_alerts()


def detect_custom_host_scan(
    df: pd.DataFrame,
    settings: AnalysisSettings,
    scoring_config: dict,
) -> pd.DataFrame:
    """Detect a source contacting a custom number of hosts in a custom window."""
    threshold = settings.host_scan_unique_destinations
    window = settings.host_scan_window_minutes
    alerts: list[dict[str, Any]] = []
    for src_ip, group in df.sort_values("timestamp").groupby("src_ip"):
        window_df = _first_unique_value_window(group, "dst_ip", threshold, window)
        if window_df is None:
            continue
        destinations = sorted(window_df["dst_ip"].astype(str).unique().tolist())
        alerts.append(
            _custom_alert(
                timestamp=window_df["timestamp"].max(),
                src_ip=str(src_ip),
                dst_ip="multiple",
                alert_type="Host scan",
                event_count=len(window_df),
                window_minutes=window,
                evidence={
                    "unique_destinations": len(destinations),
                    "destinations_sample": destinations[:50],
                    "threshold_source": "custom_settings",
                    "effective_threshold": threshold,
                    "observed_value": len(destinations),
                },
                scoring_config=scoring_config,
                first_seen=window_df["timestamp"].min(),
                last_seen=window_df["timestamp"].max(),
                destinations=destinations,
                ports=window_df["dst_port"].astype(int).tolist(),
            )
        )
    return pd.DataFrame(alerts, columns=ALERT_COLUMNS) if alerts else _empty_alerts()


def detect_custom_large_outbound_transfer(
    df: pd.DataFrame,
    settings: AnalysisSettings,
    scoring_config: dict,
) -> pd.DataFrame:
    """Detect outbound transfers using a custom percentile and byte floor."""
    if df.empty:
        return _empty_alerts()
    percentile_threshold = float(df["bytes_sent"].quantile(float(settings.large_transfer_percentile)))
    threshold = max(percentile_threshold, float(settings.large_transfer_minimum_bytes))
    alerts: list[dict[str, Any]] = []
    for _, event in df.iterrows():
        if float(event["bytes_sent"]) < threshold:
            continue
        alerts.append(
            _custom_alert(
                timestamp=event["timestamp"],
                src_ip=str(event["src_ip"]),
                dst_ip=str(event["dst_ip"]),
                alert_type="Large outbound transfer",
                event_count=1,
                window_minutes=0,
                evidence={
                    "bytes_sent": int(event["bytes_sent"]),
                    "threshold": int(threshold),
                    "interpretation": "Unusually large outbound data transfer requiring investigation",
                    "threshold_source": "custom_settings",
                    "effective_threshold": int(threshold),
                    "observed_value": int(event["bytes_sent"]),
                },
                scoring_config=scoring_config,
                first_seen=event["timestamp"],
                last_seen=event["timestamp"],
                destinations=[str(event["dst_ip"])],
                ports=[int(event["dst_port"])],
            )
        )
    return pd.DataFrame(alerts, columns=ALERT_COLUMNS) if alerts else _empty_alerts()


def detect_custom_off_hours_activity(
    df: pd.DataFrame,
    settings: AnalysisSettings,
    scoring_config: dict,
) -> pd.DataFrame:
    """Detect suspicious activity inside the explicit custom off-hours range."""
    if df.empty:
        return _empty_alerts()
    start_hour = settings.off_hours_start_hour
    end_hour = settings.off_hours_end_hour
    if start_hour < end_hour:
        off_hours = df[(df["timestamp"].dt.hour >= start_hour) & (df["timestamp"].dt.hour < end_hour)].copy()
    else:
        off_hours = df[(df["timestamp"].dt.hour >= start_hour) | (df["timestamp"].dt.hour < end_hour)].copy()
    if off_hours.empty:
        return _empty_alerts()

    rare_ports = {23, 3389, 445, 1433, 3306, 5900}
    percentile_threshold = float(df["bytes_sent"].quantile(float(settings.large_transfer_percentile)))
    large_threshold = max(float(settings.large_transfer_minimum_bytes), percentile_threshold)
    alerts: list[dict[str, Any]] = []
    for src_ip, group in off_hours.sort_values("timestamp").groupby("src_ip"):
        suspicious = group[
            (group["action"] == "BLOCK")
            | (group["bytes_sent"] >= large_threshold)
            | (group["dst_port"].isin(rare_ports))
        ].copy()
        if suspicious.empty:
            continue
        alerts.append(
            _custom_alert(
                timestamp=suspicious["timestamp"].min(),
                src_ip=str(src_ip),
                dst_ip="multiple" if suspicious["dst_ip"].nunique() > 1 else str(suspicious["dst_ip"].iloc[0]),
                alert_type="Suspicious off-hours activity",
                event_count=len(suspicious),
                window_minutes=5,
                evidence={
                    "off_hours_window": f"{start_hour:02d}:00-{end_hour:02d}:00",
                    "blocked_events": int((suspicious["action"] == "BLOCK").sum()),
                    "rare_ports": sorted(set(suspicious.loc[suspicious["dst_port"].isin(rare_ports), "dst_port"].astype(int).tolist())),
                    "large_transfer_events": int((suspicious["bytes_sent"] >= large_threshold).sum()),
                    "threshold_source": "custom_settings",
                },
                scoring_config=scoring_config,
                first_seen=suspicious["timestamp"].min(),
                last_seen=suspicious["timestamp"].max(),
                destinations=suspicious["dst_ip"].astype(str).tolist(),
                ports=suspicious["dst_port"].astype(int).tolist(),
            )
        )
    return pd.DataFrame(alerts, columns=ALERT_COLUMNS) if alerts else _empty_alerts()
