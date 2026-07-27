"""Threshold-based suspicious activity detectors."""

from __future__ import annotations

import json
from typing import Any

import pandas as pd

from src.scoring import score_for_alert_type, score_to_severity

ALERT_COLUMNS = [
    "alert_id",
    "timestamp",
    "src_ip",
    "dst_ip",
    "alert_type",
    "severity",
    "event_count",
    "window_minutes",
    "evidence",
    "score_contribution",
    "first_seen",
    "last_seen",
    "affected_destinations",
    "affected_ports",
]


def _empty_alerts() -> pd.DataFrame:
    return pd.DataFrame(columns=ALERT_COLUMNS)


def _alert(
    timestamp: pd.Timestamp,
    src_ip: str,
    dst_ip: str,
    alert_type: str,
    event_count: int,
    window_minutes: int,
    evidence: dict[str, Any],
    config: dict,
    first_seen: pd.Timestamp,
    last_seen: pd.Timestamp,
    destinations: list[str],
    ports: list[int],
) -> dict[str, Any]:
    score = score_for_alert_type(alert_type, config)
    return {
        "alert_id": "",
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "alert_type": alert_type,
        "severity": score_to_severity(score, config),
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
    """Return the first source-local time window with enough unique values."""
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


def detect_repeated_blocked_connections(df: pd.DataFrame, config: dict) -> pd.DataFrame:
    """Detect repeated blocked connections from one source in a short window."""
    cfg = config["brute_force"]
    threshold = int(cfg["blocked_attempts"])
    window = int(cfg["window_minutes"])
    ports = set(map(int, cfg["destination_ports"]))
    blocked = df[(df["action"] == "BLOCK") & (df["dst_port"].isin(ports))].copy()
    if blocked.empty:
        return _empty_alerts()

    alerts: list[dict[str, Any]] = []
    candidate_sources = blocked["src_ip"].value_counts()
    candidate_sources = candidate_sources[candidate_sources >= threshold].index
    for src_ip, group in blocked[blocked["src_ip"].isin(candidate_sources)].sort_values("timestamp").groupby("src_ip"):
        indexed = group.set_index("timestamp").sort_index()
        counts = indexed["dst_port"].rolling(f"{window}min").count()
        if counts.max() >= threshold:
            end_time = counts[counts >= threshold].index[0]
            start_time = end_time - pd.Timedelta(minutes=window)
            window_df = group[(group["timestamp"] > start_time) & (group["timestamp"] <= end_time)]
            alerts.append(
                _alert(
                    timestamp=end_time,
                    src_ip=src_ip,
                    dst_ip="multiple" if window_df["dst_ip"].nunique() > 1 else str(window_df["dst_ip"].iloc[0]),
                    alert_type="Repeated blocked connections",
                    event_count=len(window_df),
                    window_minutes=window,
                    evidence={
                        "blocked_connections": int(len(window_df)),
                        "target_ports": sorted(window_df["dst_port"].unique().astype(int).tolist()),
                        "interpretation": "Possible brute-force or automated connection attempts",
                    },
                    config=config,
                    first_seen=window_df["timestamp"].min(),
                    last_seen=window_df["timestamp"].max(),
                    destinations=window_df["dst_ip"].astype(str).tolist(),
                    ports=window_df["dst_port"].astype(int).tolist(),
                )
            )
    return pd.DataFrame(alerts, columns=ALERT_COLUMNS) if alerts else _empty_alerts()


def detect_port_scan(df: pd.DataFrame, config: dict) -> pd.DataFrame:
    """Detect one source contacting many destination ports in a window."""
    cfg = config["port_scan"]
    threshold = int(cfg["unique_ports"])
    window = int(cfg["window_minutes"])
    alerts: list[dict[str, Any]] = []
    candidate_sources = df["src_ip"].value_counts()
    candidate_sources = candidate_sources[candidate_sources >= threshold].index
    for src_ip, group in df[df["src_ip"].isin(candidate_sources)].sort_values("timestamp").groupby("src_ip"):
        window_df = _first_unique_value_window(group, "dst_port", threshold, window)
        if window_df is None:
            continue
        unique_ports = sorted(window_df["dst_port"].unique().astype(int).tolist())
        alerts.append(
            _alert(
                timestamp=window_df["timestamp"].max(),
                src_ip=src_ip,
                dst_ip="multiple" if window_df["dst_ip"].nunique() > 1 else str(window_df["dst_ip"].iloc[0]),
                alert_type="Port scan",
                event_count=len(window_df),
                window_minutes=window,
                evidence={"unique_destination_ports": len(unique_ports), "ports_sample": unique_ports[:50]},
                config=config,
                first_seen=window_df["timestamp"].min(),
                last_seen=window_df["timestamp"].max(),
                destinations=window_df["dst_ip"].astype(str).tolist(),
                ports=unique_ports,
            )
        )
    return pd.DataFrame(alerts, columns=ALERT_COLUMNS) if alerts else _empty_alerts()


def detect_host_scan(df: pd.DataFrame, config: dict) -> pd.DataFrame:
    """Detect one source contacting many destination IPs in a window."""
    cfg = config["host_scan"]
    threshold = int(cfg["unique_destinations"])
    window = int(cfg["window_minutes"])
    alerts: list[dict[str, Any]] = []
    candidate_sources = df["src_ip"].value_counts()
    candidate_sources = candidate_sources[candidate_sources >= threshold].index
    for src_ip, group in df[df["src_ip"].isin(candidate_sources)].sort_values("timestamp").groupby("src_ip"):
        window_df = _first_unique_value_window(group, "dst_ip", threshold, window)
        if window_df is None:
            continue
        destinations = sorted(window_df["dst_ip"].astype(str).unique().tolist())
        alerts.append(
            _alert(
                timestamp=window_df["timestamp"].max(),
                src_ip=src_ip,
                dst_ip="multiple",
                alert_type="Host scan",
                event_count=len(window_df),
                window_minutes=window,
                evidence={"unique_destinations": len(destinations), "destinations_sample": destinations[:50]},
                config=config,
                first_seen=window_df["timestamp"].min(),
                last_seen=window_df["timestamp"].max(),
                destinations=destinations,
                ports=window_df["dst_port"].astype(int).tolist(),
            )
        )
    return pd.DataFrame(alerts, columns=ALERT_COLUMNS) if alerts else _empty_alerts()


def detect_large_outbound_transfer(df: pd.DataFrame, config: dict) -> pd.DataFrame:
    """Detect unusually large outbound bytes_sent values."""
    cfg = config["large_transfer"]
    percentile = float(cfg["percentile"])
    minimum = int(cfg["minimum_bytes"])
    if df.empty:
        return _empty_alerts()
    percentile_threshold = float(df["bytes_sent"].quantile(percentile))
    threshold = max(percentile_threshold, minimum)
    candidates = df[df["bytes_sent"] >= threshold].copy()
    alerts: list[dict[str, Any]] = []
    for _, row in candidates.iterrows():
        alerts.append(
            _alert(
                timestamp=row["timestamp"],
                src_ip=str(row["src_ip"]),
                dst_ip=str(row["dst_ip"]),
                alert_type="Large outbound transfer",
                event_count=1,
                window_minutes=0,
                evidence={
                    "bytes_sent": int(row["bytes_sent"]),
                    "threshold": int(threshold),
                    "interpretation": "Unusually large outbound data transfer requiring investigation",
                },
                config=config,
                first_seen=row["timestamp"],
                last_seen=row["timestamp"],
                destinations=[str(row["dst_ip"])],
                ports=[int(row["dst_port"])],
            )
        )
    return pd.DataFrame(alerts, columns=ALERT_COLUMNS) if alerts else _empty_alerts()


def detect_off_hours_activity(df: pd.DataFrame, config: dict) -> pd.DataFrame:
    """Detect off-hours activity with another suspicious characteristic."""
    cfg = config["off_hours"]
    start_hour = int(cfg["start_hour"])
    end_hour = int(cfg["end_hour"])
    window = 5
    if start_hour < end_hour:
        off_hours = df[(df["timestamp"].dt.hour >= start_hour) & (df["timestamp"].dt.hour < end_hour)].copy()
    else:
        off_hours = df[(df["timestamp"].dt.hour >= start_hour) | (df["timestamp"].dt.hour < end_hour)].copy()
    if off_hours.empty:
        return _empty_alerts()

    rare_ports = {23, 3389, 445, 1433, 3306, 5900}
    large_threshold = max(int(config["large_transfer"]["minimum_bytes"]), int(df["bytes_sent"].quantile(float(config["large_transfer"]["percentile"]))))
    alerts: list[dict[str, Any]] = []
    for src_ip, group in off_hours.sort_values("timestamp").groupby("src_ip"):
        suspicious = group[
            (group["action"] == "BLOCK")
            | (group["bytes_sent"] >= large_threshold)
            | (group["dst_port"].isin(rare_ports))
        ].copy()
        if suspicious.empty:
            continue
        repeated = len(group) >= 5
        if repeated or not suspicious.empty:
            alerts.append(
                _alert(
                    timestamp=suspicious["timestamp"].min(),
                    src_ip=src_ip,
                    dst_ip="multiple" if suspicious["dst_ip"].nunique() > 1 else str(suspicious["dst_ip"].iloc[0]),
                    alert_type="Suspicious off-hours activity",
                    event_count=len(suspicious),
                    window_minutes=window,
                    evidence={
                        "off_hours_window": f"{start_hour:02d}:00-{end_hour:02d}:00",
                        "blocked_events": int((suspicious["action"] == "BLOCK").sum()),
                        "rare_ports": sorted(set(suspicious.loc[suspicious["dst_port"].isin(rare_ports), "dst_port"].astype(int).tolist())),
                        "large_transfer_events": int((suspicious["bytes_sent"] >= large_threshold).sum()),
                    },
                    config=config,
                    first_seen=suspicious["timestamp"].min(),
                    last_seen=suspicious["timestamp"].max(),
                    destinations=suspicious["dst_ip"].astype(str).tolist(),
                    ports=suspicious["dst_port"].astype(int).tolist(),
                )
            )
    return pd.DataFrame(alerts, columns=ALERT_COLUMNS) if alerts else _empty_alerts()


def run_all_detectors(df: pd.DataFrame, config: dict, available_columns: set[str] | None = None) -> pd.DataFrame:
    """Run every detector, combine results, remove duplicates, and assign IDs."""
    available = set(available_columns or df.attrs.get("available_columns", df.columns))
    detector_requirements = {
        "Repeated blocked connections": {"timestamp", "src_ip", "dst_ip", "dst_port", "action"},
        "Port scan": {"timestamp", "src_ip", "dst_ip", "dst_port"},
        "Host scan": {"timestamp", "src_ip", "dst_ip", "dst_port"},
        "Large outbound transfer": {"timestamp", "src_ip", "dst_ip", "dst_port", "bytes_sent"},
        "Suspicious off-hours activity": {"timestamp", "src_ip", "dst_ip", "dst_port", "action", "bytes_sent"},
    }
    detector_functions = {
        "Repeated blocked connections": detect_repeated_blocked_connections,
        "Port scan": detect_port_scan,
        "Host scan": detect_host_scan,
        "Large outbound transfer": detect_large_outbound_transfer,
        "Suspicious off-hours activity": detect_off_hours_activity,
    }
    skipped = [name for name, required in detector_requirements.items() if not required.issubset(available)]
    frames = [detector_functions[name](df, config) for name in detector_requirements if name not in skipped]
    alerts = pd.concat(frames, ignore_index=True) if frames else _empty_alerts()
    if alerts.empty:
        result = _empty_alerts()
        result.attrs["skipped_detectors"] = skipped
        return result
    dedupe_columns = ["timestamp", "src_ip", "dst_ip", "alert_type", "first_seen", "last_seen"]
    alerts = alerts.drop_duplicates(subset=dedupe_columns).sort_values("timestamp").reset_index(drop=True)
    alerts["alert_id"] = [f"ALT-{i:06d}" for i in range(1, len(alerts) + 1)]
    result = alerts[ALERT_COLUMNS]
    result.attrs["skipped_detectors"] = skipped
    return result
