"""Behavioral feature engineering for local AI anomaly detection."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pandas as pd

if TYPE_CHECKING:
    from src.baseline import BaselineStore

IDENTIFIER_COLUMNS = ["src_ip", "window_start"]
TRAINING_METADATA_COLUMNS = ["normal_label_ratio", "has_reliable_normal_label"]
MODEL_FEATURES = [
    "connection_count", "blocked_count", "blocked_ratio", "unique_dst_ips",
    "unique_dst_ports", "bytes_sent_total", "bytes_received_total",
    "average_bytes_sent", "average_bytes_received", "tcp_ratio", "udp_ratio",
    "activity_hour", "off_hours_indicator",
]
BASELINE_FEATURES = [
    "connection_count_vs_baseline_ratio",
    "unique_ports_vs_baseline_ratio",
]


def build_behavioral_features(
    logs: pd.DataFrame,
    window_minutes: int = 5,
    working_start_hour: int = 5,
    working_end_hour: int = 24,
    baseline: "BaselineStore | None" = None,
) -> pd.DataFrame:
    """Aggregate log events by source and time window into numerical features.

    When *baseline* is supplied (requires baselining enabled in config), two
    extra ratio columns are added for the Isolation Forest so it can learn
    asset-relative deviation in addition to absolute counts.
    """
    use_baseline_features = baseline is not None
    active_features = MODEL_FEATURES + (BASELINE_FEATURES if use_baseline_features else [])
    columns = IDENTIFIER_COLUMNS + active_features + TRAINING_METADATA_COLUMNS
    required = {"timestamp", "src_ip"}
    if logs is None or logs.empty or not required.issubset(logs.columns) or window_minutes <= 0:
        return pd.DataFrame(columns=columns)

    data = logs.copy(deep=True)
    data["timestamp"] = pd.to_datetime(data["timestamp"], errors="coerce")
    data = data.dropna(subset=["timestamp", "src_ip"])
    if data.empty:
        return pd.DataFrame(columns=columns)
    for name in ("bytes_sent", "bytes_received"):
        data[name] = pd.to_numeric(data[name], errors="coerce").fillna(0).clip(lower=0) if name in data else 0
    data["action"] = data["action"].astype(str).str.upper() if "action" in data else ""
    data["protocol"] = data["protocol"].astype(str).str.upper() if "protocol" in data else ""
    data["window_start"] = data["timestamp"].dt.floor(f"{int(window_minutes)}min")
    data["is_blocked"] = data["action"].eq("BLOCK").astype(int)
    data["is_tcp"] = data["protocol"].eq("TCP").astype(int)
    data["is_udp"] = data["protocol"].eq("UDP").astype(int)
    normal_labels = {"normal", "benign", "legitimate", "0", "false"}
    if "label" in data:
        normalized_labels = data["label"].astype(str).str.strip().str.lower()
        data["known_label"] = normalized_labels.ne("") & normalized_labels.ne("nan")
        data["is_normal_label"] = normalized_labels.isin(normal_labels).astype(int)
    else:
        data["known_label"] = False
        data["is_normal_label"] = 0
    if "dst_ip" not in data:
        data["dst_ip"] = pd.NA
    if "dst_port" not in data:
        data["dst_port"] = pd.NA

    grouped = data.groupby(["src_ip", "window_start"], dropna=False)
    result = grouped.agg(
        connection_count=("timestamp", "size"), blocked_count=("is_blocked", "sum"),
        unique_dst_ips=("dst_ip", "nunique"), unique_dst_ports=("dst_port", "nunique"),
        bytes_sent_total=("bytes_sent", "sum"), bytes_received_total=("bytes_received", "sum"),
        average_bytes_sent=("bytes_sent", "mean"), average_bytes_received=("bytes_received", "mean"),
        tcp_ratio=("is_tcp", "mean"), udp_ratio=("is_udp", "mean"),
        normal_label_ratio=("is_normal_label", "mean"), has_reliable_normal_label=("known_label", "all"),
    ).reset_index()
    result["blocked_ratio"] = result["blocked_count"].div(result["connection_count"].replace(0, pd.NA)).fillna(0)
    result["activity_hour"] = result["window_start"].dt.hour
    if working_start_hour < working_end_hour:
        result["off_hours_indicator"] = (~result["activity_hour"].between(working_start_hour, working_end_hour - 1)).astype(int)
    else:
        result["off_hours_indicator"] = result["activity_hour"].between(working_end_hour, working_start_hour - 1).astype(int)
    result["has_reliable_normal_label"] = result["has_reliable_normal_label"] & result["normal_label_ratio"].eq(1.0)

    if use_baseline_features:
        def _bl_conn(src_ip: str) -> float:
            bl = baseline.get(src_ip)  # type: ignore[union-attr]
            return float(bl.event_count) if bl and bl.event_count > 0 else 0.0

        def _bl_ports(src_ip: str) -> float:
            bl = baseline.get(src_ip)  # type: ignore[union-attr]
            return float(bl.unique_ports_median) if bl and bl.unique_ports_median > 0 else 0.0

        bl_conn = result["src_ip"].astype(str).map(_bl_conn)
        bl_ports = result["src_ip"].astype(str).map(_bl_ports)
        result["connection_count_vs_baseline_ratio"] = (
            result["connection_count"].div(bl_conn.replace(0, pd.NA)).fillna(1.0).clip(lower=0)
        )
        result["unique_ports_vs_baseline_ratio"] = (
            result["unique_dst_ports"].div(bl_ports.replace(0, pd.NA)).fillna(1.0).clip(lower=0)
        )

    return result[columns].sort_values(["window_start", "src_ip"]).reset_index(drop=True)
