"""Per-asset / per-subnet baseline statistics for adaptive detection thresholds.

All computation is local and purely from the log data already in memory.
No network calls, no external APIs.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

import pandas as pd


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class AssetBaseline:
    """Robust statistics for one asset group (src_ip or subnet key)."""

    asset_key: str
    event_count: int = 0

    # Median + MAD for each metric computed over time-windows
    blocked_rate_median: float = 0.0      # blocked events per window
    blocked_rate_mad: float = 0.0

    unique_ports_median: float = 0.0     # unique dst_ports per window
    unique_ports_mad: float = 0.0

    unique_dsts_median: float = 0.0      # unique dst_ips per window
    unique_dsts_mad: float = 0.0

    bytes_sent_p95: float = 0.0          # 95th-percentile bytes_sent per event


class BaselineStore:
    """Dict-like container of per-asset baselines with threshold resolution.

    Call :meth:`get_effective_threshold` to resolve the threshold for a given
    (asset, metric) pair.  If the asset has too little history the global
    config value is returned unchanged, preserving the original behaviour.
    """

    def __init__(self, baselines: dict[str, AssetBaseline], bl_config: dict[str, Any]) -> None:
        self._store: dict[str, AssetBaseline] = baselines
        self._cfg = bl_config

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def get(self, asset_key: str) -> AssetBaseline | None:
        """Return the baseline for *asset_key*, or None if unknown."""
        return self._store.get(asset_key)

    def get_effective_threshold(
        self,
        asset_key: str,
        metric: str,
        global_value: float,
    ) -> tuple[float, str, float | None]:
        """Return (effective_threshold, source_label, baseline_median).

        Parameters
        ----------
        asset_key:
            Key returned by :func:`_get_asset_key`.
        metric:
            One of ``"blocked_rate"``, ``"unique_ports"``,
            ``"unique_dsts"``, ``"bytes_sent"``.
        global_value:
            The global config threshold to fall back to.

        Returns
        -------
        effective_threshold:
            The threshold to use for this asset.
        source_label:
            ``"per_asset_baseline"`` or ``"global_config"``.
        baseline_median:
            The raw median value from the baseline (None when falling back).
        """
        min_events = int(self._cfg.get("min_history_events", 20))
        multiplier = float(self._cfg.get("deviation_multiplier", 2.0))
        floor_val = float(self._cfg.get("min_threshold_floor", 5))

        bl = self._store.get(asset_key)
        if bl is None or bl.event_count < min_events:
            return global_value, "global_config", None

        median_val = self._metric_median(bl, metric)
        if median_val is None or median_val <= 0:
            return global_value, "global_config", None

        # Pure per-asset threshold: baseline_median * multiplier, floored at
        # min_threshold_floor.  This can be LOWER than the global config value
        # (catching anomalies earlier for quiet hosts) or HIGHER (reducing
        # false positives for naturally busy hosts like proxies/DNS servers).
        raw_effective = median_val * multiplier
        effective = max(floor_val, raw_effective)
        return effective, "per_asset_baseline", median_val

    @staticmethod
    def _metric_median(bl: AssetBaseline, metric: str) -> float | None:
        mapping = {
            "blocked_rate": bl.blocked_rate_median,
            "unique_ports": bl.unique_ports_median,
            "unique_dsts": bl.unique_dsts_median,
            "bytes_sent": bl.bytes_sent_p95,
        }
        return mapping.get(metric)

    def __len__(self) -> int:
        return len(self._store)

    def __repr__(self) -> str:
        return f"BaselineStore(assets={len(self._store)}, config={self._cfg})"


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


def _get_asset_key(
    src_ip: str,
    group_by: str = "src_ip",
    prefix_length: int = 24,
) -> str:
    """Return the grouping key for *src_ip*.

    group_by ``"src_ip"`` returns the address as-is.
    group_by ``"subnet24"`` returns the network address of the CIDR block,
    e.g. ``"10.0.1.0/24"``.
    """
    if group_by == "src_ip":
        return str(src_ip)
    try:
        network = ipaddress.ip_network(f"{src_ip}/{prefix_length}", strict=False)
        return str(network)
    except ValueError:
        return str(src_ip)


# ---------------------------------------------------------------------------
# Robust statistics helpers
# ---------------------------------------------------------------------------


def _median_and_mad(series: pd.Series) -> tuple[float, float]:
    """Return (median, MAD) for *series*, both 0.0 if the series is empty."""
    if series.empty:
        return 0.0, 0.0
    med = float(series.median())
    mad = float((series - med).abs().median())
    return med, mad


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def compute_baseline(df: pd.DataFrame, config: dict) -> BaselineStore:
    """Compute per-asset baselines from cleaned log data.

    Parameters
    ----------
    df:
        Cleaned log DataFrame.  Must have at minimum ``timestamp`` and
        ``src_ip`` columns.
    config:
        Full config dict as returned by :func:`src.utils.load_config`.
        The ``baselining`` sub-dict drives grouping; ``ai_detection``
        provides the window length used for per-window aggregation.

    Returns
    -------
    BaselineStore
        Container of :class:`AssetBaseline` objects.  If *df* is empty or
        missing required columns the store is empty but still usable — all
        assets will fall back to global thresholds.
    """
    bl_cfg: dict[str, Any] = config.get("baselining", {})
    group_by: str = str(bl_cfg.get("group_by", "src_ip"))
    prefix: int = int(bl_cfg.get("subnet_prefix_length", 24))

    # Each metric is compared against a detector that has its own window size
    # (e.g. brute_force runs on 1-minute windows, port_scan on 5-minute
    # windows). Bucketing every metric into one shared window size would
    # silently miscalibrate whichever detector's window differs from it, so
    # each metric gets its own window length pulled from that detector's
    # config, falling back to the AI window if a section is missing.
    default_window = int(config.get("ai_detection", {}).get("window_minutes", 5))
    blocked_window = int(config.get("brute_force", {}).get("window_minutes", default_window))
    ports_window = int(config.get("port_scan", {}).get("window_minutes", default_window))
    dsts_window = int(config.get("host_scan", {}).get("window_minutes", default_window))

    baselines: dict[str, AssetBaseline] = {}

    required = {"timestamp", "src_ip"}
    if df is None or df.empty or not required.issubset(df.columns):
        return BaselineStore(baselines, bl_cfg)

    data = df.copy(deep=True)
    data["timestamp"] = pd.to_datetime(data["timestamp"], errors="coerce")
    data = data.dropna(subset=["timestamp", "src_ip"])
    if data.empty:
        return BaselineStore(baselines, bl_cfg)

    # Ensure optional columns exist with neutral defaults
    if "action" not in data.columns:
        data["action"] = "ALLOW"
    if "bytes_sent" not in data.columns:
        data["bytes_sent"] = 0
    if "dst_port" not in data.columns:
        data["dst_port"] = pd.NA
    if "dst_ip" not in data.columns:
        data["dst_ip"] = pd.NA

    data["action"] = data["action"].astype(str).str.upper()
    data["bytes_sent"] = pd.to_numeric(data["bytes_sent"], errors="coerce").fillna(0).clip(lower=0)

    # Build asset grouping key column
    data["_asset_key"] = data["src_ip"].astype(str).apply(
        lambda ip: _get_asset_key(ip, group_by, prefix)
    )
    data["_is_blocked"] = (data["action"] == "BLOCK").astype(int)

    def _per_window_median(window_minutes: int, value_col: str, agg: str) -> pd.Series:
        """Median of *value_col* aggregated by *agg* over asset/window buckets."""
        window_col = data["timestamp"].dt.floor(f"{window_minutes}min")
        grouped = data.groupby(["_asset_key", window_col], dropna=False)[value_col].agg(agg)
        return grouped.groupby("_asset_key").median()

    def _per_window_mad(window_minutes: int, value_col: str, agg: str, medians: pd.Series) -> pd.Series:
        window_col = data["timestamp"].dt.floor(f"{window_minutes}min")
        grouped = data.groupby(["_asset_key", window_col], dropna=False)[value_col].agg(agg)
        deviations = (grouped - grouped.index.get_level_values("_asset_key").map(medians)).abs()
        return deviations.groupby("_asset_key").median()

    blocked_medians = _per_window_median(blocked_window, "_is_blocked", "sum")
    blocked_mads = _per_window_mad(blocked_window, "_is_blocked", "sum", blocked_medians)
    ports_medians = _per_window_median(ports_window, "dst_port", "nunique")
    ports_mads = _per_window_mad(ports_window, "dst_port", "nunique", ports_medians)
    dsts_medians = _per_window_median(dsts_window, "dst_ip", "nunique")
    dsts_mads = _per_window_mad(dsts_window, "dst_ip", "nunique", dsts_medians)

    # Per-asset 95th-percentile bytes_sent (event-level, not window-level)
    bytes_p95 = data.groupby("_asset_key", dropna=False)["bytes_sent"].quantile(0.95)
    event_counts = data.groupby("_asset_key", dropna=False).size()

    for asset_key in event_counts.index:
        asset_key_str = str(asset_key)
        baselines[asset_key_str] = AssetBaseline(
            asset_key=asset_key_str,
            event_count=int(event_counts.get(asset_key, 0)),
            blocked_rate_median=float(blocked_medians.get(asset_key, 0.0)),
            blocked_rate_mad=float(blocked_mads.get(asset_key, 0.0)),
            unique_ports_median=float(ports_medians.get(asset_key, 0.0)),
            unique_ports_mad=float(ports_mads.get(asset_key, 0.0)),
            unique_dsts_median=float(dsts_medians.get(asset_key, 0.0)),
            unique_dsts_mad=float(dsts_mads.get(asset_key, 0.0)),
            bytes_sent_p95=float(bytes_p95.get(asset_key, 0.0)),
        )

    return BaselineStore(baselines, bl_cfg)
