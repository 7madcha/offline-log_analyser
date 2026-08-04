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
        min_events = int(self._cfg.get("min_history_events", 50))
        multiplier = float(self._cfg.get("deviation_multiplier", 3.0))
        floor_val = float(self._cfg.get("min_threshold_floor", 5))

        bl = self._store.get(asset_key)
        if bl is None or bl.event_count < min_events:
            return global_value, "global_config", None

        median_val = self._metric_median(bl, metric)
        if median_val is None or median_val <= 0:
            return global_value, "global_config", None

        # effective = max(global_floor, max(global_value, baseline * multiplier))
        # Never drops below the global config threshold so we do not accidentally
        # suppress alerts for hosts whose baseline is high but still suspicious.
        raw_effective = median_val * multiplier
        effective = max(floor_val, max(global_value, raw_effective))
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
    window_minutes: int = int(config.get("ai_detection", {}).get("window_minutes", 5))

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
    data["_window"] = data["timestamp"].dt.floor(f"{window_minutes}min")
    data["_is_blocked"] = (data["action"] == "BLOCK").astype(int)

    # Aggregate per (asset_key, window) to get per-window feature series
    grouped = data.groupby(["_asset_key", "_window"], dropna=False)
    per_window = grouped.agg(
        _blocked=("_is_blocked", "sum"),
        _unique_ports=("dst_port", "nunique"),
        _unique_dsts=("dst_ip", "nunique"),
    ).reset_index()

    # Per-asset 95th-percentile bytes_sent (event-level, not window-level)
    bytes_p95 = (
        data.groupby("_asset_key", dropna=False)["bytes_sent"]
        .quantile(0.95)
        .rename("_bytes_p95")
    )
    event_counts = data.groupby("_asset_key", dropna=False).size().rename("_event_count")

    # Build one AssetBaseline per asset key
    for asset_key, win_group in per_window.groupby("_asset_key"):
        asset_key_str = str(asset_key)
        n_events = int(event_counts.get(asset_key_str, 0))

        blocked_med, blocked_mad = _median_and_mad(win_group["_blocked"].astype(float))
        ports_med, ports_mad = _median_and_mad(win_group["_unique_ports"].astype(float))
        dsts_med, dsts_mad = _median_and_mad(win_group["_unique_dsts"].astype(float))
        b_p95 = float(bytes_p95.get(asset_key_str, 0.0))

        baselines[asset_key_str] = AssetBaseline(
            asset_key=asset_key_str,
            event_count=n_events,
            blocked_rate_median=blocked_med,
            blocked_rate_mad=blocked_mad,
            unique_ports_median=ports_med,
            unique_ports_mad=ports_mad,
            unique_dsts_median=dsts_med,
            unique_dsts_mad=dsts_mad,
            bytes_sent_p95=b_p95,
        )

    return BaselineStore(baselines, bl_cfg)
