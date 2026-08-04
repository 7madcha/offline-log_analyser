"""Tests for per-asset baseline computation and adaptive detection thresholds."""

from __future__ import annotations

import pandas as pd
import pytest

from src.baseline import (
    AssetBaseline,
    BaselineStore,
    _get_asset_key,
    _median_and_mad,
    compute_baseline,
)
from src.detectors import detect_host_scan, detect_port_scan


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _baseline_config(
    enabled: bool = True,
    min_history_events: int = 50,
    deviation_multiplier: float = 3.0,
    min_threshold_floor: int = 5,
) -> dict:
    """Return a minimal config dict with baselining section."""
    return {
        "baselining": {
            "enabled": enabled,
            "group_by": "src_ip",
            "subnet_prefix_length": 24,
            "min_history_events": min_history_events,
            "deviation_multiplier": deviation_multiplier,
            "min_threshold_floor": min_threshold_floor,
        },
        "ai_detection": {"window_minutes": 5},
        "brute_force": {"blocked_attempts": 50, "window_minutes": 1, "destination_ports": [22, 23, 3389], "score": 30},
        "port_scan": {"unique_ports": 20, "window_minutes": 5, "score": 25},
        "host_scan": {"unique_destinations": 30, "window_minutes": 5, "score": 20},
        "large_transfer": {"percentile": 0.99, "minimum_bytes": 10_000_000, "score": 20},
        "off_hours": {"start_hour": 0, "end_hour": 5, "score": 10},
        "correlation": {"window_minutes": 15, "multiple_alert_bonus": 15},
        "severity": {"low_max": 29, "medium_max": 59, "high_max": 79, "critical_max": 100},
    }


def _make_events(
    n: int,
    src_ip: str = "10.0.0.1",
    base: pd.Timestamp | None = None,
    dst_port_fn=None,
    dst_ip_fn=None,
    action: str = "ALLOW",
    spread_seconds: int = 10,
) -> pd.DataFrame:
    """Build a small DataFrame of synthetic log events."""
    if base is None:
        base = pd.Timestamp("2026-07-01 09:00:00")
    rows = []
    for i in range(n):
        port = dst_port_fn(i) if dst_port_fn else 80
        dst = dst_ip_fn(i) if dst_ip_fn else "192.168.1.1"
        rows.append(
            {
                "timestamp": base + pd.Timedelta(seconds=i * spread_seconds),
                "src_ip": src_ip,
                "dst_ip": dst,
                "src_port": 50000 + i,
                "dst_port": port,
                "protocol": "TCP",
                "action": action,
                "bytes_sent": 1000,
                "bytes_received": 500,
            }
        )
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Unit tests for helpers
# ---------------------------------------------------------------------------


def test_median_and_mad_empty():
    med, mad = _median_and_mad(pd.Series([], dtype=float))
    assert med == 0.0 and mad == 0.0


def test_median_and_mad_uniform():
    med, mad = _median_and_mad(pd.Series([5.0, 5.0, 5.0]))
    assert med == 5.0
    assert mad == 0.0


def test_median_and_mad_skewed():
    # Series with an outlier; median should be robust
    s = pd.Series([1.0, 2.0, 2.0, 2.0, 100.0])
    med, mad = _median_and_mad(s)
    assert med == 2.0
    assert mad == 0.0


def test_get_asset_key_src_ip():
    assert _get_asset_key("10.0.0.55", "src_ip") == "10.0.0.55"


def test_get_asset_key_subnet24():
    key = _get_asset_key("10.0.0.55", "subnet24", 24)
    assert key == "10.0.0.0/24"


def test_get_asset_key_invalid_ip_falls_back():
    key = _get_asset_key("not_an_ip", "subnet24", 24)
    assert key == "not_an_ip"


# ---------------------------------------------------------------------------
# Test 1: Sparse data falls back to global threshold
# ---------------------------------------------------------------------------


def test_sparse_asset_falls_back_to_global():
    """An asset with fewer than min_history_events must return the global threshold."""
    cfg = _baseline_config(min_history_events=50)
    # Only 10 events for this IP — well below the 50-event minimum
    df = _make_events(10, src_ip="10.0.0.1")
    store = compute_baseline(df, cfg)

    effective, source, median_val = store.get_effective_threshold("10.0.0.1", "unique_ports", 20.0)

    assert source == "global_config"
    assert effective == 20.0
    assert median_val is None


def test_empty_df_returns_empty_store():
    cfg = _baseline_config()
    store = compute_baseline(pd.DataFrame(), cfg)
    assert len(store) == 0
    # Still usable: falls back to global threshold gracefully
    effective, source, _ = store.get_effective_threshold("10.0.0.1", "unique_ports", 20.0)
    assert source == "global_config"
    assert effective == 20.0


# ---------------------------------------------------------------------------
# Test 2: High-traffic host raises effective threshold vs. a quiet host
# ---------------------------------------------------------------------------


def test_high_traffic_host_gets_higher_threshold():
    """A host with naturally high port diversity should have a higher effective
    threshold than the global default, while a quiet host stays at global."""
    base = pd.Timestamp("2026-07-01 09:00:00")
    cfg = _baseline_config(min_history_events=20, deviation_multiplier=3.0)

    # High-traffic host: touches many unique ports every 5 minutes
    busy_events = []
    for window in range(10):
        for i in range(30):
            ts = base + pd.Timedelta(minutes=window * 5, seconds=i)
            busy_events.append(
                {
                    "timestamp": ts,
                    "src_ip": "10.0.0.200",
                    "dst_ip": "192.168.1.1",
                    "src_port": 50000,
                    "dst_port": 1000 + (window * 30 + i),  # many unique ports
                    "protocol": "TCP",
                    "action": "ALLOW",
                    "bytes_sent": 1000,
                    "bytes_received": 500,
                }
            )

    # Quiet host: one port per window
    quiet_events = []
    for window in range(10):
        ts = base + pd.Timedelta(minutes=window * 5)
        quiet_events.append(
            {
                "timestamp": ts,
                "src_ip": "10.0.0.10",
                "dst_ip": "192.168.1.1",
                "src_port": 50001,
                "dst_port": 443,
                "protocol": "TCP",
                "action": "ALLOW",
                "bytes_sent": 500,
                "bytes_received": 200,
            }
        )

    df = pd.DataFrame(busy_events + quiet_events)
    store = compute_baseline(df, cfg)

    busy_eff, busy_source, _ = store.get_effective_threshold("10.0.0.200", "unique_ports", 20.0)
    quiet_eff, quiet_source, _ = store.get_effective_threshold("10.0.0.10", "unique_ports", 20.0)

    # The busy host's effective threshold must exceed the global default.
    assert busy_source == "per_asset_baseline"
    assert busy_eff > 20.0

    # The quiet host has too few events (10 < 20 min) → falls back to global.
    # (Or if it has enough events, its low activity keeps threshold at global floor.)
    # Either way, busy host threshold must be higher than quiet host threshold.
    assert busy_eff >= quiet_eff


# ---------------------------------------------------------------------------
# Test 3: Differential alert — same raw count, different outcome per baselining
# ---------------------------------------------------------------------------


def _make_port_scan_df(n_ports: int, src_ip: str, base: pd.Timestamp) -> pd.DataFrame:
    """Create a port-scan-like DataFrame hitting n_ports unique ports in one window."""
    rows = []
    for i in range(n_ports):
        rows.append(
            {
                "timestamp": base + pd.Timedelta(seconds=i),
                "src_ip": src_ip,
                "dst_ip": "192.168.1.1",
                "src_port": 50000,
                "dst_port": 1000 + i,
                "protocol": "TCP",
                "action": "ALLOW",
                "bytes_sent": 100,
                "bytes_received": 0,
            }
        )
    return pd.DataFrame(rows)


def test_differential_alert_baselining_enabled():
    """With baselining on, 25 unique ports triggers an alert for a quiet host
    but NOT for a high-traffic host whose baseline already justifies > 25 ports."""
    base = pd.Timestamp("2026-07-01 09:00:00")
    cfg = _baseline_config(
        enabled=True,
        min_history_events=10,  # low so baseline is trusted quickly
        deviation_multiplier=3.0,
    )

    QUIET_IP = "10.0.0.5"
    BUSY_IP = "10.0.0.200"
    OBSERVED_PORTS = 25

    # Build baseline data:
    # - Quiet host: 1 unique port per window across 15 windows → median ≈ 1
    # - Busy host: 30 unique ports per window across 15 windows → median ≈ 30
    baseline_rows = []
    for win in range(15):
        ts = base - pd.Timedelta(hours=2) + pd.Timedelta(minutes=win * 5)
        # Quiet host — 1 port/window
        baseline_rows.append({"timestamp": ts, "src_ip": QUIET_IP, "dst_ip": "192.168.1.1", "src_port": 50000, "dst_port": 443, "protocol": "TCP", "action": "ALLOW", "bytes_sent": 100, "bytes_received": 50})
        # Busy host — 30 ports/window
        for p in range(30):
            baseline_rows.append({"timestamp": ts + pd.Timedelta(seconds=p), "src_ip": BUSY_IP, "dst_ip": "192.168.1.1", "src_port": 50001, "dst_port": 5000 + p, "protocol": "TCP", "action": "ALLOW", "bytes_sent": 100, "bytes_received": 50})

    # Current-window events: both hosts hit 25 unique ports
    current_quiet = _make_port_scan_df(OBSERVED_PORTS, QUIET_IP, base)
    current_busy = _make_port_scan_df(OBSERVED_PORTS, BUSY_IP, base)

    full_df = pd.DataFrame(baseline_rows + current_quiet.to_dict("records") + current_busy.to_dict("records"))

    from src.baseline import compute_baseline
    store = compute_baseline(full_df, cfg)

    # Verify the store has entries for both IPs
    assert store.get(QUIET_IP) is not None
    assert store.get(BUSY_IP) is not None

    # Quiet host effective threshold should be <= 25 (alert should fire)
    q_eff, q_src, q_med = store.get_effective_threshold(QUIET_IP, "unique_ports", 20.0)
    # Busy host effective threshold should be > 25 (alert should NOT fire)
    b_eff, b_src, b_med = store.get_effective_threshold(BUSY_IP, "unique_ports", 20.0)

    # Busy host median ports/window ≈ 30, *3 = 90 → well above 25
    assert b_src == "per_asset_baseline"
    assert b_eff > OBSERVED_PORTS

    # Now run the detector with baselining enabled
    alerts_quiet = detect_port_scan(current_quiet, cfg, baseline=store)
    alerts_busy = detect_port_scan(current_busy, cfg, baseline=store)

    # Quiet host: threshold ≤ 25, so alert fires
    assert len(alerts_quiet) == 1
    ev_quiet = __import__("json").loads(alerts_quiet.iloc[0]["evidence"])
    assert ev_quiet["threshold_source"] in ("per_asset_baseline", "global_config")

    # Busy host: threshold > 25 due to baseline, so no alert
    assert alerts_busy.empty


def test_differential_alert_baselining_disabled(config, event_factory):
    """With baselining off, existing global-threshold behaviour is unchanged."""
    base = pd.Timestamp("2026-07-01 09:00:00")
    df = pd.DataFrame([event_factory(base + pd.Timedelta(seconds=i), dst_port=1000 + i) for i in range(20)])
    # No baseline passed → must behave exactly as before
    alerts = detect_port_scan(df, config)
    assert len(alerts) == 1
    ev = __import__("json").loads(alerts.iloc[0]["evidence"])
    assert ev["threshold_source"] == "global_config"


# ---------------------------------------------------------------------------
# Test 4: Evidence keys always present
# ---------------------------------------------------------------------------


def test_evidence_always_has_threshold_source(config, event_factory):
    """Every port-scan alert — with or without baselining — includes threshold_source."""
    base = pd.Timestamp("2026-07-01 09:00:00")
    df = pd.DataFrame([event_factory(base + pd.Timedelta(seconds=i), dst_port=1000 + i) for i in range(20)])
    for bl in (None, BaselineStore({}, {})):
        alerts = detect_port_scan(df, config, baseline=bl)
        if not alerts.empty:
            ev = __import__("json").loads(alerts.iloc[0]["evidence"])
            assert "threshold_source" in ev
            assert "effective_threshold" in ev
            assert "observed_value" in ev


# ---------------------------------------------------------------------------
# Test 5: Subnet grouping
# ---------------------------------------------------------------------------


def test_subnet_grouping():
    """When group_by=subnet24, IPs in the same /24 share one baseline entry."""
    cfg = _baseline_config(min_history_events=5)
    cfg["baselining"]["group_by"] = "subnet24"
    df1 = _make_events(10, src_ip="10.0.0.1")
    df2 = _make_events(10, src_ip="10.0.0.2")
    df = pd.concat([df1, df2], ignore_index=True)
    store = compute_baseline(df, cfg)
    # Both IPs map to "10.0.0.0/24"; should exist in the store
    assert store.get("10.0.0.0/24") is not None
    # Individual IPs should NOT be in the store
    assert store.get("10.0.0.1") is None
