"""Orchestration for the isolated CUSTOM detector path."""

from __future__ import annotations

from collections.abc import Callable

import pandas as pd

from src.analysis_settings import AnalysisMode, AnalysisSettings, SettingsValidationError
from src.custom_detectors import (
    detect_custom_host_scan,
    detect_custom_large_outbound_transfer,
    detect_custom_off_hours_activity,
    detect_custom_port_scan,
    detect_custom_repeated_blocked_connections,
)
from src.detectors import ALERT_COLUMNS


CustomDetector = Callable[[pd.DataFrame, AnalysisSettings, dict], pd.DataFrame]

_DETECTORS: tuple[tuple[str, frozenset[str], CustomDetector], ...] = (
    (
        "Repeated blocked connections",
        frozenset({"timestamp", "src_ip", "dst_ip", "dst_port", "action"}),
        detect_custom_repeated_blocked_connections,
    ),
    ("Port scan", frozenset({"timestamp", "src_ip", "dst_ip", "dst_port"}), detect_custom_port_scan),
    ("Host scan", frozenset({"timestamp", "src_ip", "dst_ip", "dst_port"}), detect_custom_host_scan),
    (
        "Large outbound transfer",
        frozenset({"timestamp", "src_ip", "dst_ip", "dst_port", "bytes_sent"}),
        detect_custom_large_outbound_transfer,
    ),
    (
        "Suspicious off-hours activity",
        frozenset({"timestamp", "src_ip", "dst_ip", "dst_port", "action", "bytes_sent"}),
        detect_custom_off_hours_activity,
    ),
)


def _empty_custom_result(skipped: list[str], settings: AnalysisSettings) -> pd.DataFrame:
    result = pd.DataFrame(columns=ALERT_COLUMNS)
    result.attrs["skipped_detectors"] = skipped
    result.attrs["analysis_mode"] = AnalysisMode.CUSTOM.value
    result.attrs["analysis_settings"] = settings.to_dict()
    return result


def run_custom_detectors(
    df: pd.DataFrame,
    settings: AnalysisSettings,
    scoring_config: dict,
    available_columns: set[str] | None = None,
) -> pd.DataFrame:
    """Run all configurable detectors with one immutable settings object.

    The returned DataFrame is compatible with the existing correlation and
    scoring pipeline. This function never changes ``settings``, ``df``, or
    ``scoring_config`` and never falls back to the standard detector path.
    """
    if not isinstance(settings, AnalysisSettings):
        raise SettingsValidationError("run_custom_detectors requires a validated AnalysisSettings object.")
    if not isinstance(df, pd.DataFrame):
        raise TypeError("Custom detector input must be a pandas DataFrame.")
    if not isinstance(scoring_config, dict):
        raise TypeError("Custom detector scoring_config must be a dictionary.")

    available = set(available_columns if available_columns is not None else df.attrs.get("available_columns", df.columns))
    skipped = [name for name, required, _detector in _DETECTORS if not required.issubset(available)]
    if df.empty:
        return _empty_custom_result(skipped, settings)
    frames = [detector(df, settings, scoring_config) for name, _required, detector in _DETECTORS if name not in skipped]
    non_empty = [frame for frame in frames if not frame.empty]
    if not non_empty:
        return _empty_custom_result(skipped, settings)

    alerts = pd.concat(non_empty, ignore_index=True)
    dedupe_columns = ["timestamp", "src_ip", "dst_ip", "alert_type", "first_seen", "last_seen"]
    alerts = alerts.drop_duplicates(subset=dedupe_columns).sort_values("timestamp").reset_index(drop=True)
    alerts["alert_id"] = [f"ALT-{index:06d}" for index in range(1, len(alerts) + 1)]
    result = alerts[ALERT_COLUMNS]
    result.attrs["skipped_detectors"] = skipped
    result.attrs["analysis_mode"] = AnalysisMode.CUSTOM.value
    result.attrs["analysis_settings"] = settings.to_dict()
    return result
