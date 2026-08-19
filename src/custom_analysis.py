"""Isolated end-to-end adapter for one CUSTOM dashboard analysis."""

from __future__ import annotations

import pandas as pd

from src.analysis_settings import AnalysisSettings
from src.cleaner import clean_logs
from src.correlator import correlate_alerts
from src.custom_detector_runner import run_custom_detectors
from src.schema_mapper import map_log_schema
from src.utils import load_config
from src.validator import validate_columns, validate_dataset


def analyze_dataframe_with_custom_settings(
    raw: pd.DataFrame,
    settings: AnalysisSettings,
    config_path: str = "config.yaml",
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, dict]:
    """Run normalization, CUSTOM detection, and existing correlation locally."""
    config = load_config(config_path)
    validate_dataset(raw)
    mapping = map_log_schema(raw, config)
    validate_columns(mapping.logs, ["timestamp", "src_ip"])
    cleaned, summary = clean_logs(mapping.logs, set(mapping.mapped_columns))
    validate_dataset(cleaned)
    alerts = run_custom_detectors(cleaned, settings, config, set(mapping.mapped_columns))
    cleaned.attrs["mapped_columns"] = mapping.mapped_columns
    cleaned.attrs["unavailable_columns"] = mapping.unavailable_columns
    cleaned.attrs["skipped_detectors"] = alerts.attrs.get("skipped_detectors", [])
    cleaned.attrs["analysis_mode"] = alerts.attrs["analysis_mode"]
    cleaned.attrs["analysis_settings"] = alerts.attrs["analysis_settings"]
    incidents = correlate_alerts(alerts, config)
    return cleaned, alerts, incidents, summary

