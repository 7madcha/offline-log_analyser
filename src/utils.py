"""Shared utilities for configuration, paths, and formatting."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def load_config(config_path: str | Path = "config.yaml") -> dict[str, Any]:
    """Load YAML configuration from disk."""
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")
    with path.open("r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle) or {}
    ai = config.setdefault("ai_detection", {})
    defaults = {"enabled": True, "window_minutes": 5, "n_estimators": 200, "contamination": 0.02, "random_state": 42, "anomaly_threshold": 60}
    for key, value in defaults.items():
        ai.setdefault(key, value)
    def valid_number(value: Any, default: float, minimum: float, maximum: float | None = None) -> float:
        """Return a bounded numeric value or a safe default."""
        if isinstance(value, bool):
            return default
        try:
            number = float(value)
        except (TypeError, ValueError):
            return default
        if number < minimum or (maximum is not None and number > maximum):
            return default
        return number

    if valid_number(ai.get("window_minutes"), 5, 1) == 5 and ai.get("window_minutes") != 5:
        ai["window_minutes"] = 5
    else:
        ai["window_minutes"] = int(valid_number(ai.get("window_minutes"), 5, 1))
    if valid_number(ai.get("n_estimators"), 200, 1) == 200 and ai.get("n_estimators") != 200:
        ai["n_estimators"] = 200
    else:
        ai["n_estimators"] = int(valid_number(ai.get("n_estimators"), 200, 1))
    ai["contamination"] = valid_number(ai.get("contamination"), 0.02, 0.000001, 0.5)
    ai["anomaly_threshold"] = valid_number(ai.get("anomaly_threshold"), 60, 0, 100)
    ai["random_state"] = int(valid_number(ai.get("random_state"), 42, 0))
    analytics = config.setdefault("analytics", {})
    analytics["top_n"] = int(valid_number(analytics.get("top_n"), 10, 1))
    hours = config.setdefault("working_hours", {"start_hour": 5, "end_hour": 24})
    hours["start_hour"] = int(valid_number(hours.get("start_hour"), 5, 0, 23))
    hours["end_hour"] = int(valid_number(hours.get("end_hour"), 24, 1, 24))
    return config


def ensure_directory(path: str | Path) -> Path:
    """Create a directory if it does not exist and return it as a Path."""
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def severity_rank(severity: str) -> int:
    """Return a numeric sort rank for severity labels."""
    return {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}.get(str(severity), 0)


def safe_join(values: list[Any] | tuple[Any, ...] | set[Any]) -> str:
    """Join values into a stable comma-separated string."""
    cleaned = [str(value) for value in values if str(value) and str(value) != "nan"]
    return ", ".join(sorted(set(cleaned)))
