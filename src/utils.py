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
