"""CSV export helpers."""

from __future__ import annotations

import re
from pathlib import Path

import pandas as pd

from src.utils import ensure_directory


def safe_filename(filename: str) -> str:
    """Return a conservative filename."""
    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "_", filename)
    return cleaned or "export.csv"


def export_dataframe(df: pd.DataFrame, path: str | Path) -> Path:
    """Export a DataFrame as UTF-8 CSV, creating directories automatically."""
    output = Path(path)
    ensure_directory(output.parent)
    df.to_csv(output, index=False, encoding="utf-8")
    return output


def export_cleaned_data(df: pd.DataFrame, path: str | Path = "data/processed/cleaned_logs.csv") -> Path:
    """Export cleaned logs."""
    return export_dataframe(df, path)


def export_alerts(df: pd.DataFrame, output_root: str | Path = "outputs") -> Path:
    """Export alerts."""
    return export_dataframe(df, Path(output_root) / "alerts" / safe_filename("alerts.csv"))


def export_incidents(df: pd.DataFrame, output_root: str | Path = "outputs") -> Path:
    """Export incidents."""
    return export_dataframe(df, Path(output_root) / "incidents" / safe_filename("incidents.csv"))
