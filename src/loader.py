"""Local CSV and JSON log loading helpers."""

from __future__ import annotations

from pathlib import Path

import pandas as pd


def _read_logs(source, filename: str) -> pd.DataFrame:
    suffix = Path(filename).suffix.lower()
    if suffix == ".csv":
        return pd.read_csv(source, dtype=str)
    if suffix in {".json", ".jsonl", ".ndjson"}:
        return pd.read_json(source, lines=suffix in {".jsonl", ".ndjson"})
    raise ValueError("Unsupported log format. Use CSV, JSON, JSONL, or NDJSON.")


def load_logs(file_path: str | Path) -> pd.DataFrame:
    """Load local firewall logs from a CSV or JSON file with clear errors."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Input log file not found: {path}")
    if path.stat().st_size == 0:
        raise ValueError(f"Input log file is empty: {path}")

    try:
        df = _read_logs(path, path.name)
    except pd.errors.EmptyDataError as exc:
        raise ValueError(f"Input log file has no readable data: {path}") from exc
    except pd.errors.ParserError as exc:
        raise ValueError(f"Input log file is not valid: {path}") from exc
    except UnicodeDecodeError as exc:
        raise ValueError(f"Input log file is not valid UTF-8 text: {path}") from exc

    if df.empty:
        raise ValueError(f"Input log file contains no rows: {path}")
    return df


def load_uploaded_logs(uploaded_file) -> pd.DataFrame:
    """Load an uploaded CSV or JSON log without writing it to disk."""
    try:
        df = _read_logs(uploaded_file, uploaded_file.name)
    except ValueError:
        raise
    except (pd.errors.EmptyDataError, UnicodeDecodeError) as exc:
        raise ValueError(f"Uploaded log file has no readable data: {uploaded_file.name}") from exc
    if df.empty:
        raise ValueError(f"Uploaded log file contains no rows: {uploaded_file.name}")
    return df
