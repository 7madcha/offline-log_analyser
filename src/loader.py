"""CSV loading helpers."""

from __future__ import annotations

from pathlib import Path

import pandas as pd


def load_logs(file_path: str | Path) -> pd.DataFrame:
    """Load firewall logs from a CSV file with clear error messages."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Input CSV file not found: {path}")
    if path.stat().st_size == 0:
        raise ValueError(f"Input CSV file is empty: {path}")

    try:
        df = pd.read_csv(path, dtype=str)
    except pd.errors.EmptyDataError as exc:
        raise ValueError(f"Input CSV file has no readable data: {path}") from exc
    except pd.errors.ParserError as exc:
        raise ValueError(f"Input CSV file is not a valid CSV: {path}") from exc
    except UnicodeDecodeError as exc:
        raise ValueError(f"Input CSV file is not valid UTF-8 text: {path}") from exc

    if df.empty:
        raise ValueError(f"Input CSV file contains no rows: {path}")
    return df
