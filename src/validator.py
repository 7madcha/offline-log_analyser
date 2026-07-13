"""Dataset validation helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import pandas as pd


@dataclass(frozen=True)
class ValidationResult:
    """Structured validation result."""

    valid: bool
    missing_columns: list[str]
    duplicate_columns: list[str]
    row_count: int


def validate_columns(df: pd.DataFrame, required_columns: Iterable[str]) -> ValidationResult:
    """Verify required and duplicate columns."""
    required = list(required_columns)
    columns = list(df.columns)
    missing = [column for column in required if column not in columns]
    duplicates = df.columns[df.columns.duplicated()].tolist()
    result = ValidationResult(
        valid=not missing and not duplicates,
        missing_columns=missing,
        duplicate_columns=duplicates,
        row_count=len(df),
    )
    if missing:
        raise ValueError(f"Missing required columns: {', '.join(missing)}")
    if duplicates:
        raise ValueError(f"Duplicate columns found: {', '.join(duplicates)}")
    return result


def validate_dataset(df: pd.DataFrame) -> None:
    """Verify the dataset can be processed."""
    if df is None:
        raise ValueError("Dataset is missing.")
    if df.empty:
        raise ValueError("Dataset is empty.")
